package collect

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/velgard-sk/vanguard/internal/apps/scankit"
	"github.com/velgard-sk/vanguard/internal/collection/config"
	"github.com/velgard-sk/vanguard/internal/collection/health"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration"
	"github.com/velgard-sk/vanguard/internal/collection/persistence"
)

// apiKeys maps the caller's credentials onto the internal key set the profile
// validates against. It is a plain copy: the library adds no key of its own and
// reads no environment variable here, so a provider a caller did not supply a
// credential for stays unsupplied.
func (c Credentials) apiKeys() *config.APIKeys {
	return &config.APIKeys{
		Breach:      c.Breach,
		Censys:      c.Censys,
		CensysOrgID: c.CensysOrgID,
		VirusTotal:  c.VirusTotal,
		WebSearch:   c.WebSearch,
		Shodan:      c.Shodan,
		Netlas:      c.Netlas,
		Certspotter: c.Certspotter,
	}
}

// run composes the two documents and collects everything the profile enables into a
// fresh destination. Everything it validates, it validates before a target or a
// provider is contacted: a broken configuration or missing credential stops the run
// before the destination is inspected. Destination validation may create a missing
// empty directory, but an unusable external runtime still leaves it without
// collection evidence.
func (c *Collector) run(ctx context.Context) error {
	scan, err := config.ParseScan(c.engagementYAML, c.profileYAML)
	if err != nil {
		return err
	}
	profile, engagement := scan.Profile, scan.Engagement
	keys := c.credentials.apiKeys()
	if err := profile.ValidateAPIKeys(keys); err != nil {
		return err
	}
	root := engagement.Root()
	if root == "" {
		return errors.New("the engagement supplies no scan root")
	}
	// The destination decision comes before the external runtime and before any
	// target or provider is contacted: a destination this run may not write is
	// cheapest to reject while nothing has happened yet, and it is never modified in
	// order to be checked. A collection directory is claimed once, for one run.
	dir, err := persistence.PrepareFresh(c.destinationDir)
	if err != nil {
		return err
	}
	c.destinationDir = dir

	runtime, err := scankit.ResolveRuntime(ctx, &profile)
	if err != nil {
		return err
	}

	progress := newProgress(c.progress)
	return c.runCollection(ctx, &profile, &engagement, keys, runtime, root, progress)
}

// runCollection wires the sinks and tooling, runs the orchestrator, and records the
// outcome in the collection manifest.
//
// The manifest is written as running before the orchestrator starts and rewritten
// with a terminal status on every exit, so a collection never has to be judged by
// what its event log happens to contain. The success transition happens only after
// both log sinks have closed cleanly: until then the collected material is not
// durable, and a manifest that claimed otherwise would describe evidence that was
// never flushed.
func (c *Collector) runCollection(ctx context.Context, profile *config.ScanProfile,
	engagement *config.EngagementConfig, keys *config.APIKeys, runtime scankit.ExternalRuntime,
	root string, progress *progressSink) (resultErr error) {
	orchCfg := orchestration.FromConfig(profile, engagement, keys)
	if err := scankit.RecordExecutionEnvironment(&orchCfg, c.engagementYAML, c.profileYAML, runtime, c.collector); err != nil {
		return err
	}
	scanID := orchestration.NewScanID()
	orchCfg.ScanID = scanID

	pSink, err := scankit.OpenCollectionSink(c.destinationDir, progress)
	if err != nil {
		return err
	}
	var manifest *persistence.Manifest

	var closeOnce sync.Once
	var closeSinks func() error
	var closeErr error
	// closeStreams flushes and closes the tool logs and the event sink. It is the
	// shared end-of-execution step, run by the deferred safety net or by the explicit
	// post-run call, whichever comes first; the Once guard makes the second a no-op
	// and keeps the recorded error.
	closeStreams := func() {
		closeOnce.Do(func() {
			if closeSinks != nil {
				closeErr = closeSinks()
			}
			closeErr = errors.Join(closeErr, pSink.Close())
		})
	}

	manifestWritten := false
	manifestClosed := false
	closeReported := false
	defer func() {
		closeStreams()
		if closeErr != nil && !closeReported {
			resultErr = errors.Join(resultErr, fmt.Errorf("persist collected streams: %w", closeErr))
		}
		if !manifestWritten || manifestClosed {
			return
		}
		status := persistence.StatusFailed
		if ctx.Err() != nil {
			status = persistence.StatusInterrupted
		}
		if err := scankit.CompleteCollection(manifest, c.destinationDir, status, time.Now(), nil); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("record %s collection: %w", status, err))
		}
	}()

	orchCfg.DomainEventSink = pSink

	// Record the exact configuration this run used: engagement.yaml and
	// scan-profile.yaml, both named in the manifest written below. The bytes written
	// are the bytes that were validated above, so the collection states what ran
	// rather than what some file contained afterwards.
	engagementSnapshot, profileSnapshot, err := scankit.SaveConfigSnapshots(c.engagementYAML, c.profileYAML, c.destinationDir)
	if err != nil {
		return err
	}

	startedAt := time.Now()
	manifest, err = scankit.StartCollection(scanID, root, profile.PhaseSet(), c.destinationDir, startedAt,
		engagementSnapshot, profileSnapshot, c.collector)
	if err != nil {
		return err
	}
	manifestWritten = true

	// The live health monitor rides the tool sinks' existing notification callback:
	// every tool event that proves lost collection work is folded as it is emitted,
	// and its first occurrence is printed while the run is still going. Orchestration
	// is not told about it - tools and scheduling stay unaware of the gate.
	monitor := health.New(progress.healthProblem)

	closeSinks, err = scankit.WireToolSinks(c.destinationDir, &orchCfg, monitor.Observe)
	if err != nil {
		return err
	}

	if err := progress.printf("scanning %s (output: %s)\n", root, c.destinationDir); err != nil {
		return err
	}

	runErr := scankit.RunOrchestrator(ctx, &orchCfg)
	// Tool sinks notify synchronously and orchestration drains its worker groups
	// before returning, so the fold is complete here and needs no flush step.
	assessment := monitor.Assessment()
	// Flush the streams before judging the outcome, so the manifest status describes
	// material that is actually on disk.
	closeStreams()
	completedAt := time.Now()

	closeReported = true
	// A stream error is a capture error: an event the collection observed but could
	// not record is missing evidence, whether the writer failed during the run or
	// while closing.
	if closeErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("persist collected streams: %w", closeErr))
	}
	// A cancelled run is interrupted even when the orchestrator returned nothing: it
	// stopped short of what it was asked to do, so what it was still working on was
	// never decided either way.
	if runErr == nil && ctx.Err() != nil {
		runErr = ctx.Err()
	}

	status := terminalStatus(ctx.Err(), runErr, assessment)
	// The summary is written on a failed or interrupted collection too, when problems
	// were observed before the run stopped: it is evidence about the attempt, and the
	// manifest is where an operator looks for it.
	completeErr := scankit.CompleteCollection(manifest, c.destinationDir, status, completedAt,
		collectionHealth(assessment))
	if completeErr == nil {
		manifestClosed = true
	}
	if err := errors.Join(runErr, completeErr); err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	return c.reportOutcome(progress, assessment, status)
}

// reportOutcome writes the closing operator lines and returns what the run has to
// tell its caller once the collection is written and its manifest is durable.
//
// A failing progress writer is the caller's problem, not the collection's: the collection
// is complete and its manifest says so, and the write failure is what this returns.
// It is reported ahead of degradation because it is a defect in the caller's own
// plumbing, and unlike degradation it says nothing about what was collected.
func (c *Collector) reportOutcome(progress *progressSink, assessment health.Assessment,
	status persistence.CollectionStatus) error {
	_ = progress.summary(assessment)
	_ = progress.printf("collected streams and metadata written to %s\n", c.destinationDir)
	if err := progress.err(); err != nil {
		return err
	}
	if status == persistence.StatusDegraded {
		return &DegradedError{summary: publicSummary(assessment)}
	}
	return nil
}

// terminalStatus is the collection's whole outcome decision, in precedence order.
//
// Cancellation outranks everything, because an interrupted run judged nothing: what
// it was still working on was never decided either way. An error outranks
// degradation, because a run that failed - including one whose streams reported a
// write failure - cannot vouch for what it did collect. Degradation outranks
// success, because a run that lost work must not read as a clean one. Everything
// else is a complete collection.
func terminalStatus(ctxErr, runErr error, assessment health.Assessment) persistence.CollectionStatus {
	switch {
	case ctxErr != nil:
		return persistence.StatusInterrupted
	case runErr != nil:
		return persistence.StatusFailed
	case assessment.Degraded():
		return persistence.StatusDegraded
	default:
		return persistence.StatusSucceeded
	}
}

// preflight resolves whether this machine can collect. It parses the profile and
// runs the same read-only external-runtime checks a collection runs at startup -
// and nothing else, so it contacts no target and writes no file.
//
// It resolves no build identity: the version a capture would record is the
// caller's own, supplied through Options.Version, and this package neither
// constructs nor guesses it.
func preflight(ctx context.Context, profileYAML []byte) (PreflightReport, error) {
	profile, err := config.ParseProfile(profileYAML, "scan profile")
	if err != nil {
		return PreflightReport{}, err
	}
	runtime, err := scankit.ResolveRuntime(ctx, &profile)
	if err != nil {
		return PreflightReport{}, err
	}
	return PreflightReport{
		Runtime: RuntimeInfo{
			// A profile that needs nothing external resolves nothing, which is a pass
			// rather than a gap: a passive scan needs no nmap, no interpreter, no SSLyze.
			Required:      runtime != scankit.ExternalRuntime{},
			NmapPath:      runtime.NmapPath,
			NmapVersion:   runtime.NmapVersion,
			PythonPath:    runtime.PythonPath,
			PythonVersion: runtime.PythonVersion,
			SslyzeVersion: runtime.SslyzeVersion,
			Truststore:    runtime.Truststore,
			// A UDP pass that was asked for and could not be proven never reaches
			// here: it fails the resolution above, so reporting it is reporting a
			// verified capability rather than an attempt.
			UDPVerified:       runtime.UDP.NmapPath != "",
			UDPPrivilegedFlag: runtime.UDP.PrivilegedFlag,
		},
	}, nil
}
