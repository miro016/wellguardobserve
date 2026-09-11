package scankit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/velgard-sk/vanguard/internal/buildid"
	"github.com/velgard-sk/vanguard/internal/collection/config"
	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration"
	"github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	goscanspreflight "github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/preflight"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/probes"
	"github.com/velgard-sk/vanguard/internal/projections/intel"
)

// ExternalRuntime is the external dependency set the startup checks resolved on
// this machine: the nmap and Python executables that were actually found, the
// versions they reported, and what the UDP capability probe established about the
// nmap that would run a UDP pass.
//
// The goscans half is embedded rather than copied field by field, so the value
// passes from the check to the run unchanged and an app can carry it through its
// own call chain without depending on the package that produced it.
type ExternalRuntime struct {
	goscanspreflight.Result
	// UDP is what the UDP capability preflight resolved. It is the zero value when
	// the profile did not enable the UDP pass, which is also when no probe ran.
	UDP UDPRuntime
}

// ResolveRuntime runs the startup checks that judge a scan profile against the
// machine it is about to run on, and reports the external runtime they resolved. A
// tool whose external binary is missing or unusable (nmap for the port scanner, the
// interpreter and SSLyze for the TLS checks) is a deployment problem that fails here
// rather than mid-scan.
//
// It says nothing about credentials: those are the caller's to supply and to check
// (config.ScanProfile.ValidateAPIKeys), which is what lets a machine be proven ready
// without handing a read-only deployment check any secrets.
//
// The returned runtime is what was found on this machine, not what the profile asked
// for; it is the zero value when nothing external is needed at all. The context is
// the caller's, so a cancelled collection stops the version queries too; each
// command still carries its own shorter deadline.
func ResolveRuntime(ctx context.Context, cfg *config.ScanProfile) (ExternalRuntime, error) {
	if err := cfg.ValidateExternalTools(); err != nil {
		return ExternalRuntime{}, err
	}
	resolved, err := goScansPreflight(ctx, *cfg)
	if err != nil {
		return ExternalRuntime{}, err
	}
	runtime := ExternalRuntime{Result: resolved}
	if !cfg.UDPEnabled() {
		return runtime, nil
	}
	// The UDP pass runs the same nmap the check above resolved and recorded, so the
	// capability that was proven and the binary that scans cannot diverge.
	udp, err := resolveUDPRuntime(ctx, resolved.NmapPath, resolved.NmapVersion, nil)
	if err != nil {
		return ExternalRuntime{}, err
	}
	runtime.UDP = udp
	return runtime, nil
}

// RecordExternalRuntime copies the resolved external runtime into the orchestrator
// configuration, so the goscans actor reports the nmap and SSLyze that actually ran
// rather than the paths the configuration named. A disabled tool carries a zero
// runtime, which the actor reports as absent.
//
// It lives here rather than in the orchestrator wiring because the wiring maps the
// configuration file, and this value is not in the file: it is what the startup
// checks found on the machine.
func RecordExternalRuntime(orchCfg *orchestration.Config, runtime ExternalRuntime) {
	orchCfg.SetGoScansRuntime(runtime.NmapPath, runtime.NmapVersion,
		runtime.PythonPath, runtime.PythonVersion, runtime.SslyzeVersion)
	// The UDP pass needs the same treatment for a different reason: not to report
	// what ran, but to run at all. It is given the executable the capability probe
	// proved, and the privilege flag that probe established, so the binary that was
	// checked is the binary that scans. A profile with UDP off carries a zero
	// runtime here and the pass stays off.
	orchCfg.SetPortScanUDPRuntime(runtime.UDP.NmapPath, runtime.UDP.PrivilegedFlag)
}

// RecordExecutionEnvironment attaches the complete reproducibility record to the
// orchestrator configuration. It reads only local build metadata, embedded data,
// and the already validated configuration documents, which it takes as the bytes
// the execution ran with rather than as paths: an execution's configuration may
// never have been a file, and hashing what was validated is what makes the digest
// describe the run rather than whatever a path holds by the time it is read.
//
// The collector identity is passed in rather than resolved here: the same value is
// written into the capture manifest, and taking one already-resolved identity is
// what makes the event-stream and filesystem provenance of an execution identical
// by construction. Its version is whatever the caller chose to name the build
// with, and nothing here interprets it.
func RecordExecutionEnvironment(orchCfg *orchestration.Config, engagementYAML, profileYAML []byte,
	external ExternalRuntime, collector buildid.Identity) error {
	RecordExternalRuntime(orchCfg, external)
	// Both documents are required to reproduce the scan, so the digest covers the
	// engagement and the profile together (engagement first, then profile). They are
	// the exact bytes the execution validated and snapshotted, so identical inputs
	// hash identically however the caller obtained them.
	sum := sha256.Sum256(append(append([]byte{}, engagementYAML...), profileYAML...))
	kev := intel.Default()
	orchCfg.Environment = events.ScanEnvironmentRecorded{
		Actor: collector,
		Runtime: events.RuntimeIdentity{
			NmapPath: external.NmapPath, NmapVersion: external.NmapVersion,
			PythonPath: external.PythonPath, PythonVersion: external.PythonVersion,
			SslyzeVersion: external.SslyzeVersion,
		},
		Snapshots: []events.EnvironmentSnapshot{
			{Name: "goscans-probes", Version: goscanspreflight.GoScansVersion, Count: probes.Count(), Digest: probes.Digest()},
			{Name: "kev", Version: kev.Version, Released: kev.Released.Format("2006-01-02")},
		},
		Modules:      buildModules(),
		ConfigSHA256: hex.EncodeToString(sum[:]),
	}
	return nil
}

func buildModules() []events.ModuleVersion {
	wanted := map[string]bool{
		"github.com/Ullaakut/nmap/v3":              true,
		"github.com/projectdiscovery/naabu/v2":     true,
		"github.com/projectdiscovery/wappalyzergo": true,
		"github.com/siemens/GoScans":               true,
	}
	var out []events.ModuleVersion
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if wanted[dep.Path] {
				version := dep.Version
				if dep.Replace != nil {
					version = dep.Replace.Version
				}
				out = append(out, events.ModuleVersion{Path: dep.Path, Version: version})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// goScansPreflightCommandTimeout bounds one preflight command. Every command is a
// version or capability query against a local binary, so a slow one means a broken
// deployment rather than a busy one.
const goScansPreflightCommandTimeout = 10 * time.Second

// goScansPreflightOutputCap bounds what is read from one preflight command, so an
// unexpectedly chatty binary cannot grow the scan process.
const goScansPreflightOutputCap = 64 * 1024

// goScansPreflight verifies the external runtime the GoScans tool needs, read-only,
// and only when the tool is enabled, and reports what it resolved. A disabled tool
// starts no process and touches no path, so a passive scan never needs nmap,
// Python, or SSLyze installed, and gets back a zero runtime.
//
// It runs here rather than inside config validation because it executes commands:
// config stays a pure decode-and-check of the file, and the process work lives with
// the other startup checks. Each command carries its own deadline as a child of the
// caller's context, so a hung binary cannot outlive either.
func goScansPreflight(ctx context.Context, cfg config.ScanProfile) (goscanspreflight.Result, error) {
	if !cfg.GoScansEnabled() {
		if cfg.Tools.PortScan.Enabled != nil && *cfg.Tools.PortScan.Enabled {
			return goscanspreflight.ResolveNmap(ctx, "nmap", goScansPreflightCommandTimeout, goScansPreflightOutputCap)
		}
		return goscanspreflight.Result{}, nil
	}
	g := cfg.Tools.GoScans
	tls := g.Ssl.Enabled != nil && *g.Ssl.Enabled
	return goscanspreflight.Run(ctx, goscanspreflight.Options{
		NmapPath:       g.Nmap.Path,
		CheckTLS:       tls,
		PythonPath:     g.Sslyze.PythonPath,
		SslyzeVersion:  g.Sslyze.Version,
		Truststore:     g.Sslyze.AdditionalTruststore,
		CommandTimeout: goScansPreflightCommandTimeout,
		MaxOutputBytes: goScansPreflightOutputCap,
	})
}

// OpenCollectionSink creates the collection's event sink. There is one sink
// construction path because there is one kind of collection: the destination was
// empty when the run claimed it, so the stream starts at the beginning and the
// caller's own sink is chained behind it for live progress.
func OpenCollectionSink(collectionDir string, next events.DomainEventSink) (*persistence.Sink, error) {
	sink, err := persistence.NewSink(collectionDir, next)
	if err != nil {
		return nil, fmt.Errorf("failed to create persistence sink: %w", err)
	}
	return sink, nil
}

// RunOrchestrator runs the orchestrator over the scan root its configuration names.
// There is one entry point because there is one kind of run: a collection starts
// from the root and collects everything the profile enables, with no prior state to
// seed it from.
func RunOrchestrator(ctx context.Context, orchCfg *orchestration.Config) error {
	return orchestration.New(orchCfg).Run(ctx)
}

// StartCollection writes the collection manifest before the orchestrator runs,
// recording the run identity, the phase set it was asked to cover, the UTC start,
// the config snapshots, and the collector identity. It returns the manifest so the
// caller can close it.
//
// Writing at the start rather than at the end is what makes an unfinished collection
// visible: a collector killed mid-scan leaves a manifest that still says running
// rather than a directory that claims the attempt never happened.
func StartCollection(scanID, root string, phases config.PhaseSet, outputDir string,
	started time.Time, engagementSnapshot, profileSnapshot string, collector buildid.Identity) (*persistence.Manifest, error) {
	manifest := persistence.NewManifest(scanID, root, phases, started, engagementSnapshot, profileSnapshot, collector)
	if err := manifest.Save(outputDir); err != nil {
		return nil, fmt.Errorf("save collection manifest: %w", err)
	}
	return manifest, nil
}

// CompleteCollection closes the manifest with its terminal status, its UTC
// completion time, and its optional collection-health summary, then rewrites the
// manifest atomically.
//
// The health summary travels with the status because they are one decision: the
// caller folds the run's tool events once and hands the same value to the manifest
// and to its own caller, so the collection and the returned error cannot disagree.
func CompleteCollection(manifest *persistence.Manifest, outputDir string,
	status persistence.CollectionStatus, completed time.Time, health *persistence.CollectionHealth) error {
	if err := manifest.Complete(status, completed, health); err != nil {
		return err
	}
	if err := manifest.Save(outputDir); err != nil {
		return fmt.Errorf("save collection manifest: %w", err)
	}
	return nil
}

// SaveConfigSnapshots writes engagement.yaml and scan-profile.yaml into the
// collection's configs/ tree and returns both collection-relative paths for the
// manifest. It writes the exact bytes the run validated, so the collection records
// what ran and not what a file happened to contain afterwards.
func SaveConfigSnapshots(engagementYAML, profileYAML []byte, collectionDir string) (engagement, profile string, err error) {
	return persistence.SaveSnapshots(engagementYAML, profileYAML, collectionDir)
}

// WireToolSinks opens a per-tool text log for each enabled tool and attaches it as
// that tool's event sink, routing events to the caller via notify when provided.
// Every tool's events are also persisted as structured envelopes to one shared
// canonical tool-event log. It returns a closer that reports any file-close error,
// because a collection is not durable and may not be marked succeeded until every
// tool log closes cleanly.
//
// The streams come from collection persistence, which owns where they live and
// creates the bucket; this function owns the wiring - which tool gets a sink, what
// decorates it, and what the shared sequence counter is.
//
// The logs are opened truncating, which is what the collection directory this runs
// against allows: it was empty when the collection claimed it, so there is no other
// tool output to keep and the envelope sequence starts at zero.
func WireToolSinks(collectionDir string, cfg *orchestration.Config, notify func(time.Time, tooleventlog.Event)) (func() error, error) {
	var files []*os.File
	// sinks are kept so the closer can report what the tool streams failed to write
	// while the execution was running. A tool actor cannot react to a full disk, so
	// the failure surfaces here, at the one barrier the execution already treats as
	// its durability check.
	var sinks []*tooleventlog.PersistSink
	closer := func() error {
		var closeErr error
		for _, s := range sinks {
			closeErr = errors.Join(closeErr, s.Err())
		}
		for _, f := range files {
			if err := f.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close tool log %s: %w", f.Name(), err))
			}
		}
		return closeErr
	}

	var seq atomic.Int64

	tooling, err := persistence.OpenToolLogs(collectionDir)
	if err != nil {
		return nil, err
	}
	files = append(files, tooling)
	var encMu sync.Mutex

	open := func(name string) (tooleventlog.EventSink, error) {
		f, err := persistence.OpenToolTextLog(collectionDir, name)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
		text := tooleventlog.NewSink(f, notify)
		sink := tooleventlog.NewPersistSink(&seq, &encMu, tooling, text)
		sinks = append(sinks, sink)
		return sink, nil
	}

	// enabled is the tool's own run decision: a boolean flag for most tools, and for
	// crt.sh and Censys the mode's Enabled predicate. Every non-disabled mode gets
	// the normal tool_<name>.log, so cache lookup decisions land in the same stream
	// as service decisions.
	type wiring struct {
		enabled bool
		name    string
		set     func(tooleventlog.EventSink)
	}
	for _, w := range []wiring{
		{cfg.Crtsh.Mode.Enabled(), "crtsh", func(s tooleventlog.EventSink) { cfg.Crtsh.Sink = s }},
		{cfg.EnableCertspotter, "certspotter", func(s tooleventlog.EventSink) { cfg.Certspotter.Sink = s }},
		{cfg.EnableSubfinder, "subfinder", func(s tooleventlog.EventSink) { cfg.Subfinder.Sink = s }},
		{cfg.EnableDnsInfo, "dnsinfo", func(s tooleventlog.EventSink) { cfg.DnsInfo.Sink = s }},
		{cfg.EnableAsnInfo, "asn", func(s tooleventlog.EventSink) { cfg.AsnInfo.Sink = s }},
		{cfg.EnableWhois, "whois", func(s tooleventlog.EventSink) { cfg.Whois.Sink = s }},
		{cfg.EnableMailSec, "mailsec", func(s tooleventlog.EventSink) { cfg.MailSec.Sink = s }},
		{cfg.EnableBreach, "breach", func(s tooleventlog.EventSink) { cfg.Breach.Sink = s }},
		{cfg.Censys.Mode.Enabled(), "censys", func(s tooleventlog.EventSink) { cfg.Censys.Sink = s }},
		{cfg.EnableVirusTotal, "virustotal", func(s tooleventlog.EventSink) { cfg.Virustotal.Sink = s }},
		{cfg.EnableWebSearch, "websearch", func(s tooleventlog.EventSink) { cfg.WebSearch.Sink = s }},
		{cfg.EnableShodan, "shodan", func(s tooleventlog.EventSink) { cfg.Shodan.Sink = s }},
		{cfg.EnableNetlas, "netlas", func(s tooleventlog.EventSink) { cfg.Netlas.Sink = s }},
		{cfg.EnablePortScan, "portscan", func(s tooleventlog.EventSink) { cfg.PortScan.Sink = s }},
		{cfg.EnableHttpProbe, "httpprobe", func(s tooleventlog.EventSink) { cfg.HttpProbe.Sink = s }},
		{cfg.EnableHttps, "https", func(s tooleventlog.EventSink) { cfg.Https.Sink = s }},
		{cfg.EnableSmtp, "smtp", func(s tooleventlog.EventSink) { cfg.Smtp.Sink = s }},
		{cfg.EnableWebInfo, "webinfo", func(s tooleventlog.EventSink) { cfg.WebInfo.Sink = s }},
		{cfg.EnableWappalyzer, "wappalyzer", func(s tooleventlog.EventSink) { cfg.Wappalyzer.Sink = s }},
		{cfg.EnableGoScans, "goscans", func(s tooleventlog.EventSink) { cfg.GoScans.Sink = s }},
	} {
		if !w.enabled {
			continue
		}
		sink, err := open(w.name)
		if err != nil {
			return nil, errors.Join(err, closer())
		}
		w.set(sink)
	}
	return closer, nil
}
