package orchestration

import (
	"context"
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/whois"
)

// subfinderLikelyMisconfigured reports whether a subfinder run that queried every
// source ("all": true) but returned no subdomains looks like a configuration gap
// (typically missing provider keys, so an authenticated source such as VirusTotal
// ran blind) rather than a target that genuinely has none. The "all" gate matters:
// with only the default fast sources a zero result is unremarkable, but with every
// source enabled a zero result almost always means a keyed source went inert.
func subfinderLikelyMisconfigured(all bool, count int) bool {
	return all && count == 0
}

// flagSubfinderZeroResult raises a coverage IssueObserved when subfinder enumerated
// with every source enabled yet returned no subdomains. That combination almost
// always means a provider key is missing rather than a target without subdomains,
// so it is surfaced instead of passing as a clean empty result. It is a no-op when
// subfinder ran with only its default sources or found anything at all.
func (o *Orchestrator) flagSubfinderZeroResult(ctx context.Context, root string, count int) {
	if !subfinderLikelyMisconfigured(o.cfg.Subfinder.All, count) {
		return
	}

	msg := fmt.Sprintf(
		"subfinder enumerated %s with all sources enabled but returned 0 subdomains; "+
			"this almost always means a provider key is missing (an authenticated source such as "+
			"VirusTotal ran blind), not that the target has no subdomains",
		root)

	o.emitPassiveCoverageIssue(ctx, root, msg, events.SeverityMedium)
}

// discoveryFloor is the set of names a passive scan always reaches even when
// enumeration finds nothing new: the scanned root and its registrable apex (the
// crawler emits the root, and a CT source often returns the apex). A run that
// discovers only these has no attack surface beyond the bare root.
func discoveryFloor(root string) map[string]bool {
	return map[string]bool{
		root:                        true,
		whois.RegistrableApex(root): true,
	}
}

// discoveryCollapsed reports whether passive discovery effectively yielded nothing
// beyond the discovery floor (the root and its registrable apex). An enumeration
// that normally expands the surface but returns only floor names is a coverage
// collapse, so the caller raises a coverage Issue instead of letting the run
// present as a clean, low-risk scan. An empty discovered set is a collapse too.
func discoveryCollapsed(discovered, floor map[string]bool) bool {
	for d := range discovered {
		if !floor[d] {
			return false
		}
	}
	return true
}

// hasEnumerationSource reports whether at least one subdomain-enumeration source
// ran for this scan. The discovery-collapse guard only makes sense when the scan
// actually tried to expand past the root: with no enumeration source a root-only
// result is the expected outcome, not a collapse.
func (o *Orchestrator) hasEnumerationSource() bool {
	// Both non-disabled crt.sh modes enumerate: a cache-supported crawl returns the
	// same certificate SANs from the fixture that the service would have returned.
	return o.cfg.Crtsh.Mode.Enabled() ||
		o.cfg.EnableCertspotter ||
		o.cfg.EnableSubfinder ||
		(o.cfg.EnableVirusTotal && o.cfg.Virustotal.EnableSubdomains) ||
		o.cfg.EnableWebSearch
}

// flagDiscoveryCollapse raises a coverage IssueObserved when the whole passive
// phase discovered only the root (and perhaps its registrable apex). It runs after
// the pipeline has drained, so targetState holds every distinct discovered name. It is the runtime backstop for a silently crippled enumerator (e.g.
// subfinder with no provider keys): without it a near-empty surface reports as a
// clean, "LOW risk" scan. It is a no-op when no enumeration source ran, since a
// root-only result is then expected rather than a collapse.
func (o *Orchestrator) flagDiscoveryCollapse(ctx context.Context, root string) {
	if !o.hasEnumerationSource() {
		return
	}

	floor := discoveryFloor(root)
	names := o.targets.discoveredDomains()
	discovered := make(map[string]bool, len(names))
	for _, d := range names {
		discovered[d] = true
	}

	if !discoveryCollapsed(discovered, floor) {
		return
	}

	msg := fmt.Sprintf(
		"passive discovery for %s collapsed to %d name(s) at or below the root/apex floor; "+
			"an enumeration source ran but the surface did not expand past the bare root, so "+
			"discovery coverage is likely incomplete (e.g. a passive source returned nothing) "+
			"rather than the target genuinely having no subdomains",
		root, len(discovered))

	o.emitPassiveCoverageIssue(ctx, root, msg, events.SeverityHigh)
}

// emitPassiveCoverageIssue publishes a passive-phase coverage IssueObserved: an
// observation the orchestrator makes about its own discovery completeness, not a
// tool error. The "coverage" source files it under the report's Coverage gaps
// section; severity ranks how much surface the gap may hide. It is the passive
// counterpart to active.go's emitCoverageIssue (which is active-phase, low-severity,
// and deduped per target).
func (o *Orchestrator) emitPassiveCoverageIssue(ctx context.Context, query, msg string, severity events.Severity) {
	at := time.Now()
	issue := events.IssueObserved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			Source:          sourceCoverage,
			Phase:           events.PhasePassive,
			Category:        events.CategoryIssue,
			Severity:        severity,
			ObservationKind: events.ObservationKindOperational,
			CapturedAt:      at,
		},
		Query: query,
		Error: msg,
	}
	issue.EventID = events.NewEventID(at, issue)
	o.publish(ctx, []events.DomainEvent{issue})
}
