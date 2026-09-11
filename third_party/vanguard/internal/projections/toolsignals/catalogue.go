package toolsignals

import "fmt"

// Catalogue signal ids. Each is a stable, machine-readable identifier for one
// deterministic defect class, grouped by family prefix. They are the join key for
// cross-scan aggregation and the primary sort key in the report, so they never
// change casually.
const (
	// SigLogIntegrityDecode is raised when a log line fails to decode into an envelope.
	SigLogIntegrityDecode = "log-integrity/decode"
	// SigLogIntegritySchema is raised when an envelope's Version is not the expected
	// SchemaVersion.
	SigLogIntegritySchema = "log-integrity/schema"
	// SigLogIntegritySeqGap is raised when the per-scan Seq is not a gap-free,
	// duplicate-free set.
	SigLogIntegritySeqGap = "log-integrity/seq-gap"
	// SigLogIntegrityMissingCorr is raised when a call-boundary event lacks a CorrID or
	// Phase.
	SigLogIntegrityMissingCorr = "log-integrity/missing-corr"

	// SigAttributionTargetGap is raised when a per-target tool leaves too many events
	// unattributed to a target.
	SigAttributionTargetGap = "attribution/target-gap"

	// SigUDPPassTerminalMissing is raised when a UDP portscan pass started and never
	// reached a terminal event, or reached one with no start.
	SigUDPPassTerminalMissing = "udp/pass-terminal-missing"
	// SigUDPPassTerminalDuplicate is raised when a UDP portscan pass reached more than
	// one terminal event.
	SigUDPPassTerminalDuplicate = "udp/pass-terminal-duplicate"
	// SigUDPPortAccountingMismatch is raised when a UDP pass's per-state port counts do
	// not reconcile with what it says it accounted for or was asked to probe.
	SigUDPPortAccountingMismatch = "udp/port-accounting-mismatch"
	// SigUDPPartialWithoutError is raised when a UDP pass reports a partial result with
	// no error event naming what it lost.
	SigUDPPartialWithoutError = "udp/partial-without-error"
	// SigUDPErrorWithCompleteSuccess is raised when a UDP pass emitted an error event
	// yet its completion claims it covered every requested port.
	SigUDPErrorWithCompleteSuccess = "udp/error-with-complete-success"

	// SigWasteDuplicateConcurrentQuery is raised when the same (tool,target) is queried
	// by two or more calls whose spans overlap in time.
	SigWasteDuplicateConcurrentQuery = "waste/duplicate-concurrent-query"
	// SigWasteSelfInflictedRateLimit is raised when a rate-limit event falls inside the
	// overlap window of a duplicate-concurrent query - a self-inflicted throttle.
	SigWasteSelfInflictedRateLimit = "waste/self-inflicted-rate-limit"

	// SigReliabilityExternalRateLimit is raised for rate-limit events that are not
	// self-inflicted - an external API-key or budget throttle.
	SigReliabilityExternalRateLimit = "reliability/external-rate-limit"
	// SigReliabilityDegradationStorm is raised when a tool burns many retries/backoffs
	// or ends degraded or gave up.
	SigReliabilityDegradationStorm = "reliability/degradation-storm"
	// SigReliabilityFailedCallRate is raised when a tool's failed-call rate over its
	// available calls exceeds the threshold.
	SigReliabilityFailedCallRate = "reliability/failed-call-rate"

	// SigDiagOpaqueProviderError is raised when a tool logs a warn/error carrying no
	// actionable detail (a generic "reported N error(s)" with no concrete cause).
	SigDiagOpaqueProviderError = "diag/opaque-provider-error"
	// SigHygieneExpectedOutcomeAtWarn is raised when a benign, expected outcome is
	// logged at WARN and dominates a tool's warn volume.
	SigHygieneExpectedOutcomeAtWarn = "hygiene/expected-outcome-at-warn"

	// SigTrendAttributionDrop is raised when a tool's target-attribution ratio worsens
	// across the corpus (the crtsh 100%->0% regression).
	SigTrendAttributionDrop = "trend/attribution-drop"
	// SigTrendRateLimitRising is raised when a tool's rate-limit count rises across the
	// corpus.
	SigTrendRateLimitRising = "trend/rate-limit-rising"
	// SigTrendFailedCallRateRising is raised when a tool's failed-call rate rises across
	// the corpus.
	SigTrendFailedCallRateRising = "trend/failed-call-rate-rising"
)

// Severity ranks a signal's advisory importance. Severities are advisory and
// configurable, never a hard verdict; they order the report and drive the
// -min-severity and -fail-on thresholds.
type Severity string

const (
	// SeverityHigh marks a code-side defect or a corrupt log.
	SeverityHigh Severity = "high"
	// SeverityMedium marks a likely defect worth triage.
	SeverityMedium Severity = "medium"
	// SeverityLow marks an informational or hygiene concern.
	SeverityLow Severity = "low"
	// SeverityInfo marks a benign observation.
	SeverityInfo Severity = "info"
)

// severityRank orders severities, higher is more severe. An unknown or empty
// severity ranks below info so it never gates.
func severityRank(s Severity) int {
	switch s {
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// escalate raises a severity one step, capped at high. It is how a systemic signal
// (present in a strong majority of scans) is made louder than a one-off flake.
func (s Severity) escalate() Severity {
	switch s {
	case SeverityInfo:
		return SeverityLow
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	default:
		return SeverityHigh
	}
}

// atOrAbove reports whether s is at least as severe as floor. An empty floor
// (unset threshold) is never met.
func (s Severity) atOrAbove(floor Severity) bool {
	if floor == "" {
		return false
	}
	return severityRank(s) >= severityRank(floor)
}

// ParseSeverity validates a caller-supplied level, returning an error for any
// value outside the four known levels. An empty string is allowed only when
// allowEmpty is set (the unset -fail-on gate), returning the empty Severity.
func ParseSeverity(s string, allowEmpty bool) (Severity, error) {
	if s == "" && allowEmpty {
		return "", nil
	}
	switch Severity(s) {
	case SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return Severity(s), nil
	default:
		return "", fmt.Errorf("invalid severity %q: want high|medium|low|info", s)
	}
}
