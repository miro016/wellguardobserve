package toolsignals

import "slices"

// Config holds the thresholds and curated lists the detectors and the cross-scan
// aggregation read. It is JSON-serializable so a caller can override the baked-in
// defaults with a -config file; the defaults are explicit and reviewable so the
// signal set stays auditable and stable across runs.
type Config struct {
	// SystemicFraction is the share of scans a grouped signal must appear in to be
	// treated as systemic and have its severity escalated one step. In [0,1]; a
	// strong majority by default.
	SystemicFraction float64 `json:"systemicFraction"`

	// TargetedTools names the tools that are expected to attribute every event to a
	// target (the passive/active recon providers, which always act on a concrete
	// host/domain/IP). attribution/target-gap fires when such a tool's targeted-event
	// ratio falls below TargetRatioThreshold - the crtsh 603/603-unattributed case.
	// A tool absent from this list is never flagged for a target gap, so a genuinely
	// target-less system tool does not false-positive.
	TargetedTools []string `json:"targetedTools"`

	// TargetRatioThreshold is the minimum acceptable fraction of a TargetedTools
	// tool's events that carry a target. Below it, attribution/target-gap fires. In
	// [0,1].
	TargetRatioThreshold float64 `json:"targetRatioThreshold"`

	// FailedCallRateThreshold is the failed-call rate (over available calls) at or
	// above which reliability/failed-call-rate fires. In [0,1].
	FailedCallRateThreshold float64 `json:"failedCallRateThreshold"`

	// DegradationThreshold is the per-tool count of retry/backoff/degraded events at or
	// above which reliability/degradation-storm fires (a terminal gave-up always fires).
	DegradationThreshold int `json:"degradationThreshold"`

	// OpaqueErrorNames are event-name substrings whose warn/error events carry only a
	// generic count and no concrete cause; diag/opaque-provider-error fires when such an
	// event is also opaque in its attributes.
	OpaqueErrorNames []string `json:"opaqueErrorNames"`

	// ExpectedAtWarnNames are event-name substrings for benign, expected outcomes that
	// should not inflate warn volume; hygiene/expected-outcome-at-warn fires when they
	// dominate a tool's warns.
	ExpectedAtWarnNames []string `json:"expectedAtWarnNames"`

	// ExpectedWarnShareThreshold is the share of a tool's warns that must be
	// curated-benign for hygiene/expected-outcome-at-warn to fire. In [0,1].
	ExpectedWarnShareThreshold float64 `json:"expectedWarnShareThreshold"`
}

// DefaultConfig returns the baked-in default detector config. The values are
// explicit here (not scattered magic numbers) so the whole signal set is reviewable
// in one place.
func DefaultConfig() Config {
	return Config{
		SystemicFraction:           0.8,
		TargetRatioThreshold:       0.5,
		FailedCallRateThreshold:    0.5,
		DegradationThreshold:       5,
		ExpectedWarnShareThreshold: 0.5,
		// The recon providers, passive then active. Each acts on a concrete target and
		// should stamp it on every event; a large unattributed share is a defect.
		TargetedTools: []string{
			"crtsh", "certspotter", "subfinder", "dnsinfo", "asn", "whois",
			"mailsec", "breach", "censys", "virustotal", "websearch", "shodan",
			"netlas", "portscan", "httpprobe", "https", "smtp", "webinfo",
			"wappalyzer",
		},
		// subfinder logs a per-provider failure as a bare "reported N error(s)" with no
		// concrete cause.
		OpaqueErrorNames: []string{"provider failed"},
		// dnsinfo logs zone-transfer refusals (AXFR/IXFR) at warn; they are the normal
		// case (servers refuse zone transfers), not a problem worth a warn each.
		ExpectedAtWarnNames: []string{"zone transfer", "axfr", "ixfr"},
	}
}

// isTargetedTool reports whether tool is on the per-target allowlist.
func (c Config) isTargetedTool(tool string) bool {
	return slices.Contains(c.TargetedTools, tool)
}
