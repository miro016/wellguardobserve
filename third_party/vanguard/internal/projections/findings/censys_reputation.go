package findings

import (
	"fmt"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// Censys reputation score levels that warrant a finding. Censys reports a
// per-host reputation verdict in every search hit; only the two riskiest levels
// are surfaced, so a benign or low-risk estate host does not raise noise.
const (
	censysReputationMalicious = "malicious"
	censysReputationHighRisk  = "high_risk"
)

// CensysReputation raises a finding per estate host that Censys flags as
// malicious or high risk. The verdict rides along in the search hit at no extra
// cost, so this adds a threat-intel signal without a paid enrichment call. A
// malicious host on the target's own estate is a strong compromise indicator; a
// high-risk one warrants review. Labels Censys assigned to the host (for example
// "login-page", "remote-access") are folded into the evidence when present.
func CensysReputation(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CensysHostsDiscovered)
	if !ok {
		return nil
	}
	var findings []events.FindingRaised
	for i := range c.Hosts {
		h := &c.Hosts[i]
		severity, ok := censysReputationSeverity(h.Reputation)
		if !ok {
			continue
		}
		// Censys times each service, not the host, so the newest service scan time is
		// the closest thing to "when Censys last looked at this host". Zero when no
		// service carried one.
		var observedAt time.Time
		for _, svc := range h.Services {
			if svc.SourceObservedAt.After(observedAt) {
				observedAt = svc.SourceObservedAt
			}
		}
		evidence := fmt.Sprintf("Censys reputation for %s is %q", h.IP, h.Reputation)
		if len(h.Labels) > 0 {
			evidence += fmt.Sprintf(" (labels: %s)", strings.Join(h.Labels, ", "))
		}
		f := events.FindingRaised{
			Rule:            "censys-host-reputation",
			Title:           "Host flagged risky by Censys reputation",
			FindingCategory: string(entities.FindingReputation),
			AssetKind:       assetIP,
			AssetID:         h.IP,
			Evidence:        evidence,
			Recommendation:  "Investigate the host on Censys and treat it as untrusted until the reputation is cleared.",
			References:      []string{"CWE-506"},
			// Censys's own scan time, which can be far older than this scan. Zero when
			// Censys supplied none; never backfilled with the scan time.
			EvidenceObservedAt:      observedAt,
			EvidenceObservationKind: events.ObservationKindPassiveSnapshot,
		}
		f.Severity = severity
		findings = append(findings, f)
	}
	return findings
}

// censysReputationSeverity maps a Censys reputation score level to a finding
// severity, reporting false for levels that should not raise a finding.
func censysReputationSeverity(level string) (events.Severity, bool) {
	switch level {
	case censysReputationMalicious:
		return events.SeverityHigh, true
	case censysReputationHighRisk:
		return events.SeverityMedium, true
	default:
		return 0, false
	}
}
