package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// maliciousReputationThreshold is the engine-vote count at or above which the
// finding is escalated from Medium to High severity.
const maliciousReputationThreshold = 5

// MaliciousReputation raises a finding when one or more engines flag a domain as
// malicious in its VirusTotal reputation. Any malicious vote is worth surfacing;
// a higher count escalates the severity.
func MaliciousReputation(evt events.DomainEvent) []events.FindingRaised {
	r, ok := evt.(events.DomainReputationDiscovered)
	if !ok || r.Malicious < 1 {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "malicious-reputation",
		Title:           "Domain flagged malicious by reputation engines",
		FindingCategory: string(entities.FindingReputation),
		AssetKind:       assetDomain,
		AssetID:         r.Domain,
		Evidence:        fmt.Sprintf("%d engine(s) flagged %s as malicious (%d suspicious, score %d)", r.Malicious, r.Domain, r.Suspicious, r.Reputation),
		Recommendation:  "Investigate the domain's reputation on VirusTotal and treat it as untrusted until cleared.",
		References:      []string{"CWE-506"},
	}
	f.Severity = events.SeverityMedium
	if r.Malicious >= maliciousReputationThreshold {
		f.Severity = events.SeverityHigh
	}
	return []events.FindingRaised{f}
}
