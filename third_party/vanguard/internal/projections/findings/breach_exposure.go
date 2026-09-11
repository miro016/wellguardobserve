package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// BreachExposure raises a finding when a domain has email aliases that appear in
// known data breaches. Exposed credentials are an unintended exposure that
// warrants a password-reset and MFA review, so any non-empty breach result is a
// real finding.
func BreachExposure(evt events.DomainEvent) []events.FindingRaised {
	b, ok := evt.(events.BreachDataDiscovered)
	if !ok || len(b.Breaches) == 0 {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "breach-exposure",
		Title:           "Email addresses exposed in known data breaches",
		FindingCategory: string(entities.FindingExposure),
		AssetKind:       assetDomain,
		AssetID:         b.Domain,
		Evidence:        fmt.Sprintf("%d email alias(es) on %s appear in known data breaches", len(b.Breaches), b.Domain),
		Recommendation:  "Force password resets for the affected accounts and enable multi-factor authentication.",
		References:      []string{"CWE-359"},
	}
	f.Severity = events.SeverityMedium
	return []events.FindingRaised{f}
}
