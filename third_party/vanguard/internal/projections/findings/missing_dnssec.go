package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// MissingDNSSEC raises a finding for a delegated zone that is not DNSSEC-signed.
func MissingDNSSEC(evt events.DomainEvent) []events.FindingRaised {
	d, ok := evt.(events.DnsRecordsDiscovered)
	if !ok {
		return nil
	}
	if d.DNSSEC || len(d.NS) == 0 {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "missing-dnssec",
		Title:           "DNSSEC not enabled",
		FindingCategory: string(entities.FindingDNS),
		AssetKind:       assetDomain,
		AssetID:         d.Domain,
		Evidence:        fmt.Sprintf("%s is delegated to %d nameservers but the zone is not DNSSEC-signed", d.Domain, len(d.NS)),
		Recommendation:  "Enable DNSSEC signing for the zone to protect against spoofing.",
	}
	f.Severity = events.SeverityLow
	return []events.FindingRaised{f}
}
