package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ZoneTransferOpen raises a finding whenever a zone transfer succeeded. An open
// AXFR leaks the entire zone and is always a real misconfiguration.
func ZoneTransferOpen(evt events.DomainEvent) []events.FindingRaised {
	z, ok := evt.(events.ZoneTransferDiscovered)
	if !ok {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "zone-transfer-open",
		Title:           "DNS zone transfer (AXFR) allowed",
		FindingCategory: string(entities.FindingMisconfig),
		AssetKind:       assetDomain,
		AssetID:         z.Domain,
		Evidence:        fmt.Sprintf("nameserver %s allowed a zone transfer leaking %d records", z.Nameserver, len(z.Records)),
		Recommendation:  "Restrict AXFR to authorized secondary nameservers only.",
		References:      []string{"CWE-200"},
	}
	f.Severity = events.SeverityHigh
	return []events.FindingRaised{f}
}
