package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/projections/intel"
)

// enrichKnownExploited flags a CVE finding when any of its CVEs is in the bundled
// known-exploited (CISA KEV) snapshot, appending a dated catalogue reference and an
// evidence note. It is offline and deterministic (the catalogue is embedded and
// static), so it stays replay-stable. The risk model up-weights a flagged finding.
func enrichKnownExploited(f *events.FindingRaised, cves []string) {
	cat := intel.Default()
	var hits []string
	for _, cve := range cves {
		if e, ok := cat.KnownExploited(cve); ok {
			hits = append(hits, e.CVE)
		}
	}
	if len(hits) == 0 {
		return
	}
	sort.Strings(hits)
	f.KnownExploited = true
	f.References = append(f.References, cat.Reference())
	f.Evidence += fmt.Sprintf(" Known exploited in the wild (%s): %s.", cat.Reference(), strings.Join(hits, ", "))
}

// DefaultCredentials raises a finding when an actively discovered service runs a
// product the catalogue knows ships with well-known default credentials, surfacing
// the candidate as a starting point for an authorized, gated check (it runs
// nothing). The candidate is unverified for this host, so the finding is marked
// inferred and the risk model down-weights it until it is corroborated.
func DefaultCredentials(evt events.DomainEvent) []events.FindingRaised {
	s, ok := evt.(events.ServiceDiscovered)
	if !ok || s.Product == "" {
		return nil
	}
	dc, ok := intel.Default().DefaultCredentials(s.Product)
	if !ok {
		return nil
	}
	sid := entities.NewServiceID(s.IP, s.Port, s.Protocol)
	f := events.FindingRaised{
		Rule:            "default-credentials",
		Title:           "Service product ships with well-known default credentials",
		FindingCategory: string(entities.FindingMisconfig),
		AssetKind:       assetService,
		AssetID:         sid.String(),
		Evidence:        fmt.Sprintf("%s on %s:%d ships with default credentials (candidate %q). %s", s.Product, s.IP, s.Port, dc.Candidate, dc.Note),
		Recommendation:  "Confirm the default credentials were changed; rotate any default or weak credentials.",
		References:      []string{"CWE-1392"},
		Confidence:      string(entities.ConfidenceInferred),
		Service: events.ServiceFacet{
			Port: sid.Port, Proto: sid.Proto, Product: s.Product,
			Version: s.Version, CPEs: s.CPEs,
		},
	}
	f.Severity = events.SeverityMedium
	return []events.FindingRaised{f}
}
