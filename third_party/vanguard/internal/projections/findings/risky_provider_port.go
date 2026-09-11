package findings

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// RiskyProviderPortShodan raises an inferred risky-open-port finding for each
// Shodan-reported sensitive port. It shares the rule name and asset key with
// RiskyOpenPort, so an active-scan confirmation of the same ip:port dedups into one
// finding and upgrades its confidence to confirmed (Findings.Apply's Stronger
// merge) - the mechanism ShodanVulnerabilities already relies
// on. A provider reports a port as open from its own vantage point, not this scan's,
// so it stays inferred (and down-weighted by the risk model) until Step 2's active
// confirmation - or a later scan - corroborates it.
func RiskyProviderPortShodan(evt events.DomainEvent) []events.FindingRaised {
	s, ok := evt.(events.ShodanHostsDiscovered)
	if !ok {
		return nil
	}
	var out []events.FindingRaised
	for i := range s.Hosts {
		h := &s.Hosts[i]
		for _, svc := range h.Services {
			if svc.Transport != entities.ProtocolTCP {
				// The finding asserts a TCP service identity, so it needs Shodan to
				// have said tcp. A service reported on udp is not its subject, and one
				// reported with no transport at all is not evidence of a TCP service.
				continue
			}
			if f, ok := riskyProviderPortFinding(h.IP, svc.Port, "Shodan", h.SourceObservedAt); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// RiskyProviderPortNetlas mirrors RiskyProviderPortShodan for Netlas-reported ports.
func RiskyProviderPortNetlas(evt events.DomainEvent) []events.FindingRaised {
	n, ok := evt.(events.NetlasHostsDiscovered)
	if !ok {
		return nil
	}
	var out []events.FindingRaised
	for i := range n.Hosts {
		h := &n.Hosts[i]
		for _, svc := range h.Services {
			if svc.Transport != entities.ProtocolTCP {
				continue
			}
			if f, ok := riskyProviderPortFinding(h.IP, svc.Port, "Netlas", h.SourceObservedAt); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// RiskyProviderPortCensys mirrors RiskyProviderPortShodan for Censys-reported
// ports. Censys carries its ports inside each host's Services, not a flat port list.
func RiskyProviderPortCensys(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CensysHostsDiscovered)
	if !ok {
		return nil
	}
	var out []events.FindingRaised
	for i := range c.Hosts {
		h := &c.Hosts[i]
		for _, svc := range h.Services {
			if svc.Transport != entities.ProtocolTCP {
				continue
			}
			// Censys times each service separately, so the finding carries that
			// service's own scan time rather than a host-wide summary.
			if f, ok := riskyProviderPortFinding(h.IP, svc.Port, "Censys", svc.SourceObservedAt); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// riskyProviderPortFinding builds the inferred risky-open-port finding for a
// provider-reported sensitive port, or ok=false when port is not in sensitivePorts.
// It is identical in Rule and AssetKind/AssetID to RiskyOpenPort (the active rule)
// so the two dedup by entities.FindingID; only Confidence and the evidence/
// provenance wording differ. Note: Findings.Apply keeps the first event's Evidence
// on a dedup merge, so whichever of the provider or active event arrives first sets
// the displayed evidence string - the finding still ends with the correct merged
// Confidence and both events' provenance either way.
func riskyProviderPortFinding(ip string, port int, provider string, observedAt time.Time) (events.FindingRaised, bool) {
	label, risky := sensitivePorts[port]
	if !risky {
		return events.FindingRaised{}, false
	}
	f := events.FindingRaised{
		Rule:            "risky-open-port",
		Title:           fmt.Sprintf("Sensitive service exposed: %s", label),
		FindingCategory: string(entities.FindingExposure),
		AssetKind:       assetService,
		AssetID:         entities.NewServiceID(ip, port, entities.ProtocolTCP).String(),
		Evidence:        fmt.Sprintf("%s is reported open on %s port %d by %s (unverified from this scan).", label, ip, port, provider),
		Recommendation:  "Confirm the service is intended to be public; restrict it with a firewall or move it off the public internet.",
		References:      []string{cweExposedService},
		Confidence:      string(entities.ConfidenceInferred),
		// The provider observed this port from its own vantage point at its own time,
		// which can be far older than this scan. Zero when the provider supplied none;
		// it is never backfilled with the scan time.
		EvidenceObservedAt:      observedAt,
		EvidenceObservationKind: events.ObservationKindPassiveSnapshot,
	}
	f.Severity = events.SeverityHigh
	return f, true
}
