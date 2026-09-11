package findings

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// CensysVulnerabilities raises a finding per Censys host that has known CVEs.
// Censys attributes these from its scan data (the service exposures/compromises
// risk lists), so the finding flags them for analyst review rather than asserting
// exploitability. It mirrors ShodanVulnerabilities and NetlasVulnerabilities and
// reuses the shared CVE evidence/severity helpers, making Censys a third
// independent CVE corroborator.
func CensysVulnerabilities(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CensysHostsDiscovered)
	if !ok {
		return nil
	}
	var findings []events.FindingRaised
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if len(h.Vulns) == 0 {
			continue
		}
		cves := append([]string(nil), h.Vulns...)
		sort.Strings(cves)
		// Censys times each service, not the host, so the newest service scan time is
		// the closest thing to "when Censys last looked at this host". Zero when no
		// service carried one.
		var observedAt time.Time
		for _, svc := range h.Services {
			if svc.SourceObservedAt.After(observedAt) {
				observedAt = svc.SourceObservedAt
			}
		}
		f := events.FindingRaised{
			Rule:            "censys-known-vulnerabilities",
			Title:           "Host with known vulnerabilities (Censys)",
			FindingCategory: string(entities.FindingVulnerability),
			AssetKind:       assetIP,
			AssetID:         h.IP,
			Evidence:        fmt.Sprintf("Censys reports %d known CVE(s) on %s: %s", len(cves), h.IP, strings.Join(cveSample(cves), ", ")),
			Recommendation:  vulnRecommendation,
			References:      cves,
			// Scan-inferred and unverified, like the Shodan and Netlas rules: marked
			// inferred so the risk model down-weights it until it is
			// corroborates the version.
			Confidence: string(entities.ConfidenceInferred),
			// Censys's own scan time, which can be far older than this scan. Zero when
			// Censys supplied none; never backfilled with the scan time.
			EvidenceObservedAt:      observedAt,
			EvidenceObservationKind: events.ObservationKindPassiveSnapshot,
		}
		f.Severity = vulnSeverity(len(cves))
		enrichKnownExploited(&f, cves)
		findings = append(findings, f)
	}
	return findings
}
