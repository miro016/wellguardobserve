package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// maxVulnsInEvidence caps how many CVEs are listed in a finding's evidence, so a
// host with a long vulnerability list does not produce an unwieldy string.
const maxVulnsInEvidence = 15

// vulnRecommendation is the shared remediation advice for the provider CVE rules
// (shodan/netlas/censys), which all infer CVEs from passive data.
const vulnRecommendation = "Verify the affected services and patch or mitigate the reported CVEs."

// ShodanVulnerabilities raises a finding per Shodan host that has known CVEs.
// Shodan infers these from service banners (not verified exploitation), so the
// finding flags them for analyst review rather than asserting exploitability.
func ShodanVulnerabilities(evt events.DomainEvent) []events.FindingRaised {
	s, ok := evt.(events.ShodanHostsDiscovered)
	if !ok {
		return nil
	}
	var findings []events.FindingRaised
	for i := range s.Hosts {
		h := &s.Hosts[i]
		if len(h.Vulns) == 0 {
			continue
		}
		cves := append([]string(nil), h.Vulns...)
		sort.Strings(cves)
		f := events.FindingRaised{
			Rule:            "shodan-known-vulnerabilities",
			Title:           "Host with known vulnerabilities (Shodan)",
			FindingCategory: string(entities.FindingVulnerability),
			AssetKind:       assetIP,
			AssetID:         h.IP,
			Evidence:        fmt.Sprintf("Shodan reports %d known CVE(s) on %s: %s", len(cves), h.IP, strings.Join(cveSample(cves), ", ")),
			Recommendation:  vulnRecommendation,
			References:      cves,
			// Banner-inferred and unverified: Shodan infers CVEs from service banners
			// without exploitation. Marked inferred so the risk model down-weights it
			// until the version is corroborated.
			Confidence: string(entities.ConfidenceInferred),
			// Shodan's own banner timestamp, which can be far older than this scan.
			// Zero when Shodan supplied none; never backfilled with the scan time.
			EvidenceObservedAt:      h.SourceObservedAt,
			EvidenceObservationKind: events.ObservationKindPassiveSnapshot,
		}
		f.Severity = vulnSeverity(len(cves))
		enrichKnownExploited(&f, cves)
		findings = append(findings, f)
	}
	return findings
}

// vulnSeverity grades a host by how many CVEs were inferred: a single CVE is
// High, several is Critical. Shared by the Shodan and Netlas rules.
func vulnSeverity(count int) events.Severity {
	if count >= 5 {
		return events.SeverityCritical
	}
	return events.SeverityHigh
}

// cveSample returns at most maxVulnsInEvidence CVEs, appending a remainder note.
func cveSample(cves []string) []string {
	if len(cves) <= maxVulnsInEvidence {
		return cves
	}
	out := append([]string(nil), cves[:maxVulnsInEvidence]...)
	return append(out, fmt.Sprintf("(+%d more)", len(cves)-maxVulnsInEvidence))
}
