package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// NetlasVulnerabilities raises a finding per Netlas host that has known CVEs.
// Netlas associates CVEs from its scan data, so the finding flags them for
// analyst review rather than asserting exploitability. It mirrors
// ShodanVulnerabilities and reuses the shared CVE evidence/severity helpers.
func NetlasVulnerabilities(evt events.DomainEvent) []events.FindingRaised {
	n, ok := evt.(events.NetlasHostsDiscovered)
	if !ok {
		return nil
	}
	var findings []events.FindingRaised
	for i := range n.Hosts {
		h := &n.Hosts[i]
		if len(h.Vulns) == 0 {
			continue
		}
		cves := append([]string(nil), h.Vulns...)
		sort.Strings(cves)
		f := events.FindingRaised{
			Rule:            "netlas-known-vulnerabilities",
			Title:           "Host with known vulnerabilities (Netlas)",
			FindingCategory: string(entities.FindingVulnerability),
			AssetKind:       assetIP,
			AssetID:         h.IP,
			Evidence:        fmt.Sprintf("Netlas reports %d known CVE(s) on %s: %s", len(cves), h.IP, strings.Join(cveSample(cves), ", ")),
			Recommendation:  vulnRecommendation,
			References:      cves,
			// Banner-inferred and unverified, like the Shodan rule: marked inferred so
			// the risk model down-weights it until it is corroborated.
			Confidence: string(entities.ConfidenceInferred),
			// Netlas's own index timestamp, which can be far older than this scan. Zero
			// when Netlas supplied none; never backfilled with the scan time.
			EvidenceObservedAt:      h.SourceObservedAt,
			EvidenceObservationKind: events.ObservationKindPassiveSnapshot,
		}
		f.Severity = vulnSeverity(len(cves))
		enrichKnownExploited(&f, cves)
		findings = append(findings, f)
	}
	return findings
}
