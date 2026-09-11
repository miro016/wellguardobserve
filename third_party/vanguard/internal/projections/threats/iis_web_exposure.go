package threats

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// IISWebExposure fires when an internet-facing IIS web application both discloses
// its exact build (version-disclosure) and lacks hardening headers
// (missing-security-headers) on the same endpoint. Both findings key on the same
// canonical Endpoint id (the exact normalized URL the probe fetched), so the pairing
// lands on one asset and never merges two different URLs. That configuration class is
// the recurring target of documented IIS/Exchange exploitation, so the pairing is a
// concrete pre-attack surface rather than two isolated low findings.
//
// The IIS match reads the version-disclosure finding's structured ServiceFacet (its
// CPE or product), not the Evidence prose, so it does not break when the detector
// rewords its evidence and it can tell one build from another.
func IISWebExposure(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets(entities.AssetKindEndpoint) {
		m := g.Findings(asset)
		ver := m["version-disclosure"]
		hdr := m["missing-security-headers"]
		if ver == nil || hdr == nil {
			continue
		}
		if !isIISFacet(ver.Service) {
			continue
		}
		// The asset id is already the concrete URL, so it is also the display label.
		display := asset.ID
		out = append(out, ThreatScenario{
			Name:       "Exposed IIS web application",
			Severity:   int(events.SeverityMedium),
			Narrative:  fmt.Sprintf("%s runs an internet-facing IIS application that discloses its exact build and lacks hardening headers; this is the configuration class targeted by documented IIS/Exchange exploitation.", display),
			Summary:    "An internet-facing IIS application discloses its exact build and lacks hardening headers; this is the configuration class targeted by documented IIS/Exchange exploitation.",
			Assets:     []entities.AssetRef{assetRef(entities.AssetKindEndpoint, asset.ID)},
			Evidence:   []string{evidence(ver), evidence(hdr)},
			References: []string{"MITRE ATT&CK T1190", cweInfoExposure},
		}.withChain(ver, hdr))
	}
	return out
}

// isIISFacet reports whether a service facet identifies Microsoft IIS. NVD has used
// both internet_information_server and internet_information_services as IIS product
// tokens, so parsed CPEs match either. Product-name fallback covers producers with no
// CPE. Evidence prose is never parsed.
func isIISFacet(s entities.ServiceFacet) bool {
	for _, raw := range s.CPEs {
		cpe, ok := valueobjects.ParseCPE(raw)
		if !ok {
			continue
		}
		if strings.EqualFold(cpe.Product, "internet_information_server") ||
			strings.EqualFold(cpe.Product, "internet_information_services") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(s.Product), "iis")
}
