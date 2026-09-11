package threats

import (
	"fmt"
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ExpiredLiveCert fires when an expired or long-lived certificate covers a name that
// is actually serving TLS: a real, in-use trust problem rather than a stale record.
// Liveness is resolved by any face (g.LiveDomain) - the name's own TlsPosture or an
// IP it resolves to that served live TLS - so a cert served on a bare IP still counts,
// not only one on a name with its own https posture.
func ExpiredLiveCert(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets(entities.AssetKindCertificate) {
		certID := asset.ID
		f := firstOf(g.Findings(asset), "expired-cert", "long-lived-cert")
		if f == nil {
			continue
		}
		names, ok := g.CertNames(certID)
		if !ok {
			// The finding's certificate is not in the inventory; nothing to chain to.
			continue
		}
		var live []string
		for _, d := range names {
			if g.LiveDomain(d) {
				live = append(live, d)
			}
		}
		if len(live) == 0 {
			continue
		}
		sort.Strings(live)
		assets := []entities.AssetRef{assetRef(entities.AssetKindCertificate, certID)}
		for _, d := range live {
			assets = append(assets, assetRef("domain", d))
		}
		out = append(out, ThreatScenario{
			Name:       "Expired or stale certificate on a live service",
			Severity:   int(events.SeverityHigh),
			Narrative:  fmt.Sprintf("certificate %s (%s) covers a name still serving TLS (%s); clients face certificate errors an attacker can normalise to mask interception.", certDisplay(certID), f.Rule, live[0]),
			Summary:    "A certificate that is expired or stale still covers a name serving TLS; clients face certificate errors an attacker can normalise to mask interception.",
			Assets:     assets,
			Evidence:   []string{evidence(f), "live TLS on " + live[0]},
			References: []string{attckAiTM, "CWE-298"},
		}.withChain(f))
	}
	return out
}

// certDisplay renders a certificate asset id for an operator: the canonical serial when
// the key carries one, otherwise the key itself (a common-name-only or issuer-only
// certificate still has to be nameable in the narrative).
func certDisplay(certID string) string {
	if serial, ok := entities.CertSerialFromID(certID); ok {
		return serial
	}
	return certID
}
