package threats

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// TransportDowngrade fires when a domain has weak transport security and also
// carries credentials or an auth surface worth intercepting.
func TransportDowngrade(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets("domain") {
		id := asset.ID
		m := g.Findings(asset)
		weak := firstOf(m, "weak-tls-version", "mx-no-starttls")
		if weak == nil {
			continue
		}
		breach := m["breach-exposure"]
		if breach == nil && !g.HasAuthSurface(id) {
			continue
		}
		ev := []string{evidence(weak)}
		if breach != nil {
			ev = append(ev, evidence(breach))
		} else {
			ev = append(ev, "auth/admin surface present on the domain")
		}
		out = append(out, ThreatScenario{
			Name:       "Transport downgrade / interception",
			Severity:   int(events.SeverityHigh),
			Narrative:  fmt.Sprintf("%s exposes weak transport security alongside sensitive surface; a network attacker can downgrade or intercept the channel to capture credentials or session data.", id),
			Summary:    "Weak transport security sits alongside sensitive surface; a network attacker can downgrade or intercept the channel to capture credentials or session data.",
			Assets:     []entities.AssetRef{assetRef("domain", id)},
			Evidence:   ev,
			References: []string{attckAiTM, "CWE-319"},
		}.withChain(weak, breach))
	}
	return out
}
