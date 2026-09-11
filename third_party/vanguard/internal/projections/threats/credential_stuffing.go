package threats

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// CredentialStuffing fires when a domain has breached credentials and also exposes
// an admin/login surface: a direct account-takeover path.
func CredentialStuffing(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets("domain") {
		id := asset.ID
		m := g.Findings(asset)
		breach := m["breach-exposure"]
		// The auth surface fires from an observed login surface (a probe saw an auth
		// challenge or login form) or a dork-inferred admin/auth endpoint. The dork
		// finding, when present, carries the better evidence.
		admin := firstOf(m, "dork-admin-interface", "dork-auth-endpoint")
		if breach == nil || (admin == nil && !g.HasAuthSurface(id)) {
			continue
		}
		surfaceEvidence := "observed login/auth surface on " + id
		if admin != nil {
			surfaceEvidence = evidence(admin)
		}
		ev := []string{evidence(breach), surfaceEvidence}
		severity := int(events.SeverityHigh)
		narrative := fmt.Sprintf("%s has breached credentials and an exposed admin/login surface; an attacker can replay leaked passwords against it for account takeover.", id)
		summary := "A domain has breached credentials and an exposed admin/login surface; an attacker can replay leaked passwords against it for account takeover."
		// A malicious reputation verdict on the same asset up-weights the path: an
		// exposure on a host reputation engines already flag is a stronger vector than
		// either signal alone. The verdict is inferred, so it sharpens an existing path
		// rather than standing up one of its own.
		if g.FlaggedMalicious(id) {
			severity = int(events.SeverityCritical)
			ev = append(ev, "reputation engines flag "+id+" as malicious")
			const flagged = " Reputation engines already flag the host as malicious, raising the likelihood it is actively targeted."
			narrative += flagged
			summary += flagged
		}
		out = append(out, ThreatScenario{
			Name:       "Credential stuffing into exposed admin",
			Severity:   severity,
			Narrative:  narrative,
			Summary:    summary,
			Assets:     []entities.AssetRef{assetRef("domain", id)},
			Evidence:   ev,
			References: []string{"MITRE ATT&CK T1110.004", "CWE-307"},
		}.withChain(breach, admin))
	}
	return out
}
