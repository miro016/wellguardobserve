package threats

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// OpenDataExposure fires when search-exposed open directories, backups, or config
// files were found: data is reachable without authentication.
func OpenDataExposure(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets("domain") {
		id := asset.ID
		m := g.Findings(asset)
		var ev []string
		var contributing []*entities.Finding
		for _, rule := range []string{"dork-open-directory", "dork-backup-exposure", "dork-config-exposure"} {
			if f := m[rule]; f != nil {
				ev = append(ev, evidence(f))
				contributing = append(contributing, f)
			}
		}
		if len(ev) == 0 {
			continue
		}
		out = append(out, ThreatScenario{
			Name:       "Open data exposure",
			Severity:   int(events.SeverityHigh),
			Narrative:  fmt.Sprintf("%s exposes open directories, backups, or configuration files to search engines; an attacker can harvest data or secrets without authentication.", id),
			Summary:    "Open directories, backups, or configuration files are exposed to search engines; an attacker can harvest data or secrets without authentication.",
			Assets:     []entities.AssetRef{assetRef("domain", id)},
			Evidence:   ev,
			References: []string{"MITRE ATT&CK T1213", "CWE-552"},
		}.withChain(contributing...))
	}
	return out
}
