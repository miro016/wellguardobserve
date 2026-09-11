package threats

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// InfraMapping fires when an open zone transfer is combined with multiple
// netblocks: the attacker can map a broad, multi-homed infrastructure.
func InfraMapping(g assetgraph.Graph) []ThreatScenario {
	netblockCount := g.NetblockCount()
	if netblockCount <= 1 {
		return nil
	}
	var out []ThreatScenario
	for _, asset := range g.FindingAssets("domain") {
		id := asset.ID
		zone := g.Findings(asset)["zone-transfer-open"]
		if zone == nil {
			continue
		}
		out = append(out, ThreatScenario{
			Name:       "Broad infrastructure mapping",
			Severity:   int(events.SeverityMedium),
			Narrative:  fmt.Sprintf("%s allows zone transfer while the surface spans %d netblocks; an attacker can enumerate the full zone and map a broad infrastructure footprint.", id, netblockCount),
			Summary:    "A domain allows zone transfer while the surface spans several netblocks; an attacker can enumerate the full zone and map a broad infrastructure footprint.",
			Assets:     []entities.AssetRef{assetRef("domain", id)},
			Evidence:   []string{evidence(zone), fmt.Sprintf("%d netblocks observed", netblockCount)},
			References: []string{"MITRE ATT&CK T1590", cweInfoExposure},
		}.withChain(zone))
	}
	return out
}
