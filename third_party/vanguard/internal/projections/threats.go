package projections

import (
	"github.com/velgard-sk/vanguard/internal/projections/threats"
)

// BuildThreats runs the curated threat scenarios (internal/projections/threats)
// over the read-only asset graph folded from the event stream. It is a pure function
// of the projection, so the same scan always yields the same scenarios.
func (p *Projection) BuildThreats() []threats.ThreatScenario {
	return threats.Build(p.assetGraph())
}
