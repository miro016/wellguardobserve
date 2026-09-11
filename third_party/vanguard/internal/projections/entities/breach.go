package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// BreachExposure aggregates the data-breach exposure of a single Domain: the
// email aliases on the name that appear in known breaches. Like MailSecurity and
// Registration it is a facet of the owning Domain rather than a standalone asset,
// so a name and its credential exposure read as one entity. In the reconnaissance
// lifecycle this is the passive breach-data step (HIBP breachedDomain).
type BreachExposure struct {
	// Aliases are the breached email aliases and the breaches that exposed them.
	Aliases []valueobjects.BreachedAlias
	// ResolvedAt is when the breach data was last gathered.
	ResolvedAt time.Time
}
