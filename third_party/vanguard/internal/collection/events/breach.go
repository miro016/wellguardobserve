package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = BreachDataDiscovered{}

// BreachDataDiscovered signals that email aliases on a domain were found in known
// data breaches (via the HIBP breachedDomain endpoint). Like MailSecurity and
// Registration it is a facet of the owning Domain rather than a standalone asset:
// it describes credential exposure tied to a name, so it is folded into the
// Domain alongside the other passive facets. An empty Breaches slice is not
// emitted; the orchestrator only translates a non-empty result.
type BreachDataDiscovered struct {
	EventMeta
	Domain   string
	Breaches []valueobjects.BreachedAlias
}

// At returns the capture time recorded in the event envelope.
func (e BreachDataDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e BreachDataDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e BreachDataDiscovered) String() string {
	return fmt.Sprintf("discovered breach data for %s (%d exposed alias(es))", e.Domain, len(e.Breaches))
}

func (BreachDataDiscovered) isDomainEvent() {}
