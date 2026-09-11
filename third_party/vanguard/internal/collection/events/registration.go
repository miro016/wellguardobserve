package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = DomainRegistrationDiscovered{}

// DomainRegistrationDiscovered signals that registration data for a domain was
// gathered via WHOIS or RDAP. Registration data (registrar, lifecycle dates,
// contacts) is distinct from DNS resolution records: it describes who owns a
// name and when it expires, not where it points.
//
// DataSource records which leg of the whois tool answered ("whois" or "rdap").
// Combined with EventMeta.Source (the tool name), it lets the same field set be
// compared across data sources and, later, across tools (e.g. paid sources like
// Censys or Shodan) to evaluate tool efficiency and data quality.
type DomainRegistrationDiscovered struct {
	EventMeta
	Domain      string
	DataSource  string
	Registrar   string
	WhoisServer string
	Status      []string
	CreatedDate time.Time
	UpdatedDate time.Time
	ExpiryDate  time.Time
	Nameservers []string
	DNSSEC      bool
	Contacts    []valueobjects.RegistrationContact
}

// At returns the capture time recorded in the event envelope.
func (e DomainRegistrationDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e DomainRegistrationDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e DomainRegistrationDiscovered) String() string {
	if e.Registrar == "" {
		return fmt.Sprintf("discovered registration for %s via %s", e.Domain, e.DataSource)
	}
	return fmt.Sprintf("discovered registration for %s (registrar: %s) via %s", e.Domain, e.Registrar, e.DataSource)
}

func (DomainRegistrationDiscovered) isDomainEvent() {}
