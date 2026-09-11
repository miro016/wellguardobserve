package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = DomainReputationDiscovered{}

// DomainReputationDiscovered signals that threat-intelligence for a domain was
// gathered (via VirusTotal): the community reputation score, per-engine analysis
// vote counts, content categories, tags, popularity ranks, JARM fingerprint, and
// registrar. Like MailSecurity and BreachExposure it is a facet of the owning
// Domain rather than a standalone asset: it describes the domain's standing and
// classification, so it is folded into the Domain alongside the other passive
// facets. VirusTotal's registrar string is carried here rather than as a separate
// DomainRegistrationDiscovered, since whois/RDAP is the authoritative registration
// source and this is only a corroborating field.
type DomainReputationDiscovered struct {
	EventMeta
	Domain          string
	Reputation      int
	Malicious       int
	Suspicious      int
	Harmless        int
	Undetected      int
	Categories      []valueobjects.ReputationCategory
	Tags            []string
	PopularityRanks []valueobjects.PopularityRank
	JARM            string
	Registrar       string
}

// At returns the capture time recorded in the event envelope.
func (e DomainReputationDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e DomainReputationDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e DomainReputationDiscovered) String() string {
	return fmt.Sprintf("discovered reputation for %s (score %d, %d malicious)", e.Domain, e.Reputation, e.Malicious)
}

func (DomainReputationDiscovered) isDomainEvent() {}
