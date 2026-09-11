package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = MailSecurityDiscovered{}

// MailSecurityDiscovered signals that email-authentication records (SPF, DMARC,
// DKIM, BIMI) for a domain were gathered. Mail security posture is distinct from
// DNS resolution records and registration data: it describes whether a name is
// protected against spoofing, so it is folded into the owning Domain alongside
// DnsInfo and Registration rather than kept as a separate asset.
type MailSecurityDiscovered struct {
	EventMeta
	Domain        string
	SPF           string
	SPFAnalysis   *valueobjects.SPFAnalysis
	DMARC         string
	DMARCSeverity string
	DKIM          []valueobjects.DKIMRecord
	BIMI          *valueobjects.BIMIRecord
	// MXCount is how many MX hosts the domain publishes. It tells whether a name
	// actually handles mail, so spoofing findings (missing SPF/DMARC) can be gated
	// to mail-handling domains and not raised on every bare subdomain.
	MXCount int
}

// At returns the capture time recorded in the event envelope.
func (e MailSecurityDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e MailSecurityDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e MailSecurityDiscovered) String() string {
	dmarc := e.DMARCSeverity
	if dmarc == "" {
		dmarc = "unknown"
	}
	return fmt.Sprintf("discovered mail security for %s (DMARC: %s, %d DKIM selector(s))",
		e.Domain, dmarc, len(e.DKIM))
}

func (MailSecurityDiscovered) isDomainEvent() {}
