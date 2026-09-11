package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = MxTlsDiscovered{}

// MxTlsDiscovered signals that an active SMTP probe checked a domain's MX hosts
// for STARTTLS support and TLS posture. It is the active counterpart to the
// passive MailSecurityDiscovered (which gathers SPF/DMARC/DKIM/MX from DNS): this
// event records whether each MX host actually offers STARTTLS and the negotiated
// TLS details, so it is folded into the owning Domain as its own facet. The
// negotiated MX leaf certificate is translated separately as a reused
// CertificateDiscovered event.
type MxTlsDiscovered struct {
	EventMeta
	Domain string
	Hosts  []valueobjects.MxTlsHost
}

// At returns the capture time recorded in the event envelope.
func (e MxTlsDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e MxTlsDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e MxTlsDiscovered) String() string {
	starttls := 0
	for i := range e.Hosts {
		if e.Hosts[i].StartTLSSupported {
			starttls++
		}
	}
	return fmt.Sprintf("discovered MX TLS posture for %s (%d/%d MX host(s) offer STARTTLS)", e.Domain, starttls, len(e.Hosts))
}

func (MxTlsDiscovered) isDomainEvent() {}
