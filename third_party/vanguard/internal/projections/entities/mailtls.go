package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// MxTls aggregates the active SMTP STARTTLS posture of a single Domain's MX
// hosts. Like MailSecurity it is a facet of the owning Domain rather than a
// standalone asset, and is the active-phase counterpart to the passive
// MailSecurity facet (SPF/DMARC/DKIM/MX from DNS): it records whether each MX
// host actually offers STARTTLS and the negotiated TLS details.
type MxTls struct {
	// Hosts holds the per-MX STARTTLS/TLS posture, ordered by priority.
	Hosts []valueobjects.MxTlsHost
	// ResolvedAt is when the MX hosts were last probed.
	ResolvedAt time.Time
}
