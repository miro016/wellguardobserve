package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// MailSecurity aggregates the email-authentication posture of a single Domain:
// SPF, DMARC, DKIM, and BIMI. Like DnsInfo and Registration it is a facet of the
// owning Domain rather than a standalone asset, so a name and its mail posture
// read as one entity. In the reconnaissance lifecycle this is the passive mail
// security step. MX records are not duplicated here: they live in DnsInfo.
type MailSecurity struct {
	// SPF is the domain's SPF (v=spf1) record, empty when none is published.
	SPF string
	// SPFAnalysis is the worst-case static analysis of the SPF record and its
	// include/redirect chain. Nil when no SPF record was found.
	SPFAnalysis *valueobjects.SPFAnalysis
	// DMARC is the domain's DMARC (_dmarc) record, empty when none is published.
	DMARC string
	// DMARCSeverity classifies the DMARC posture: "critical" (missing),
	// "warning" (p=none), "info" (p=quarantine), or "ok" (p=reject).
	DMARCSeverity string
	// DKIM holds the discovered DKIM selectors and their records.
	DKIM []valueobjects.DKIMRecord
	// BIMI is the domain's BIMI record, nil when none is published.
	BIMI *valueobjects.BIMIRecord
	// ResolvedAt is when the mail security records were last gathered.
	ResolvedAt time.Time
}
