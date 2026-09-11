package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ExpiredCert raises a finding for a certificate that is observed live and whose
// validity window has already ended.
//
// It deliberately ignores Certificate Transparency log entries (crt.sh). A CT
// log is a historical record: every certificate a domain ever rotated through
// stays in it forever, so most CT entries are expired by design and flagging
// them produces only noise. ObservationKind explicitly distinguishes those
// records from active TLS probes.
func ExpiredCert(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CertificateDiscovered)
	if !ok {
		return nil
	}
	if c.ObservationKind != events.ObservationKindActiveProbe || c.Certificate.LiveVerifiedAt.IsZero() {
		// Historical CT-log entry, not a live observation; expiry is expected.
		return nil
	}
	// The cutoff is the instant this probe happened, never the wall clock: a rule
	// that read time.Now() would classify the same capture differently on every
	// rebuild. A certificate whose ValidUntil equals the cutoff is still valid, so
	// the comparison is strictly "before".
	cutoff := c.Meta().CapturedAt
	notAfter := c.Certificate.ValidUntil
	if notAfter.IsZero() || !notAfter.Before(cutoff) {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "expired-cert",
		Title:           "Expired TLS certificate",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetCertificate,
		AssetID:         certificateAssetID(c.Certificate),
		Evidence:        fmt.Sprintf("certificate for %s expired on %s", c.Certificate.CommonName, notAfter.Format("2006-01-02")),
		Recommendation:  "Renew or remove the expired certificate so it can no longer be relied upon.",
		// The handshake that proved the certificate is being served is the evidence,
		// so its instant is the evidence time.
		EvidenceObservedAt:      c.Certificate.LiveVerifiedAt,
		EvidenceObservationKind: events.ObservationKindActiveProbe,
	}
	f.Severity = events.SeverityMedium
	return []events.FindingRaised{f}
}
