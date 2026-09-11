package findings

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// certExpiryWindow is how close to ValidUntil a live certificate must be before it
// is flagged as expiring. Three weeks gives an operator time to renew before an
// outage while staying quiet for healthy certs renewed on the usual cadence.
const certExpiryWindow = 21 * 24 * time.Hour

// ExpiringCert raises a finding for a live certificate that has not yet expired
// but whose ValidUntil falls within certExpiryWindow. It complements ExpiredCert
// (already past ValidUntil) by catching the renewal before the outage.
//
// Like the other certificate rules it only considers an explicitly live-verified
// active-probe observation actionable. See the package doc.
func ExpiringCert(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CertificateDiscovered)
	if !ok {
		return nil
	}
	if c.ObservationKind != events.ObservationKindActiveProbe || c.Certificate.LiveVerifiedAt.IsZero() {
		// Historical CT-log entry, not a live observation; expiry is expected.
		return nil
	}
	notAfter := c.Certificate.ValidUntil
	if notAfter.IsZero() {
		return nil
	}
	// The cutoff is the instant this probe happened, never the wall clock, so a
	// rebuild of the same capture yields the same window and the same day count.
	cutoff := c.Meta().CapturedAt
	// Already expired is ExpiredCert's job; only flag a still-valid cert near expiry.
	// Both bounds are inclusive: a certificate expiring exactly at the cutoff is
	// still valid, and one expiring exactly at the window edge is still flagged.
	if notAfter.Before(cutoff) || notAfter.After(cutoff.Add(certExpiryWindow)) {
		return nil
	}
	days := int(notAfter.Sub(cutoff).Hours() / 24)
	f := events.FindingRaised{
		Rule:            "expiring-cert",
		Title:           "TLS certificate expiring soon",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetCertificate,
		AssetID:         certificateAssetID(c.Certificate),
		Evidence:        fmt.Sprintf("certificate for %s expires on %s (in %d day(s))", c.Certificate.CommonName, notAfter.Format("2006-01-02"), days),
		Recommendation:  "Renew the certificate before it expires to avoid a TLS outage.",
		// The handshake that proved the certificate is being served is the evidence,
		// so its instant is the evidence time.
		EvidenceObservedAt:      c.Certificate.LiveVerifiedAt,
		EvidenceObservationKind: events.ObservationKindActiveProbe,
	}
	f.Severity = events.SeverityLow
	return []events.FindingRaised{f}
}
