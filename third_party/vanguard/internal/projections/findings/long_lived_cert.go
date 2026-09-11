package findings

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// maxCertLifetime is the CA/Browser Forum cap on certificate validity. Windows
// longer than this are a sign of a misissued or legacy certificate.
const maxCertLifetime = 398 * 24 * time.Hour

// LongLivedCert raises a finding for a certificate whose validity window exceeds
// the maximum allowed lifetime.
func LongLivedCert(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CertificateDiscovered)
	if !ok {
		return nil
	}
	if c.ObservationKind != events.ObservationKindActiveProbe || c.Certificate.LiveVerifiedAt.IsZero() {
		// Historical CT-log entry, not a live observation. The CT log keeps every
		// cert a domain ever rotated through, so flagging long-lived legacy certs
		// there is pure noise; only flag explicitly live-verified certificates.
		// Same discriminator as ExpiredCert; see the package doc.
		return nil
	}
	nb, na := c.Certificate.ValidFrom, c.Certificate.ValidUntil
	if nb.IsZero() || na.IsZero() || na.Sub(nb) <= maxCertLifetime {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "long-lived-cert",
		Title:           "Certificate validity window exceeds 398 days",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetCertificate,
		AssetID:         certificateAssetID(c.Certificate),
		Evidence:        fmt.Sprintf("certificate for %s is valid for %d days (%s to %s)", c.Certificate.CommonName, int(na.Sub(nb).Hours()/24), nb.Format("2006-01-02"), na.Format("2006-01-02")),
		Recommendation:  "Reissue with a validity window of 398 days or fewer.",
		// The handshake that proved the certificate is being served is the evidence,
		// so its instant is the evidence time.
		EvidenceObservedAt:      c.Certificate.LiveVerifiedAt,
		EvidenceObservationKind: events.ObservationKindActiveProbe,
	}
	f.Severity = events.SeverityLow
	return []events.FindingRaised{f}
}
