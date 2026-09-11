package findings

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// WildcardCert raises a finding for a certificate that covers a wildcard name.
func WildcardCert(evt events.DomainEvent) []events.FindingRaised {
	c, ok := evt.(events.CertificateDiscovered)
	if !ok {
		return nil
	}
	if c.ObservationKind != events.ObservationKindActiveProbe || c.Certificate.LiveVerifiedAt.IsZero() {
		// Historical CT-log entry, not a live observation; flagging every wildcard
		// a domain ever held is noise. Only flag explicitly live-verified wildcards.
		// Same discriminator as ExpiredCert; see the package doc.
		return nil
	}
	wildcard := ""
	if strings.HasPrefix(c.Certificate.CommonName, "*.") {
		wildcard = c.Certificate.CommonName
	}
	for _, san := range c.Certificate.Domains {
		if strings.HasPrefix(san, "*.") {
			wildcard = san
			break
		}
	}
	if wildcard == "" {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "wildcard-cert",
		Title:           "Wildcard TLS certificate in use",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetCertificate,
		AssetID:         certificateAssetID(c.Certificate),
		Evidence:        fmt.Sprintf("certificate covers wildcard name %s", wildcard),
		Recommendation:  "Review whether a wildcard is required; a leaked key exposes every subdomain.",
		// The handshake that proved the certificate is being served is the evidence,
		// so its instant is the evidence time.
		EvidenceObservedAt:      c.Certificate.LiveVerifiedAt,
		EvidenceObservationKind: events.ObservationKindActiveProbe,
	}
	f.Severity = events.SeverityInfo
	return []events.FindingRaised{f}
}
