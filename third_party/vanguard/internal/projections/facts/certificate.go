package facts

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// applyCertificate folds a CertificateDiscovered event: the Certificate asset (keyed by
// issuer+serial) plus a cert_covers_name edge to each concrete name it covers. Wildcard
// SANs stay as certificate data and create no name asset, matching the inventory rule.
func (g *Graph) applyCertificate(e events.CertificateDiscovered) {
	m := e.Meta()
	c := e.Certificate
	if c.IssuerName == "" && c.SerialNumber == "" && c.CommonName == "" {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: "certificate event without issuer, serial, or common name", RawEventID: m.EventID})
		return
	}
	key := entities.CertificateID(c.IssuerName, c.SerialNumber, c.CommonName)
	attrs := map[string]any{"common_name": c.CommonName, "issuer": c.IssuerName, "serial": c.SerialNumber}
	if !c.ValidFrom.IsZero() {
		attrs["valid_from"] = c.ValidFrom
	}
	if !c.ValidUntil.IsZero() {
		attrs["valid_until"] = c.ValidUntil
	}
	if !c.LoggedAt.IsZero() {
		attrs["logged_at"] = c.LoggedAt
	}
	if !c.LiveVerifiedAt.IsZero() {
		attrs["live_verified_at"] = c.LiveVerifiedAt
	}
	// A certificate's real-world lifecycle is its validity window, so the asset is seen
	// from valid_from to valid_until rather than at scan time.
	certFirstSeen, certLastSeen := g.realSeenWindow(m, key, c.ValidFrom, c.ValidUntil)
	disc := "cert:" + key
	certClaim := claim{ValidFrom: c.ValidFrom, ValidUntil: c.ValidUntil,
		LiveVerifiedAt: c.LiveVerifiedAt, Confidence: ConfidenceHigh, EvidenceID: evID(m.EventID, disc)}
	g.upsertAssetClaim(Asset{Type: AssetCertificate, Key: key, Attributes: attrs,
		FirstSeen: certFirstSeen, LastSeen: certLastSeen, Sources: srcs(m.Source)}, certClaim)
	// The scalar issuer/serial attributes are first-write-wins, so when a live and a CT
	// observation merge onto one asset only the first producer's raw strings survive there.
	// Accumulate every raw form into set attributes so both the CT DN and the live "O CN"
	// issuer, and both serial spellings, stay retrievable on the merged certificate.
	if c.IssuerName != "" {
		g.unionAssetSet(AssetCertificate, key, "issuers", []string{c.IssuerName})
	}
	if c.SerialNumber != "" {
		g.unionAssetSet(AssetCertificate, key, "serials", []string{c.SerialNumber})
	}
	oid := obsID(m.EventID, disc)
	g.addObservation(Observation{
		ID: oid, Type: "certificate_observed", AssetKey: key, Source: m.Source,
		Mode: m.Phase, ObservationKind: m.ObservationKind, Confidence: ConfidenceHigh,
		Currentness: certificateCurrentness(m, c, g.asOf.At), RawEventID: m.EventID,
		CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		ValidFrom: c.ValidFrom, ValidUntil: c.ValidUntil, LoggedAt: c.LoggedAt,
		LiveVerifiedAt: c.LiveVerifiedAt,
		Metadata:       map[string]any{"common_name": c.CommonName, "search_query": e.SearchQuery},
	})
	g.addEvidence(Evidence{
		ID: evID(m.EventID, disc), Type: "certificate_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("%s reported certificate %q issued by %s.", m.Source, c.CommonName, c.IssuerName),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, RawEventID: m.EventID,
	})

	// birth is the public first-appearance of the covered names: the CT-log entry time,
	// falling back to the certificate's not_before. Seeding each covered name with it lowers
	// the name's FirstSeen (via the min-fold in upsertAsset) to when it entered CT, not when
	// this scan resolved it.
	birth := c.LoggedAt
	if birth.IsZero() {
		birth = c.ValidFrom
	}
	seen := make(map[string]bool)
	names := append([]string{c.CommonName}, c.Domains...)
	for _, n := range names {
		name := normalizeFQDN(n)
		if name == "" || isWildcard(name) || seen[name] {
			continue
		}
		seen[name] = true
		g.ensureDomain(m, name)
		g.upsertAssetClaim(Asset{Type: assetTypeFor(name, g.rootTarget), Key: name,
			FirstSeen: realSeen(m, birth), LastSeen: realSeen(m, birth)},
			claim{SourceObservedAt: birth, Confidence: ConfidenceHigh, EvidenceID: evID(m.EventID, disc)})
		// cert_covers_name describes the certificate's valid coverage, not when the
		// certificate happened to enter CT. Historical CT entries can postdate expiry,
		// so using the validity window also guarantees an ordered relationship window.
		g.upsertRelationshipClaim(Relationship{Type: RelCertCoversName, From: key, To: name,
			EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceHigh, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: certFirstSeen, LastSeen: certLastSeen}, certClaim)
	}
}

// certificateCurrentness classifies one certificate observation without changing
// confidence or removing any historical record.
//
// cutoff is the scan's single analysis as-of time, not the observing event's own
// capture time: every certificate in one scan must be judged against one reference
// instant, or two certificates observed minutes apart get different verdicts and a
// rebuild is not stable.
//
// Both validity bounds are inclusive. A certificate whose ValidUntil equals the
// cutoff is still valid, not expired; one whose ValidFrom equals the cutoff has
// already started.
func certificateCurrentness(m events.EventMeta, c events.CertificateData, cutoff time.Time) Currentness {
	if m.ObservationKind == events.ObservationKindActiveProbe && !c.LiveVerifiedAt.IsZero() {
		return CurrentnessLiveVerified
	}
	if cutoff.IsZero() {
		return CurrentnessUnknown
	}
	if !c.ValidUntil.IsZero() && c.ValidUntil.Before(cutoff) {
		return CurrentnessHistoricalOnly
	}
	startsByCutoff := c.ValidFrom.IsZero() || !c.ValidFrom.After(cutoff)
	endsAfterCutoff := !c.ValidUntil.IsZero() && !c.ValidUntil.Before(cutoff)
	if startsByCutoff && endsAfterCutoff {
		return CurrentnessValidUnverified
	}
	if m.ObservationKind == events.ObservationKindHistoricalLog && !c.LoggedAt.IsZero() && !c.LoggedAt.After(cutoff) {
		return CurrentnessHistoricalOnly
	}
	return CurrentnessUnknown
}
