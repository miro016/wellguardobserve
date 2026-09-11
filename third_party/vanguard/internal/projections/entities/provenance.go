package entities

import "time"

// Provenance records how a fact about an asset was established. An asset may
// accumulate several provenance records as multiple events touch it.
type Provenance struct {
	// EventID is the domain event that contributed this fact.
	EventID string
	// Source is the tool or component that produced the event.
	Source string
	// Phase is the recon phase ("passive" or "active").
	Phase string
	// ObservationKind states how the contributing claim was obtained.
	ObservationKind string
	// CapturedAt is when Vanguard recorded the contributing event.
	CapturedAt time.Time
	// UnscopedRequest marks a contribution whose destination was outside the
	// engagement scope, observed by a request path that could not be authorized
	// before it dialed. An asset carrying such an entry rests, at least in part, on
	// out-of-scope traffic. It is false for every scope-enforced observation.
	UnscopedRequest bool
}

// AnyUnscopedRequest reports whether any contribution in provs came from a request
// path that could not authorize its destination before dialing it. It is the single
// question an analysis or a report asks of an asset's provenance to decide whether
// to filter or flag it, so the rule stays in one place rather than being restated
// per consumer.
func AnyUnscopedRequest(provs []Provenance) bool {
	for _, p := range provs {
		if p.UnscopedRequest {
			return true
		}
	}
	return false
}

// Confidence expresses how trustworthy an asset attribution or finding is. For a
// finding it doubles as the verification state: an inferred finding is unverified
// until a later observation corroborates it and reports it confirmed.
type Confidence string

const (
	// ConfidenceConfirmed marks a directly observed fact (for example a DNS A
	// record, a completed TLS handshake).
	ConfidenceConfirmed Confidence = "confirmed"
	// ConfidenceInferred marks a derived or third-party-inferred, unverified fact
	// (for example a SAN entry not yet resolved, a banner-inferred CVE).
	ConfidenceInferred Confidence = "inferred"
)

// confidenceRank orders confidence from least to most trustworthy, so merges can
// take the stronger value deterministically (order-independent on replay).
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceConfirmed:
		return 2
	case ConfidenceInferred:
		return 1
	default: // empty / unknown
		return 0
	}
}

// Stronger returns the more trustworthy of two confidences. It defines the
// finding verification upgrade path: when a later event reports the same
// rule+asset finding confirmed, an inferred finding is upgraded to confirmed.
func (c Confidence) Stronger(other Confidence) Confidence {
	if confidenceRank(other) > confidenceRank(c) {
		return other
	}
	return c
}
