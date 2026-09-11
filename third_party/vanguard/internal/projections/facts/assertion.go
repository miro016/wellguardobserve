package facts

import (
	"slices"
	"sort"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// AssertionShape discriminates what kind of temporal statement one assertion makes.
// Collapsing the two is the most expensive temporal mistake available: reading a point
// observation as an interval invents uninterrupted existence between two sightings that
// nothing ever established.
type AssertionShape string

const (
	// AssertionPoint is a statement that something was observed at one instant. It says
	// nothing at all about the state before or after that instant.
	AssertionPoint AssertionShape = "point"
	// AssertionInterval is a genuine bounded validity interval the source supplied: a
	// certificate's not_before/not_after, a domain's registration window. Only a source
	// that actually declares an interval produces one.
	AssertionInterval AssertionShape = "interval"
)

// TemporalAssertion is one source's complete temporal statement about one asset or
// relationship, retained verbatim so a consumer can reconstruct what any single source
// claimed and when. Assertions accumulate: a later, stronger assertion may win the
// compact summary fields, but it never replaces or erases an earlier one.
//
// SourceTimeMissing is the honest half of the record. When a source supplies no
// real-world time the compact FirstSeen/LastSeen summary still falls back to CapturedAt
// so the asset stays sortable, and this flag marks that the fallback is not evidence the
// asset existed at scan time.
type TemporalAssertion struct {
	Source          string                 `json:"source,omitempty"`
	ObservationKind events.ObservationKind `json:"observation_kind,omitempty"`
	Shape           AssertionShape         `json:"shape"`
	Phase           events.Phase           `json:"phase,omitempty"`
	Confidence      Confidence             `json:"confidence,omitempty"`
	RawEventID      string                 `json:"raw_event_id,omitempty"`
	ToolCorrID      string                 `json:"tool_corr_id,omitempty"`
	EvidenceID      string                 `json:"evidence_id,omitempty"`
	// CapturedAt is when Vanguard recorded the claim; it is always known.
	CapturedAt time.Time `json:"captured_at"`
	// SourceObservedAt is when the source says it observed the subject, present only
	// when the source supplied it.
	SourceObservedAt time.Time `json:"source_observed_at,omitzero"`
	// ValidFrom and ValidUntil bound a genuine validity interval, set only on an
	// AssertionInterval.
	ValidFrom  time.Time `json:"valid_from,omitzero"`
	ValidUntil time.Time `json:"valid_until,omitzero"`
	// LiveVerifiedAt is when Vanguard itself directly confirmed the subject.
	LiveVerifiedAt time.Time `json:"live_verified_at,omitzero"`
	// SourceTimeMissing marks an assertion carrying no real-world time at all, whose
	// only contribution to the compact summary is the scan-time fallback.
	SourceTimeMissing bool `json:"source_time_missing,omitempty"`
}

// Interval is a normalized real-world validity window on an asset or relationship.
type Interval struct {
	From  time.Time `json:"from,omitzero"`
	Until time.Time `json:"until,omitzero"`
}

// claim is the real-world temporal content of one event's statement about an asset or
// relationship. The zero claim means the source supplied no real-world time, which the
// upsert records as SourceTimeMissing rather than reading scan time as existence.
type claim struct {
	SourceObservedAt time.Time
	ValidFrom        time.Time
	ValidUntil       time.Time
	LiveVerifiedAt   time.Time
	Confidence       Confidence
	EvidenceID       string
	// NoSubjectTime marks an event that dates the scan but not the subject: an empty
	// DNS answer, or a bare mention of a name some other event referenced. Vanguard did
	// the observing, so CapturedAt is a real instant, but it is not evidence that the
	// subject existed then, so the assertion stays undated.
	NoSubjectTime bool
}

// isUndated reports whether the claim carries no real-world time whatsoever, which is
// what separates a genuine observation from a scan-time fallback.
func (c claim) isUndated() bool {
	return c.SourceObservedAt.IsZero() && c.ValidFrom.IsZero() &&
		c.ValidUntil.IsZero() && c.LiveVerifiedAt.IsZero()
}

// selfObserved reports whether Vanguard itself did the observing, which is the only case
// where the capture time is also a real-world observation time. For every other kind
// someone else observed the subject, at an instant only they know: substituting the scan
// time there would manufacture currency the source never claimed.
func selfObserved(kind events.ObservationKind) bool {
	switch kind {
	case events.ObservationKindActiveProbe, events.ObservationKindDNSAnswer:
		return true
	case events.ObservationKindInput, events.ObservationKindHistoricalLog,
		events.ObservationKindPassiveSnapshot, events.ObservationKindDerived,
		events.ObservationKindLifecycle, events.ObservationKindOperational:
		return false
	}
	return false
}

// assert builds the temporal assertion the event being folded makes, given the
// real-world content the normalizer extracted from its payload.
func assert(m events.EventMeta, cl claim) TemporalAssertion {
	if cl.isUndated() && !cl.NoSubjectTime && selfObserved(m.ObservationKind) {
		cl.SourceObservedAt = m.CapturedAt
	}
	shape := AssertionPoint
	if !cl.ValidFrom.IsZero() || !cl.ValidUntil.IsZero() {
		shape = AssertionInterval
	}
	return TemporalAssertion{
		Source:            m.Source,
		ObservationKind:   m.ObservationKind,
		Shape:             shape,
		Phase:             m.Phase,
		Confidence:        cl.Confidence,
		RawEventID:        m.EventID,
		ToolCorrID:        m.ToolCorrID,
		EvidenceID:        cl.EvidenceID,
		CapturedAt:        m.CapturedAt,
		SourceObservedAt:  cl.SourceObservedAt,
		ValidFrom:         cl.ValidFrom,
		ValidUntil:        cl.ValidUntil,
		LiveVerifiedAt:    cl.LiveVerifiedAt,
		SourceTimeMissing: cl.isUndated(),
	}
}

// appendAssertion adds an assertion to a list, skipping an exact repeat. Two normalizers
// touching the same asset from one event (a bare mention followed by a dated upsert)
// must not inflate the counts, but any assertion differing in time, shape, or provenance
// is kept: that difference is the evidence.
func appendAssertion(list []TemporalAssertion, a TemporalAssertion) []TemporalAssertion {
	if slices.Contains(list, a) {
		return list
	}
	return append(list, a)
}

// TemporalSummary holds the precisely defined summary fields both assets and
// relationships derive from their assertion lists. Each answers one question that the
// compact FirstSeen/LastSeen pair cannot.
type TemporalSummary struct {
	// EarliestKnownAt is the earliest real-world instant any assertion establishes. It
	// is zero when no source supplied a real-world time, which is a different statement
	// from "first seen at scan time".
	EarliestKnownAt time.Time `json:"earliest_known_at,omitzero"`
	// LatestSourceObservedAt is the newest source-supplied observation time.
	LatestSourceObservedAt time.Time `json:"latest_source_observed_at,omitzero"`
	// LastLiveVerifiedAt is the newest direct confirmation by Vanguard itself.
	LastLiveVerifiedAt time.Time `json:"last_live_verified_at,omitzero"`
	// ValidIntervals is the normalized union of the genuine validity intervals asserted
	// about the subject. Point observations never contribute here.
	ValidIntervals []Interval `json:"valid_intervals,omitempty"`
	// CapturedAtFirst and CapturedAtLast bound Vanguard's own collection window, which
	// is a fact about the scan and never about the subject.
	CapturedAtFirst time.Time `json:"captured_at_first,omitzero"`
	CapturedAtLast  time.Time `json:"captured_at_last,omitzero"`
	// SourceTimeMissing marks that at least one assertion is a scan-time fallback.
	SourceTimeMissing bool `json:"source_time_missing,omitempty"`
	// SourceDated marks that at least one assertion carries a real-world time. A subject
	// with SourceTimeMissing and without SourceDated is datable only by the scan itself.
	SourceDated bool `json:"source_dated,omitempty"`
}

// summarize computes the summary fields from an assertion list.
func summarize(assertions []TemporalAssertion) TemporalSummary {
	var s TemporalSummary
	var intervals []Interval
	for _, a := range assertions {
		if a.SourceTimeMissing {
			s.SourceTimeMissing = true
		} else {
			s.SourceDated = true
		}
		if !a.CapturedAt.IsZero() {
			if s.CapturedAtFirst.IsZero() || a.CapturedAt.Before(s.CapturedAtFirst) {
				s.CapturedAtFirst = a.CapturedAt
			}
			if a.CapturedAt.After(s.CapturedAtLast) {
				s.CapturedAtLast = a.CapturedAt
			}
		}
		if a.SourceObservedAt.After(s.LatestSourceObservedAt) {
			s.LatestSourceObservedAt = a.SourceObservedAt
		}
		if a.LiveVerifiedAt.After(s.LastLiveVerifiedAt) {
			s.LastLiveVerifiedAt = a.LiveVerifiedAt
		}
		for _, t := range []time.Time{a.SourceObservedAt, a.ValidFrom, a.LiveVerifiedAt} {
			if !t.IsZero() && (s.EarliestKnownAt.IsZero() || t.Before(s.EarliestKnownAt)) {
				s.EarliestKnownAt = t
			}
		}
		if a.Shape == AssertionInterval {
			intervals = append(intervals, Interval{From: a.ValidFrom, Until: a.ValidUntil})
		}
	}
	s.ValidIntervals = mergeIntervals(intervals)
	return s
}

// mergeIntervals returns the normalized union of validity intervals: sorted by start and
// merged where they overlap or touch. An interval with an open end (a zero ValidUntil)
// absorbs everything after its start, since nothing bounds it.
func mergeIntervals(in []Interval) []Interval {
	if len(in) == 0 {
		return nil
	}
	iv := append([]Interval(nil), in...)
	sort.Slice(iv, func(i, j int) bool {
		if !iv[i].From.Equal(iv[j].From) {
			return iv[i].From.Before(iv[j].From)
		}
		return iv[i].Until.Before(iv[j].Until)
	})
	out := []Interval{iv[0]}
	for _, cur := range iv[1:] {
		last := &out[len(out)-1]
		if last.Until.IsZero() {
			continue // already unbounded from an earlier start
		}
		if cur.From.After(last.Until) {
			out = append(out, cur)
			continue
		}
		if cur.Until.IsZero() || cur.Until.After(last.Until) {
			last.Until = cur.Until
		}
	}
	return out
}
