package events

import (
	"fmt"
	"time"
)

// DataViewCompleteHistory names the data view every Vanguard artifact currently
// produces: the complete record of everything the scan learned, with each claim
// classified for currentness rather than filtered out. It is stamped next to
// AnalysisAsOf so a reader never has to guess whether a summary was pruned.
const DataViewCompleteHistory = "complete history, with currentness classification"

// AnalysisAsOf is the single cutoff every temporal judgement is evaluated against.
// Terms such as expired, expiring, current, recent, stale, and historical are
// meaningless without a reference time, and a wall-clock read would make the same
// capture classify differently on every rebuild. Deriving the cutoff from the event
// stream instead keeps a rebuild byte-stable.
//
// It lives in this package rather than in a projection because it is a property of
// the event stream itself: every consumer that folds the stream (the facts graph,
// the operator report, the findings classification) needs the same value computed
// the same way.
type AnalysisAsOf struct {
	// At is the cutoff instant. It is never zero in a valid value.
	At time.Time
	// Partial is true when the stream carried no ScanCompleted, so At is the latest
	// observation rather than a completion marker. A renderer must say "partial as
	// of" in that case: the scan may have been interrupted, and later evidence that
	// a completed run would have produced is missing rather than absent.
	Partial bool
}

// DeriveAnalysisAsOf computes the analysis cutoff for a whole event stream.
//
// A collection is one invocation, so a well-formed stream carries one ScanCompleted
// and the cutoff is that instant. The latest completion is taken rather than the
// first purely as corrupt-log tolerance: a concatenated or hand-edited log can carry
// more than one, and reading the newest keeps the cutoff at or after every
// observation instead of classifying later evidence against an earlier marker. Each
// contributing event keeps its own CapturedAt, so observation ages stay visible
// either way.
//
// It returns an error rather than a zero cutoff: every event the orchestrator emits
// stamps CapturedAt, so a stream with none is truncated, hand-edited, or written by
// an incompatible vocabulary, and every classification derived from it would be
// silently wrong.
func DeriveAnalysisAsOf(evts []DomainEvent) (AnalysisAsOf, error) {
	var latestCompleted, latestAny time.Time
	for _, evt := range evts {
		at := AsValue(evt).Meta().CapturedAt
		if at.After(latestAny) {
			latestAny = at
		}
		if _, ok := AsValue(evt).(ScanCompleted); ok && at.After(latestCompleted) {
			latestCompleted = at
		}
	}
	return AnalysisAsOfFrom(latestCompleted, latestAny)
}

// AnalysisAsOfFrom applies the cutoff rule to timestamps a caller already tracked,
// so a streaming fold that never holds the whole slice (the live Projection) and a
// batch fold that does (DeriveAnalysisAsOf) cannot disagree about the rule.
//
// latestCompleted is the latest ScanCompleted capture time, zero when the stream had
// none. latestAny is the latest capture time of any event in the stream.
func AnalysisAsOfFrom(latestCompleted, latestAny time.Time) (AnalysisAsOf, error) {
	if !latestCompleted.IsZero() {
		return AnalysisAsOf{At: latestCompleted.UTC()}, nil
	}
	if !latestAny.IsZero() {
		return AnalysisAsOf{At: latestAny.UTC(), Partial: true}, nil
	}
	return AnalysisAsOf{}, fmt.Errorf("cannot derive an analysis cutoff: no event carries a capture time")
}

// String renders the cutoff the way every artifact must label it, so the "partial"
// qualification cannot be dropped by one renderer and kept by another.
func (a AnalysisAsOf) String() string {
	if a.Partial {
		return "partial as of " + a.At.Format(time.RFC3339) + " (latest observation; no scan completion in stream)"
	}
	return "as of " + a.At.Format(time.RFC3339) + " (scan completion)"
}
