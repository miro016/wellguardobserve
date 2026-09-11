package facts

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// realSeen picks the real-world instant t for an asset's compact first/last-seen window,
// falling back to the capture time m.CapturedAt when the source carries no real-world
// timestamp.
//
// The fold in upsertAsset takes min(FirstSeen)/max(LastSeen) across every observation, so
// feeding a real-world instant here lowers an asset's FirstSeen to when it actually existed
// (a certificate's not_before, a domain's registration date, a name's CT-log entry) instead
// of when this scan happened to see it. The scan time is never lost: it stays on
// Observation.CapturedAt, so the audit view is intact while the graph's first/last-seen
// becomes the real-world lifecycle the facts timeline needs.
//
// The fallback is a layout convenience only. It is never evidence that the asset existed
// at scan time, and the assertion recorded alongside it says so: the caller passes the
// same zero time as a claim, which records SourceTimeMissing. Read
// TemporalSummary.SourceDated, not the window, to tell the two apart.
func realSeen(m events.EventMeta, t time.Time) time.Time {
	if t.IsZero() {
		return m.CapturedAt
	}
	return t.UTC()
}

// realSeenWindow returns an ordered real-world window. Incomplete or inconsistent
// upstream lifecycle data must not produce first_seen later than last_seen.
//
// An inverted window is clamped so the compact summary stays ordered, and recorded as an
// issue carrying both original timestamps: silently swallowing it would hide upstream
// data corruption that the temporal coverage block has to surface. The assertion keeps
// the source's original ValidFrom and ValidUntil either way, so the clamp never rewrites
// what the source actually said.
func (g *Graph) realSeenWindow(m events.EventMeta, subject string, first, last time.Time) (firstSeen, lastSeen time.Time) {
	firstSeen = realSeen(m, first)
	lastSeen = realSeen(m, last)
	if lastSeen.Before(firstSeen) {
		g.addIssue(Issue{
			Type: issueInvertedValidityWindow, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("%s: validity starts %s after it ends %s; window clamped for ordering, original bounds kept on the assertion",
				subject, first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339)),
			RawEventID: m.EventID,
		})
		lastSeen = firstSeen
	}
	return firstSeen, lastSeen
}
