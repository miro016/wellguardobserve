package persistence

import (
	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
	"github.com/velgard-sk/vanguard/internal/projections/report"
)

// AnalysisContext derives the temporal context a report is judged against from an event
// stream: the fixed cutoff, the declared freshness policy, the classified surface, and
// its temporal-quality accounting.
//
// All three come from the same stream on purpose. A cutoff from one scan applied to
// another scan's surface would produce counts that look authoritative and reconcile to
// nothing, so they are derived together rather than assembled by each caller.
func AnalysisContext(evts []events.DomainEvent) (report.Analysis, error) {
	g, err := facts.Build(evts)
	if err != nil {
		return report.Analysis{}, err
	}
	surface := g.ClassifiedSurface()
	coverage := g.TemporalCoverage()
	return report.Analysis{AsOf: g.AnalysisAsOf(), Freshness: g.FreshnessPolicy(), Surface: &surface, Coverage: &coverage}, nil
}

// captureScan recovers scan identity and timing from the lifecycle events, so a
// report can be rebuilt without a separate metadata file. A collection is one
// invocation and its log carries one ScanStarted/ScanCompleted bracket; taking the
// earliest start and the latest completion is corrupt-log tolerance, so a
// concatenated or hand-edited log still yields a bracket that contains every event
// rather than one that cuts the stream in half.
func captureScan(scan *entities.Scan, evt events.DomainEvent) {
	switch e := evt.(type) {
	case events.ScanStarted:
		if scan.ID == "" || e.At().Before(scan.StartedAt) {
			s, err := entities.NewScan(e.Meta().ScanID, e.RootTarget, e.At())
			if err == nil {
				s.CompletedAt = scan.CompletedAt
				*scan = s
			}
		}
	case events.ScanCompleted:
		if e.At().After(scan.CompletedAt) {
			scan.CompletedAt = e.At()
		}
	}
}
