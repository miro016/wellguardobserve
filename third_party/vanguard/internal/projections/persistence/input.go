package persistence

import (
	"errors"
	"fmt"
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/projections/dataquality"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
	"github.com/velgard-sk/vanguard/internal/projections/scandiff"
)

// LoadEvents reads a collection's canonical domain-event log. It is the one door
// every projection fold comes through, so a projection package never opens a
// collection file itself and the persisted format has exactly one reader on this
// side of the boundary.
func LoadEvents(collectionDir string) ([]events.DomainEvent, error) {
	return collection.LoadEvents(collectionDir)
}

// BuildFacts folds a collection's event stream into the complete facts graph. The
// graph is a pure fold over the domain-event log; nothing else is read.
func BuildFacts(collectionDir string) (*facts.Graph, error) {
	evts, err := LoadEvents(collectionDir)
	if err != nil {
		return nil, fmt.Errorf("load events: %w", err)
	}
	g, err := facts.Build(evts)
	if err != nil {
		return nil, fmt.Errorf("build facts graph: %w", err)
	}
	return g, nil
}

// BuildDataQuality computes the data-quality report for one collection. The
// domain-event log is required; a missing tool-event log yields a content-only
// report, while a present malformed log is rejected rather than mistaken for no
// operational evidence.
func BuildDataQuality(collectionDir string) (dataquality.Report, error) {
	evts, err := LoadEvents(collectionDir)
	if err != nil {
		return dataquality.Report{}, fmt.Errorf("load events: %w", err)
	}
	op, err := loadOpStats(collectionDir)
	if err != nil {
		return dataquality.Report{}, err
	}
	return dataquality.Build(evts, op), nil
}

// BuildDiff compares two collections. Both canonical event logs are required; a
// missing tool-event log makes the operational delta unavailable, while a present
// malformed log is rejected. The comparison is scoped to the high-signal default -
// discovery, finding, and validation content - with lifecycle events excluded and
// issues summarized as counts.
func BuildDiff(baselineDir, candidateDir string) (scandiff.Report, error) {
	a, err := LoadEvents(baselineDir)
	if err != nil {
		return scandiff.Report{}, fmt.Errorf("load baseline events: %w", err)
	}
	b, err := LoadEvents(candidateDir)
	if err != nil {
		return scandiff.Report{}, fmt.Errorf("load candidate events: %w", err)
	}
	op, err := loadOpDelta(baselineDir, candidateDir)
	if err != nil {
		return scandiff.Report{}, err
	}
	return scandiff.Build(a, b, op, scandiff.DefaultOptions()), nil
}

// loadOpStats folds a collection's tool-event log into the data-quality report's
// operational input. A missing log is not an error: a collection with no tool-event
// stream simply has no operational half.
func loadOpStats(collectionDir string) (dataquality.OpStats, error) {
	stats, ok, err := toolStats(collectionDir)
	if err != nil {
		return dataquality.OpStats{}, fmt.Errorf("load tool-event statistics: %w", err)
	}
	if !ok {
		return dataquality.OpStats{Available: false}, nil
	}
	op := dataquality.OpStats{Available: true, Providers: make(map[string]dataquality.ProviderOps, len(stats.Tools))}
	for name, ts := range stats.Tools {
		op.Providers[name] = dataquality.ProviderOps{
			Provider:      name,
			Events:        ts.Total,
			Errors:        ts.ByLevel["error"],
			Warns:         ts.ByLevel["warn"],
			RateLimited:   ts.RateLimited,
			Empties:       ts.Empties,
			Calls:         ts.Calls,
			FailedCalls:   ts.FailedCalls,
			Unavailable:   ts.Unavailable,
			MedianLatency: ts.MedianLatency(),
		}
	}
	return op, nil
}

// loadOpDelta builds the per-provider operational delta from each collection's
// tool-event log. If either side has no log the delta is marked unavailable and the
// diff is content-only: comparing one real rollup against an empty one would report
// every provider as having stopped working. A present unreadable or malformed log
// is an error because treating broken evidence as absent would hide the defect.
func loadOpDelta(baselineDir, candidateDir string) (scandiff.OpDelta, error) {
	a, okA, err := toolStats(baselineDir)
	if err != nil {
		return scandiff.OpDelta{}, fmt.Errorf("load baseline tool-event statistics: %w", err)
	}
	b, okB, err := toolStats(candidateDir)
	if err != nil {
		return scandiff.OpDelta{}, fmt.Errorf("load candidate tool-event statistics: %w", err)
	}
	if !okA || !okB {
		return scandiff.OpDelta{Available: false}, nil
	}

	names := make(map[string]struct{}, len(a.Tools)+len(b.Tools))
	for name := range a.Tools {
		names[name] = struct{}{}
	}
	for name := range b.Tools {
		names[name] = struct{}{}
	}
	// Only the few counts the diff needs travel: calls, failed calls, and empties.
	// Latency and reliability belong to the quality report, which states them for one
	// collection rather than as a difference between two.
	providers := make([]scandiff.ProviderOpDelta, 0, len(names))
	for name := range names {
		pd := scandiff.ProviderOpDelta{Provider: name}
		if as := a.Tools[name]; as != nil {
			pd.ACalls, pd.AFailed, pd.AEmpties = as.Calls, as.FailedCalls, as.Empties
		}
		if bs := b.Tools[name]; bs != nil {
			pd.BCalls, pd.BFailed, pd.BEmpties = bs.Calls, bs.FailedCalls, bs.Empties
		}
		providers = append(providers, pd)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Provider < providers[j].Provider })
	return scandiff.OpDelta{Available: true, Providers: providers}, nil
}

// toolStats folds one collection's tool-event log, reporting whether there was one
// to fold. The two are separate answers: a collection with no tool log has nothing
// to say about its providers, which is not the same as a collection whose providers
// did nothing.
func toolStats(collectionDir string) (stats tooleventlog.ToolingStats, found bool, resultErr error) {
	f, ok, err := collection.ReadToolLog(collectionDir)
	if err != nil {
		return tooleventlog.ToolingStats{}, false, err
	}
	if !ok {
		return tooleventlog.ToolingStats{}, false, nil
	}
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close tool-event log: %w", err))
		}
	}()
	stats, err = tooleventlog.ReplayTooling(f)
	if err != nil {
		return tooleventlog.ToolingStats{}, true, fmt.Errorf("replay tool-event log: %w", err)
	}
	return stats, true, nil
}
