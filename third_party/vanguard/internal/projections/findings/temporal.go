package findings

import (
	"sort"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/analysis"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// accumulateTemporal folds one raised finding's evidence times into the entity.
// It only widens: a later contributing event can add evidence but never erase what
// an earlier one established, which is what keeps the complete ledger intact.
func accumulateTemporal(f *entities.Finding, e events.FindingRaised) {
	if at := e.EvidenceObservedAt; !at.IsZero() {
		if f.EvidenceObservedFirst.IsZero() || at.Before(f.EvidenceObservedFirst) {
			f.EvidenceObservedFirst = at
		}
		if at.After(f.EvidenceObservedLast) {
			f.EvidenceObservedLast = at
		}
	}
	if at := e.Meta().CapturedAt; at.After(f.LastCorroboratedAt) {
		f.LastCorroboratedAt = at
	}
	if src, at := e.Meta().Source, e.EvidenceObservedAt; src != "" && !at.IsZero() {
		if f.EvidenceObservedBySource == nil {
			f.EvidenceObservedBySource = map[string]entities.EvidenceWindow{}
		}
		w := f.EvidenceObservedBySource[src]
		if w.First.IsZero() || at.Before(w.First) {
			w.First = at
		}
		if at.After(w.Last) {
			w.Last = at
		}
		f.EvidenceObservedBySource[src] = w
	}
	if kind := string(e.EvidenceObservationKind); kind != "" {
		f.EvidenceKinds = unionSorted(f.EvidenceKinds, []string{kind})
	}
}

// Classify assigns every finding its temporal status against one fixed cutoff.
//
// It runs as a finalize pass rather than inside Apply because the cutoff is only
// known once the whole stream has been seen: the collection's completion decides it.
// Classifying during the fold would judge early findings against an incomplete
// cutoff and make a rebuild unstable. It is idempotent for a given cutoff.
//
// Nothing is removed or reordered. Classification is additive metadata on findings
// that all stay in the ledger.
func (f *Findings) Classify(asOf time.Time, policy analysis.FreshnessPolicy) {
	f.ensureInit()
	for _, finding := range f.All {
		classify(finding, asOf, policy)
	}
}

// classify derives one finding's temporal status, reason, and corroboration.
//
// The two dimensions stay separate: this function never reads Confidence, because
// how trustworthy a finding is is a different question from whether its evidence is
// current.
func classify(f *entities.Finding, asOf time.Time, policy analysis.FreshnessPolicy) {
	f.EvaluatedAt = asOf

	direct, corroboration := directEvidence(f.EvidenceKinds)
	historicalLog := containsKind(f.EvidenceKinds, events.ObservationKindHistoricalLog)
	passive := containsKind(f.EvidenceKinds, events.ObservationKindPassiveSnapshot)

	// The two window bounds answer different questions. Whether any contributing
	// source is outside its own declared window says the evidence is partly stale;
	// whether any is inside says something still supports the finding as current.
	// Reading only the newest would let one fresh confirmation hide a year-old
	// provider claim that merged into the same finding.
	freshSource, staleSource := sourceFreshness(f.EvidenceObservedBySource, asOf, policy)
	oldestStale := staleSource != ""
	newestFresh := freshSource != ""

	switch {
	case direct && (oldestStale || historicalLog):
		// Vanguard saw it now and something else saw it long ago. Both are true, and
		// reporting only one of them would misstate what the finding rests on.
		f.TemporalStatus = entities.TemporalStatusMixed
		f.TemporalReason = "current_and_historical_evidence_combined"
		f.CurrentCorroboration = corroboration
	case direct:
		f.TemporalStatus = entities.TemporalStatusCurrent
		f.TemporalReason = directReason(corroboration)
		f.CurrentCorroboration = corroboration
	case passive && newestFresh:
		f.TemporalStatus = entities.TemporalStatusCurrent
		f.TemporalReason = "provider_observation_within_freshness_window:" + freshSource
		f.CurrentCorroboration = entities.CorroborationRecentPassive
	case passive && !f.EvidenceObservedLast.IsZero():
		f.TemporalStatus = entities.TemporalStatusHistorical
		f.TemporalReason = "provider_observation_older_than_freshness_window:" + staleSource
		f.CurrentCorroboration = entities.CorroborationNone
	case historicalLog:
		f.TemporalStatus = entities.TemporalStatusHistorical
		f.TemporalReason = "historical_log_entry"
		f.CurrentCorroboration = entities.CorroborationNone
	case passive:
		// A source claimed something but never said when it looked. That is not
		// evidence of currency, and not evidence of staleness either.
		f.TemporalStatus = entities.TemporalStatusUnknown
		f.TemporalReason = "source_supplied_no_observation_time"
		f.CurrentCorroboration = entities.CorroborationNone
	default:
		f.TemporalStatus = entities.TemporalStatusUnknown
		f.TemporalReason = "no_evidence_observation_time"
		f.CurrentCorroboration = entities.CorroborationNone
	}
}

// sourceFreshness returns the source of the newest evidence still inside its own
// declared window, and the source of the oldest evidence already outside it. Both are
// empty when no source supplied an observation time, which is unknown rather than either
// fresh or stale. One source can answer both, when it contributed a fresh observation and
// a stale one to the same finding: that is precisely the mixed case.
//
// Sources are visited in sorted order so a finding backed by two equally recent sources
// always names the same one, keeping the reason string replay-stable.
func sourceFreshness(bySource map[string]entities.EvidenceWindow, asOf time.Time, policy analysis.FreshnessPolicy) (fresh, stale string) {
	var freshAt, staleAt time.Time
	sources := make([]string, 0, len(bySource))
	for src := range bySource {
		sources = append(sources, src)
	}
	sort.Strings(sources)
	for _, src := range sources {
		w := bySource[src]
		if !w.Last.IsZero() && policy.IsFresh(src, w.Last, asOf) && w.Last.After(freshAt) {
			freshAt, fresh = w.Last, src
		}
		if !w.First.IsZero() && !policy.IsFresh(src, w.First, asOf) && (staleAt.IsZero() || w.First.Before(staleAt)) {
			staleAt, stale = w.First, src
		}
	}
	return fresh, stale
}

// directEvidence reports whether Vanguard itself observed the subject during the
// scan, and which kind of observation was the strongest. An active probe outranks a
// DNS answer: a completed handshake proves the service responded, a resolved name
// only proves it resolved.
func directEvidence(kinds []string) (bool, entities.Corroboration) {
	switch {
	case containsKind(kinds, events.ObservationKindActiveProbe):
		return true, entities.CorroborationActive
	case containsKind(kinds, events.ObservationKindDNSAnswer):
		return true, entities.CorroborationDNS
	default:
		return false, entities.CorroborationNone
	}
}

// directReason names why a directly observed finding is current.
func directReason(c entities.Corroboration) string {
	if c == entities.CorroborationDNS {
		return "dns_answer_during_scan"
	}
	return "observed_directly_during_scan"
}

// containsKind reports whether an observation kind is among a finding's evidence.
func containsKind(kinds []string, kind events.ObservationKind) bool {
	for _, k := range kinds {
		if k == string(kind) {
			return true
		}
	}
	return false
}
