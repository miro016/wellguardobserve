package facts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/analysis"
)

const ctLifecycleTolerance = 30 * 24 * time.Hour

const (
	temporalAnomalyFutureSourceTime       = "source_observation_after_capture"
	temporalAnomalyInvertedValidity       = "inverted_validity_window"
	temporalAnomalyCTOutsideLifecycle     = "ct_log_outside_certificate_lifecycle"
	temporalAnomalyActiveOutsideValidity  = "active_observation_outside_validity"
	temporalAnomalyCurrentHistorical      = "current_evidence_classified_historical"
	temporalAnomalyStaleProvider          = "provider_evidence_older_than_freshness_window"
	temporalAnomalyFallbackOnly           = "scan_time_fallback_only"
	temporalAnomalyClassificationMismatch = "classified_surface_count_mismatch"
)

// TemporalSubjectCoverage counts subjects and the acquisition methods that date them.
// A subject with several assertion kinds contributes once to each kind, preserving the
// complete multi-source history without pretending the rows are mutually exclusive.
type TemporalSubjectCoverage struct {
	Total             int                    `json:"total"`
	ByObservationKind []ObservationKindCount `json:"by_observation_kind"`
}

// ObservationKindCount is the number of distinct assets or relationships carrying an
// assertion acquired by Kind.
type ObservationKindCount struct {
	Kind  events.ObservationKind `json:"kind"`
	Count int                    `json:"count"`
}

// TemporalClassCount reconciles the exclusive currentness classes across assets and
// relationships while keeping the two subject kinds separate.
type TemporalClassCount struct {
	Class         Currentness `json:"class"`
	Assets        int         `json:"assets"`
	Relationships int         `json:"relationships"`
}

// ProviderEvidenceAge describes the dated evidence retained for one source. Times are
// source-supplied, not capture-time fallbacks; age is measured against AnalysisAsOf.
type ProviderEvidenceAge struct {
	Source              string    `json:"source"`
	Observations        int       `json:"observations"`
	OldestObservedAt    time.Time `json:"oldest_observed_at"`
	NewestObservedAt    time.Time `json:"newest_observed_at"`
	OldestAgeHours      float64   `json:"oldest_age_hours"`
	NewestAgeHours      float64   `json:"newest_age_hours"`
	MedianAgeHours      float64   `json:"median_age_hours"`
	FreshnessWindow     string    `json:"freshness_window"`
	FreshnessWindowDays float64   `json:"freshness_window_days"`
}

// TemporalAnomaly is an auditable contradiction or coverage limitation. It never
// removes or rewrites the underlying subject; RawEventID points back to the assertion
// when one event caused it.
type TemporalAnomaly struct {
	Type             string          `json:"type"`
	Severity         events.Severity `json:"severity"`
	SubjectKind      string          `json:"subject_kind,omitempty"`
	Subject          string          `json:"subject,omitempty"`
	Source           string          `json:"source,omitempty"`
	RawEventID       string          `json:"raw_event_id,omitempty"`
	CapturedAt       time.Time       `json:"captured_at,omitzero"`
	SourceObservedAt time.Time       `json:"source_observed_at,omitzero"`
	ValidFrom        time.Time       `json:"valid_from,omitzero"`
	ValidUntil       time.Time       `json:"valid_until,omitzero"`
	LiveVerifiedAt   time.Time       `json:"live_verified_at,omitzero"`
	AnalysisAsOf     time.Time       `json:"analysis_as_of,omitzero"`
	AgeHours         float64         `json:"age_hours,omitzero"`
	Detail           string          `json:"detail"`
}

// TemporalCoverage makes the quality of all temporal claims inspectable. Counts are
// additive over the complete facts graph; the classified surface is a partition beside
// the ledger, never a filter over it.
type TemporalCoverage struct {
	AnalysisAsOf                 time.Time               `json:"analysis_as_of"`
	AnalysisPartial              bool                    `json:"analysis_partial,omitempty"`
	DataView                     string                  `json:"data_view"`
	FreshnessWindows             string                  `json:"freshness_windows"`
	ClockSkewTolerance           string                  `json:"clock_skew_tolerance"`
	ClockSkewToleranceSeconds    int64                   `json:"clock_skew_tolerance_seconds"`
	Assets                       TemporalSubjectCoverage `json:"assets"`
	Relationships                TemporalSubjectCoverage `json:"relationships"`
	AssertionsTotal              int                     `json:"assertions_total"`
	SourceObservedAssertions     int                     `json:"source_observed_assertions"`
	SourceObservedPercent        float64                 `json:"source_observed_percent"`
	SourceObservedSubjects       int                     `json:"source_observed_subjects"`
	SourceObservedSubjectPercent float64                 `json:"source_observed_subject_percent"`
	GenuineValidityIntervals     int                     `json:"genuine_validity_intervals"`
	LiveVerifiedSubjects         int                     `json:"live_verified_subjects"`
	PointObservationsMissingTime int                     `json:"point_observations_missing_source_time"`
	FallbackOnlySubjects         int                     `json:"fallback_only_subjects"`
	DerivedOnlySubjects          int                     `json:"derived_only_subjects"`
	ByCurrentness                []TemporalClassCount    `json:"by_currentness"`
	ProviderEvidenceAge          []ProviderEvidenceAge   `json:"provider_evidence_age,omitempty"`
	ClassifiedAssetCount         int                     `json:"classified_asset_count"`
	ClassifiedRelationshipCount  int                     `json:"classified_relationship_count"`
	ClassifiedCountsReconcile    bool                    `json:"classified_counts_reconcile"`
	Anomalies                    []TemporalAnomaly       `json:"anomalies"`
}

type temporalSubject struct {
	kind        string
	id          string
	assertions  []TemporalAssertion
	intervals   []Interval
	primary     Currentness
	fallback    bool
	sourceDated bool
}

// TemporalCoverage returns the graph's deterministic temporal-quality accounting.
func (g *Graph) TemporalCoverage() TemporalCoverage { return g.snap().TemporalCoverage }

func temporalCoverage(s snapshot, surface ClassifiedSurface, policy analysis.FreshnessPolicy) TemporalCoverage {
	c := TemporalCoverage{
		AnalysisAsOf:                s.AnalysisAsOf,
		AnalysisPartial:             s.AnalysisPartial,
		DataView:                    events.DataViewCompleteHistory,
		FreshnessWindows:            policy.String(),
		ClockSkewTolerance:          policy.ClockSkewTolerance().String(),
		ClockSkewToleranceSeconds:   int64(policy.ClockSkewTolerance() / time.Second),
		ClassifiedAssetCount:        len(surface.Assets),
		ClassifiedRelationshipCount: len(surface.Relationships),
	}

	assetClasses := make(map[string]Currentness, len(surface.Assets))
	for _, a := range surface.Assets {
		assetClasses[string(a.Type)+"\x00"+a.Key] = a.Primary
	}
	relClasses := make(map[string]Currentness, len(surface.Relationships))
	for _, r := range surface.Relationships {
		relClasses[string(r.Type)+"\x00"+r.From+"\x00"+r.To] = r.Primary
	}

	assetKinds := map[events.ObservationKind]int{}
	relKinds := map[events.ObservationKind]int{}
	classAssets := map[Currentness]int{}
	classRels := map[Currentness]int{}
	providerTimes := map[string][]time.Time{}

	for _, a := range s.Assets {
		primary := assetClasses[string(a.Type)+"\x00"+a.Key]
		subject := temporalSubject{kind: "asset", id: string(a.Type) + " " + a.Key,
			assertions: a.Assertions, intervals: a.ValidIntervals, primary: primary,
			fallback: a.SourceTimeMissing, sourceDated: a.SourceDated}
		c.measureSubject(subject, assetKinds, providerTimes, policy)
		classAssets[primary]++
	}
	for _, r := range s.Relationships {
		primary := relClasses[string(r.Type)+"\x00"+r.From+"\x00"+r.To]
		subject := temporalSubject{kind: "relationship", id: string(r.Type) + " " + r.From + " -> " + r.To,
			assertions: r.Assertions, intervals: r.ValidIntervals, primary: primary,
			fallback: r.SourceTimeMissing, sourceDated: r.SourceDated}
		c.measureSubject(subject, relKinds, providerTimes, policy)
		classRels[primary]++
	}

	c.Assets = TemporalSubjectCoverage{Total: len(s.Assets), ByObservationKind: observationKindCounts(assetKinds)}
	c.Relationships = TemporalSubjectCoverage{Total: len(s.Relationships), ByObservationKind: observationKindCounts(relKinds)}
	if c.AssertionsTotal > 0 {
		c.SourceObservedPercent = float64(c.SourceObservedAssertions) * 100 / float64(c.AssertionsTotal)
	}
	if subjects := c.Assets.Total + c.Relationships.Total; subjects > 0 {
		c.SourceObservedSubjectPercent = float64(c.SourceObservedSubjects) * 100 / float64(subjects)
	}
	for _, class := range currentnessPrecedence {
		if classAssets[class]+classRels[class] == 0 {
			continue
		}
		c.ByCurrentness = append(c.ByCurrentness, TemporalClassCount{
			Class: class, Assets: classAssets[class], Relationships: classRels[class],
		})
	}
	c.ProviderEvidenceAge = providerAges(providerTimes, s.AnalysisAsOf, policy)

	for _, issue := range s.Issues {
		if issue.Type != issueInvertedValidityWindow {
			continue
		}
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyInvertedValidity, Severity: issue.Severity,
			Source: issue.Source, RawEventID: issue.RawEventID, Detail: issue.Message,
		})
	}

	c.ClassifiedCountsReconcile = len(surface.Assets) == len(s.Assets) && len(surface.Relationships) == len(s.Relationships) &&
		len(assetClasses) == len(s.Assets) && len(relClasses) == len(s.Relationships)
	if !c.ClassifiedCountsReconcile {
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyClassificationMismatch, Severity: events.SeverityHigh,
			Detail: fmt.Sprintf("facts contain %d assets and %d relationships; classified surface contains %d assets and %d relationships",
				len(s.Assets), len(s.Relationships), len(surface.Assets), len(surface.Relationships)),
		})
	}
	sort.Slice(c.Anomalies, func(i, j int) bool {
		a, b := c.Anomalies[i], c.Anomalies[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.RawEventID < b.RawEventID
	})
	return c
}

func (c *TemporalCoverage) measureSubject(subject temporalSubject, kinds map[events.ObservationKind]int,
	providerTimes map[string][]time.Time, policy analysis.FreshnessPolicy) {
	seenKinds := map[events.ObservationKind]bool{}
	derivedOnly := derivedOnlyAssertions(subject.assertions)
	if derivedOnly {
		c.DerivedOnlySubjects++
	}
	// A subject nothing observed cannot be dated by anything. Every assertion about
	// it is an analysis result computed from other events - a finding and the edges
	// wiring it to its asset and evidence - so there is no source that could have
	// supplied a real-world time and failed to. Counting that as a coverage
	// limitation states a property of the whole class once per member: on two real
	// scans it produced 430 of 515 anomaly rows, all of them unfixable and none of
	// them about the target. They are counted as DerivedOnlySubjects instead, and
	// the classified surface still carries each one with its reason.
	if subject.fallback && !subject.sourceDated && !derivedOnly {
		c.FallbackOnlySubjects++
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyFallbackOnly, Severity: events.SeverityInfo,
			SubjectKind: subject.kind, Subject: subject.id,
			Detail: "no source supplied a real-world time; capture time is retained only as an ordering fallback",
		})
	}
	if subject.primary == CurrentnessLiveVerified {
		c.LiveVerifiedSubjects++
	}
	hasSourceObservation := false
	for _, a := range subject.assertions {
		c.AssertionsTotal++
		seenKinds[a.ObservationKind] = true
		if a.SourceTimeMissing {
			if a.Shape == AssertionPoint {
				c.PointObservationsMissingTime++
			}
		}
		if !a.SourceObservedAt.IsZero() {
			c.SourceObservedAssertions++
			hasSourceObservation = true
		}
		if a.Shape == AssertionInterval {
			c.GenuineValidityIntervals++
		}
		if !a.SourceObservedAt.IsZero() && a.Source != "" {
			providerTimes[a.Source] = append(providerTimes[a.Source], a.SourceObservedAt)
		}
		c.checkAssertion(subject, a, policy)
	}
	if hasSourceObservation {
		c.SourceObservedSubjects++
	}
	for kind := range seenKinds {
		kinds[kind]++
	}
	if subject.primary == CurrentnessHistoricalOnly &&
		(hasDatedKind(subject.assertions, events.ObservationKindActiveProbe) || hasDatedKind(subject.assertions, events.ObservationKindDNSAnswer)) {
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyCurrentHistorical, Severity: events.SeverityHigh,
			SubjectKind: subject.kind, Subject: subject.id,
			Detail: "a dated active or DNS assertion exists but the exclusive surface class is historical_only",
		})
	}
}

func (c *TemporalCoverage) checkAssertion(subject temporalSubject, a TemporalAssertion, policy analysis.FreshnessPolicy) {
	if !a.SourceObservedAt.IsZero() && !a.CapturedAt.IsZero() &&
		a.SourceObservedAt.After(a.CapturedAt.Add(policy.ClockSkewTolerance())) {
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyFutureSourceTime, Severity: events.SeverityMedium,
			SubjectKind: subject.kind, Subject: subject.id, Source: a.Source, RawEventID: a.RawEventID,
			CapturedAt: a.CapturedAt, SourceObservedAt: a.SourceObservedAt, AnalysisAsOf: c.AnalysisAsOf,
			Detail: fmt.Sprintf("source observation %s is after capture %s beyond the allowed %s clock skew",
				a.SourceObservedAt.Format(time.RFC3339), a.CapturedAt.Format(time.RFC3339), policy.ClockSkewTolerance()),
		})
	}
	if a.ObservationKind == events.ObservationKindHistoricalLog && !a.SourceObservedAt.IsZero() &&
		((!a.ValidFrom.IsZero() && a.SourceObservedAt.Before(a.ValidFrom.Add(-ctLifecycleTolerance))) ||
			(!a.ValidUntil.IsZero() && a.SourceObservedAt.After(a.ValidUntil.Add(ctLifecycleTolerance)))) {
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyCTOutsideLifecycle, Severity: events.SeverityMedium,
			SubjectKind: subject.kind, Subject: subject.id, Source: a.Source, RawEventID: a.RawEventID,
			SourceObservedAt: a.SourceObservedAt, ValidFrom: a.ValidFrom, ValidUntil: a.ValidUntil, AnalysisAsOf: c.AnalysisAsOf,
			Detail: "historical-log time falls more than 30 days outside the asserted validity interval",
		})
	}
	activeAt := a.LiveVerifiedAt
	if activeAt.IsZero() && a.ObservationKind == events.ObservationKindActiveProbe {
		activeAt = a.SourceObservedAt
	}
	if !activeAt.IsZero() && len(subject.intervals) > 0 && !intervalsCover(subject.intervals, activeAt) {
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyActiveOutsideValidity, Severity: events.SeverityHigh,
			SubjectKind: subject.kind, Subject: subject.id, Source: a.Source, RawEventID: a.RawEventID,
			CapturedAt: a.CapturedAt, SourceObservedAt: a.SourceObservedAt, ValidFrom: a.ValidFrom,
			ValidUntil: a.ValidUntil, LiveVerifiedAt: activeAt, AnalysisAsOf: c.AnalysisAsOf,
			Detail: fmt.Sprintf("active verification at %s is outside every asserted validity interval", activeAt.Format(time.RFC3339)),
		})
	}
	if a.ObservationKind == events.ObservationKindPassiveSnapshot && !a.SourceObservedAt.IsZero() &&
		!policy.IsFresh(a.Source, a.SourceObservedAt, c.AnalysisAsOf) {
		c.Anomalies = append(c.Anomalies, TemporalAnomaly{
			Type: temporalAnomalyStaleProvider, Severity: events.SeverityLow,
			SubjectKind: subject.kind, Subject: subject.id, Source: a.Source, RawEventID: a.RawEventID,
			CapturedAt: a.CapturedAt, SourceObservedAt: a.SourceObservedAt, AnalysisAsOf: c.AnalysisAsOf,
			AgeHours: c.AnalysisAsOf.Sub(a.SourceObservedAt).Hours(),
			Detail: fmt.Sprintf("provider observation at %s is older than the declared %s freshness window",
				a.SourceObservedAt.Format(time.RFC3339), policy.Window(a.Source)),
		})
	}
}

// derivedOnlyAssertions reports whether every assertion about a subject is an
// analysis result rather than an observation of the world. A subject with no
// assertions at all is not derived: nothing established it either way.
func derivedOnlyAssertions(assertions []TemporalAssertion) bool {
	if len(assertions) == 0 {
		return false
	}
	for _, a := range assertions {
		if a.ObservationKind != events.ObservationKindDerived {
			return false
		}
	}
	return true
}

func observationKindCounts(counts map[events.ObservationKind]int) []ObservationKindCount {
	kinds := make([]events.ObservationKind, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	out := make([]ObservationKindCount, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, ObservationKindCount{Kind: kind, Count: counts[kind]})
	}
	return out
}

func providerAges(bySource map[string][]time.Time, asOf time.Time, policy analysis.FreshnessPolicy) []ProviderEvidenceAge {
	sources := make([]string, 0, len(bySource))
	for source := range bySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	out := make([]ProviderEvidenceAge, 0, len(sources))
	for _, source := range sources {
		times := bySource[source]
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		ages := make([]float64, len(times))
		for i, observedAt := range times {
			ages[i] = asOf.Sub(observedAt).Hours()
		}
		sort.Float64s(ages)
		median := ages[len(ages)/2]
		if len(ages)%2 == 0 {
			median = (ages[len(ages)/2-1] + ages[len(ages)/2]) / 2
		}
		window := policy.Window(source)
		out = append(out, ProviderEvidenceAge{
			Source: source, Observations: len(times), OldestObservedAt: times[0], NewestObservedAt: times[len(times)-1],
			OldestAgeHours: asOf.Sub(times[0]).Hours(), NewestAgeHours: asOf.Sub(times[len(times)-1]).Hours(),
			MedianAgeHours: median, FreshnessWindow: window.String(), FreshnessWindowDays: window.Hours() / 24,
		})
	}
	return out
}

// Markdown renders coverage and anomalies without collapsing the complete subject set.
func (c TemporalCoverage) Markdown() string {
	var sb strings.Builder
	sb.WriteString("## Temporal coverage\n\n")
	fmt.Fprintf(&sb, "Measured %d assertions across %d assets and %d relationships at %s. ",
		c.AssertionsTotal, c.Assets.Total, c.Relationships.Total, c.AnalysisAsOf.Format(time.RFC3339))
	fmt.Fprintf(&sb, "%d assertions (%.1f%%) carry a source observation time; %d point assertions do not.\n\n",
		c.SourceObservedAssertions, c.SourceObservedPercent, c.PointObservationsMissingTime)
	fmt.Fprintf(&sb, "- Source-observed subjects: %d (%.1f%%)\n- Genuine validity intervals: %d\n- Live-verified subjects: %d\n- Fallback-only subjects: %d\n- Derived-only subjects (nothing observed them, so nothing can date them): %d\n- Temporal anomalies: %d\n- Classified counts reconcile: %t\n- Freshness windows: %s\n- Allowed clock skew: %s\n\n",
		c.SourceObservedSubjects, c.SourceObservedSubjectPercent, c.GenuineValidityIntervals, c.LiveVerifiedSubjects,
		c.FallbackOnlySubjects, c.DerivedOnlySubjects, len(c.Anomalies),
		c.ClassifiedCountsReconcile, c.FreshnessWindows, c.ClockSkewTolerance)

	sb.WriteString("### Acquisition coverage\n\n| Observation kind | Assets | Relationships |\n|---|---:|---:|\n")
	assetKinds := kindCountMap(c.Assets.ByObservationKind)
	relKinds := kindCountMap(c.Relationships.ByObservationKind)
	kinds := make(map[events.ObservationKind]bool, len(assetKinds)+len(relKinds))
	for kind := range assetKinds {
		kinds[kind] = true
	}
	for kind := range relKinds {
		kinds[kind] = true
	}
	orderedKinds := make([]events.ObservationKind, 0, len(kinds))
	for kind := range kinds {
		orderedKinds = append(orderedKinds, kind)
	}
	sort.Slice(orderedKinds, func(i, j int) bool { return orderedKinds[i] < orderedKinds[j] })
	for _, kind := range orderedKinds {
		fmt.Fprintf(&sb, "| %s | %d | %d |\n", kind, assetKinds[kind], relKinds[kind])
	}
	sb.WriteString("\n### Primary currentness\n\n| Currentness | Assets | Relationships |\n|---|---:|---:|\n")
	for _, row := range c.ByCurrentness {
		fmt.Fprintf(&sb, "| %s | %d | %d |\n", row.Class, row.Assets, row.Relationships)
	}
	sb.WriteString("\n### Provider evidence age\n\n")
	if len(c.ProviderEvidenceAge) == 0 {
		sb.WriteString("No source supplied provider observation times.\n\n")
	} else {
		sb.WriteString("| Source | Dated assertions | Oldest (age) | Newest (age) | Median age | Freshness window |\n|---|---:|---|---|---:|---:|\n")
		for _, age := range c.ProviderEvidenceAge {
			fmt.Fprintf(&sb, "| %s | %d | %s (%.1f h) | %s (%.1f h) | %.1f h | %.1f d |\n", age.Source, age.Observations,
				age.OldestObservedAt.Format(time.RFC3339), age.OldestAgeHours, age.NewestObservedAt.Format(time.RFC3339), age.NewestAgeHours,
				age.MedianAgeHours, age.FreshnessWindowDays)
		}
		sb.WriteString("\n")
	}
	sb.WriteString("### Temporal anomalies\n\n")
	if len(c.Anomalies) == 0 {
		sb.WriteString("No temporal anomalies detected.\n\n")
		return sb.String()
	}
	// The counts, not the rows. One anomaly type routinely fires once per subject,
	// so the full ledger runs to hundreds of lines and buries every section after
	// it; it is written whole to its own report, where it can be read as a ledger
	// rather than skipped as a wall.
	sb.WriteString("| Type | Severity | Subjects |\n|---|---:|---:|\n")
	for _, row := range c.AnomalyCounts() {
		fmt.Fprintf(&sb, "| %s | %d | %d |\n", row.Type, row.Severity, row.Count)
	}
	fmt.Fprintf(&sb, "\nEvery one of the %d rows behind these counts, with its subject, source, and raw event, "+
		"is in the temporal-anomalies report written beside this one.\n\n", len(c.Anomalies))
	return sb.String()
}

// TemporalAnomalyCount is how many subjects one anomaly type fired on, with the
// severity that type carries.
type TemporalAnomalyCount struct {
	Type     string          `json:"type"`
	Severity events.Severity `json:"severity"`
	Count    int             `json:"count"`
}

// AnomalyCounts summarizes the ledger by type, worst severity first and then by
// type, so the summary orders by what a reader should look at first.
func (c TemporalCoverage) AnomalyCounts() []TemporalAnomalyCount {
	counts := map[string]*TemporalAnomalyCount{}
	for _, a := range c.Anomalies {
		row, ok := counts[a.Type]
		if !ok {
			row = &TemporalAnomalyCount{Type: a.Type, Severity: a.Severity}
			counts[a.Type] = row
		}
		if a.Severity > row.Severity {
			row.Severity = a.Severity
		}
		row.Count++
	}
	out := make([]TemporalAnomalyCount, 0, len(counts))
	for _, row := range counts {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// AnomalyTable renders the full ledger as a Markdown table, one row per anomaly. It
// is what the dedicated temporal-anomalies report prints; the coverage block above
// prints only the counts.
func AnomalyTable(anomalies []TemporalAnomaly) string {
	var sb strings.Builder
	sb.WriteString("| Type | Severity | Subject | Source | Raw event | Detail |\n|---|---:|---|---|---|---|\n")
	for _, a := range anomalies {
		subject := a.Subject
		if subject == "" {
			subject = a.SubjectKind
		}
		fmt.Fprintf(&sb, "| %s | %d | %s | %s | %s | %s |\n", a.Type, a.Severity, subject, a.Source, a.RawEventID, a.Detail)
	}
	return sb.String()
}

func kindCountMap(rows []ObservationKindCount) map[events.ObservationKind]int {
	out := make(map[events.ObservationKind]int, len(rows))
	for _, row := range rows {
		out[row.Kind] = row.Count
	}
	return out
}
