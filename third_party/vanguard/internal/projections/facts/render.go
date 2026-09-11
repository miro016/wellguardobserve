package facts

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Coverage records how completely the stream was folded: how many events were mapped by
// a normalizer and which event types have none yet.
type Coverage struct {
	EventsTotal    int            `json:"events_total"`
	EventsMapped   int            `json:"events_mapped"`
	UnmappedByType map[string]int `json:"unmapped_by_type,omitempty"`
}

// snapshot is the deterministic, serializable view of the graph: every collection is
// sorted and the per-type unmapped coverage is materialized into issues.
type snapshot struct {
	ScanID      string    `json:"scan_id"`
	GeneratedAt time.Time `json:"generated_at"`
	// AnalysisAsOf is the fixed cutoff every currentness label in this file was
	// evaluated against, and AnalysisPartial says the stream carried no scan
	// completion so the cutoff is the latest observation instead. Without them a
	// reader cannot tell what "historical" or "valid_unverified" was measured from.
	AnalysisAsOf    time.Time `json:"analysis_as_of"`
	AnalysisPartial bool      `json:"analysis_partial,omitempty"`
	// DataView states that nothing was filtered out of this file: it is the complete
	// record with currentness classification applied, not a current-only surface.
	DataView          string                           `json:"data_view"`
	Environments      []events.ScanEnvironmentRecorded `json:"environments,omitempty"`
	Assets            []Asset                          `json:"assets"`
	Observations      []Observation                    `json:"observations"`
	Evidence          []Evidence                       `json:"evidence"`
	Relationships     []Relationship                   `json:"relationships"`
	FindingCandidates []FindingCandidate               `json:"finding_candidates"`
	Issues            []Issue                          `json:"issues"`
	Coverage          Coverage                         `json:"coverage"`
	// Surface is the exclusive currentness breakdown over exactly the assets above.
	// It is derived, not filtered: every asset in Assets appears in it once.
	Surface ClassifiedSurface `json:"classified_surface"`
	// TemporalCoverage accounts for which claims are source-dated, which use only a
	// capture-time fallback, and which contradictions need operator attention.
	TemporalCoverage TemporalCoverage `json:"temporal_coverage"`
}

// snap builds the sorted snapshot from the fold state.
func (g *Graph) snap() snapshot {
	assets := make([]Asset, 0, len(g.assetIdx))
	for _, a := range g.assetIdx {
		cp := *a
		// The summaries are derived here rather than maintained during the fold: a
		// validity-interval union cannot be widened incrementally without either
		// re-normalizing on every upsert or losing the individual intervals.
		cp.TemporalSummary = summarize(cp.Assertions)
		assets = append(assets, cp)
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Type != assets[j].Type {
			return assets[i].Type < assets[j].Type
		}
		return assets[i].Key < assets[j].Key
	})

	rels := make([]Relationship, 0, len(g.relIdx))
	for _, r := range g.relIdx {
		cp := *r
		cp.TemporalSummary = summarize(cp.Assertions)
		rels = append(rels, cp)
	}
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].Type != rels[j].Type {
			return rels[i].Type < rels[j].Type
		}
		if rels[i].From != rels[j].From {
			return rels[i].From < rels[j].From
		}
		return rels[i].To < rels[j].To
	})

	obs := append([]Observation(nil), g.observations...)
	sort.Slice(obs, func(i, j int) bool { return obs[i].ID < obs[j].ID })
	ev := append([]Evidence(nil), g.evidence...)
	sort.Slice(ev, func(i, j int) bool { return ev[i].ID < ev[j].ID })

	cands := make([]FindingCandidate, 0, len(g.findIdx))
	for _, c := range g.findIdx {
		cands = append(cands, *c)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })

	issues := append([]Issue(nil), g.issues...)
	for t, c := range g.unmapped {
		issues = append(issues, Issue{
			Type:     issueUnmappedEventType,
			Source:   "facts",
			Severity: events.SeverityLow,
			Message:  fmt.Sprintf("%d event(s) of type %s have no facts normalizer yet", c, t),
		})
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Type != issues[j].Type {
			return issues[i].Type < issues[j].Type
		}
		if issues[i].Message != issues[j].Message {
			return issues[i].Message < issues[j].Message
		}
		return issues[i].RawEventID < issues[j].RawEventID
	})

	s := snapshot{
		ScanID:            g.scanID,
		GeneratedAt:       g.generatedAt,
		AnalysisAsOf:      g.AnalysisAsOf().At,
		AnalysisPartial:   g.AnalysisAsOf().Partial,
		DataView:          events.DataViewCompleteHistory,
		Environments:      append([]events.ScanEnvironmentRecorded(nil), g.environments...),
		Assets:            assets,
		Observations:      obs,
		Evidence:          ev,
		Relationships:     rels,
		FindingCandidates: cands,
		Issues:            issues,
		Coverage: Coverage{
			EventsTotal:    g.total,
			EventsMapped:   g.mapped,
			UnmappedByType: g.unmapped,
		},
	}
	s.Surface = classifiedSurface(s, g.asOf, g.policy)
	s.TemporalCoverage = temporalCoverage(s, s.Surface, g.policy)
	return s
}

// JSON renders the full facts graph as indented, deterministically ordered JSON.
func (g *Graph) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(g.snap(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal facts graph: %w", err)
	}
	return b, nil
}

// Markdown renders a human summary of the facts graph: totals, assets and relationships
// by type, and the coverage of the event stream.
func (g *Graph) Markdown() string {
	s := g.snap()
	var sb strings.Builder
	sb.WriteString("# Facts graph\n\n")
	if s.ScanID != "" {
		fmt.Fprintf(&sb, "Scan `%s`.\n\n", s.ScanID)
	}
	if len(s.Environments) > 0 {
		sb.WriteString("## Run environment\n\n")
		for _, e := range s.Environments {
			fmt.Fprintf(&sb, "- %s %s, config `%s`", e.Actor.Name, e.Actor.Version, e.ConfigSHA256)
			if e.Runtime.NmapVersion != "" {
				fmt.Fprintf(&sb, ", nmap %s", e.Runtime.NmapVersion)
			}
			sb.WriteString(".\n")
		}
		sb.WriteString("\n")
	}
	// Every currentness label below is relative to this cutoff, so it is stated
	// before any count rather than in a distant methodology note.
	fmt.Fprintf(&sb, "Temporal scope: %s.\nData view: %s.\n\n", g.AnalysisAsOf().String(), events.DataViewCompleteHistory)
	fmt.Fprintf(&sb, "- Assets: %d\n- Observations: %d\n- Evidence: %d\n- Relationships: %d\n- Finding candidates: %d\n- Issues: %d\n\n",
		len(s.Assets), len(s.Observations), len(s.Evidence), len(s.Relationships),
		len(s.FindingCandidates), len(s.Issues))

	sb.WriteString("## Assets by type\n\n")
	writeCountTable(&sb, "Asset type", countBy(s.Assets, func(a Asset) string { return string(a.Type) }))

	sb.WriteString("## Relationships by type\n\n")
	writeCountTable(&sb, "Relationship", countBy(s.Relationships, func(r Relationship) string { return string(r.Type) }))

	sb.WriteString("## Finding candidates by category\n\n")
	writeCountTable(&sb, "Category", countBy(s.FindingCandidates, func(c FindingCandidate) string { return c.Category }))

	sb.WriteString(s.Surface.Markdown())
	sb.WriteString(s.TemporalCoverage.Markdown())

	sb.WriteString("## Coverage\n\n")
	fmt.Fprintf(&sb, "Events mapped: %d / %d.\n\n", s.Coverage.EventsMapped, s.Coverage.EventsTotal)
	if len(s.Coverage.UnmappedByType) == 0 {
		sb.WriteString("No unmapped event types.\n\n")
	} else {
		sb.WriteString("Event types without a facts normalizer yet:\n\n")
		sb.WriteString("| Event type | Count |\n|---|---|\n")
		for _, k := range sortedKeys(s.Coverage.UnmappedByType) {
			fmt.Fprintf(&sb, "| %s | %d |\n", k, s.Coverage.UnmappedByType[k])
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// countBy tallies items by a string key extracted from each.
func countBy[T any](items []T, key func(T) string) map[string]int {
	m := make(map[string]int)
	for _, it := range items {
		m[key(it)]++
	}
	return m
}

// writeCountTable writes a two-column count table in sorted key order.
func writeCountTable(sb *strings.Builder, header string, counts map[string]int) {
	if len(counts) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	fmt.Fprintf(sb, "| %s | Count |\n|---|---|\n", header)
	for _, k := range sortedKeys(counts) {
		fmt.Fprintf(sb, "| %s | %d |\n", k, counts[k])
	}
	sb.WriteString("\n")
}

// sortedKeys returns the map keys in ascending order.
func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
