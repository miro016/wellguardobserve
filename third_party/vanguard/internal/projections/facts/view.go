package facts

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/analysis"
)

// View is the read-only input boundary between the facts graph and any projection built
// on top of it. It carries everything a contraction needs - the assets, the observations
// and evidence behind them, the relationships, the finding candidates, the classified
// currentness, the scan identity, the fixed analysis cutoff, and the coverage counts -
// deeply copied and deterministically sorted.
//
// It exists so a downstream projection never has to decode facts.json, reach into the
// graph's mutable indexes, or fold the raw event stream a second time. The dependency
// direction stays one-way:
//
//	events -> facts Graph -> facts View -> attack-surface Graph -> renderers
//
// which keeps one authority for provenance and temporal meaning. A normalizer fix in this
// package reaches every projection on the next replay, and no consumer can drift into its
// own interpretation of what a source claimed or when.
//
// Every slice is a copy, including the maps and slices nested inside assets, observations,
// and relationships, so a consumer that sorts, annotates, or mutates what it is given
// cannot corrupt the graph it came from.
type View struct {
	ScanID string
	// RootTarget is the scan root every scope decision in the graph was made against.
	// A projection that re-derives scope must use this and never guess from the data.
	RootTarget string
	// GeneratedAt is the latest event time in the stream, not a wall clock, so a
	// rebuild from the same events reproduces it exactly.
	GeneratedAt time.Time
	// AnalysisAsOf is the single fixed cutoff every currentness label was evaluated
	// against, with the flag that says the stream never completed.
	AnalysisAsOf events.AnalysisAsOf
	// FreshnessPolicy is the declared window set behind every recent_passive verdict,
	// so a projection reporting freshness measures it the way the artifact did.
	FreshnessPolicy analysis.FreshnessPolicy
	// DataView states that nothing was filtered out: this is the complete record with
	// classification applied, not a current-only surface.
	DataView          string
	Assets            []Asset
	Observations      []Observation
	Evidence          []Evidence
	Relationships     []Relationship
	FindingCandidates []FindingCandidate
	Issues            []Issue
	Coverage          Coverage
	// Surface is the exclusive currentness classification over exactly these assets
	// and relationships. A projection reuses it instead of reclassifying, so the two
	// artifacts cannot disagree about how current a fact is.
	Surface ClassifiedSurface
}

// View returns the deeply copied, deterministically ordered read-only view of the folded
// graph. It renders the same snapshot the JSON artifact is built from, so a projection and
// the facts file always describe the same graph.
func (g *Graph) View() View {
	s := g.snap()
	return View{
		ScanID:            s.ScanID,
		RootTarget:        g.rootTarget,
		GeneratedAt:       s.GeneratedAt,
		AnalysisAsOf:      g.AnalysisAsOf(),
		FreshnessPolicy:   g.FreshnessPolicy(),
		DataView:          s.DataView,
		Assets:            copyAssets(s.Assets),
		Observations:      copyObservations(s.Observations),
		Evidence:          copySlice(s.Evidence),
		Relationships:     copyRelationships(s.Relationships),
		FindingCandidates: copyFindings(s.FindingCandidates),
		Issues:            copySlice(s.Issues),
		Coverage:          copyCoverage(s.Coverage),
		Surface:           copySurface(s.Surface),
	}
}

// AssetsByType returns the view's assets of one type, in the view's order. It is the
// common first step of a contraction rule and saves every caller writing the same filter.
func (v View) AssetsByType(t AssetType) []Asset {
	out := make([]Asset, 0, 8)
	for _, a := range v.Assets {
		if a.Type == t {
			out = append(out, a)
		}
	}
	return out
}

// ObservationsByAsset indexes the view's observations by the asset key they were recorded
// against, preserving the view's order within each key.
func (v View) ObservationsByAsset() map[string][]Observation {
	out := make(map[string][]Observation, len(v.Assets))
	for _, o := range v.Observations {
		out[o.AssetKey] = append(out[o.AssetKey], o)
	}
	return out
}

// EvidenceByID indexes the view's evidence so a projection can resolve the proof behind
// an edge without scanning the slice.
func (v View) EvidenceByID() map[string]Evidence {
	out := make(map[string]Evidence, len(v.Evidence))
	for _, e := range v.Evidence {
		out[e.ID] = e
	}
	return out
}

// ClassifiedAssets indexes the currentness classification by typed asset identity.
func (v View) ClassifiedAssets() map[string]ClassifiedAsset {
	out := make(map[string]ClassifiedAsset, len(v.Surface.Assets))
	for _, c := range v.Surface.Assets {
		out[string(c.Type)+"\x00"+c.Key] = c
	}
	return out
}

// ClassifiedRelationships indexes the currentness classification by edge identity.
func (v View) ClassifiedRelationships() map[string]ClassifiedRelationship {
	out := make(map[string]ClassifiedRelationship, len(v.Surface.Relationships))
	for _, c := range v.Surface.Relationships {
		out[string(c.Type)+"\x00"+c.From+"\x00"+c.To] = c
	}
	return out
}

// copyAssets deep-copies the asset slice: attributes, sources, assertions, and the
// interval slice inside the temporal summary.
func copyAssets(in []Asset) []Asset {
	out := make([]Asset, len(in))
	for i, a := range in {
		a.Attributes = copyAttributes(a.Attributes)
		a.Sources = copySlice(a.Sources)
		a.Assertions = copySlice(a.Assertions)
		a.TemporalSummary = copySummary(a.TemporalSummary)
		out[i] = a
	}
	return out
}

// copyRelationships deep-copies the relationship slice under the same rules as assets.
func copyRelationships(in []Relationship) []Relationship {
	out := make([]Relationship, len(in))
	for i, r := range in {
		r.Metadata = copyAttributes(r.Metadata)
		r.Assertions = copySlice(r.Assertions)
		r.TemporalSummary = copySummary(r.TemporalSummary)
		out[i] = r
	}
	return out
}

// copyObservations deep-copies the observation slice and its metadata maps.
func copyObservations(in []Observation) []Observation {
	out := make([]Observation, len(in))
	for i, o := range in {
		o.Metadata = copyAttributes(o.Metadata)
		out[i] = o
	}
	return out
}

// copyFindings deep-copies the candidate slice and its reference lists.
func copyFindings(in []FindingCandidate) []FindingCandidate {
	out := make([]FindingCandidate, len(in))
	for i, c := range in {
		c.EvidenceIDs = copySlice(c.EvidenceIDs)
		c.References = copySlice(c.References)
		out[i] = c
	}
	return out
}

// copyCoverage copies the coverage counts, including the per-type map.
func copyCoverage(in Coverage) Coverage {
	out := in
	if in.UnmappedByType != nil {
		out.UnmappedByType = make(map[string]int, len(in.UnmappedByType))
		for k, v := range in.UnmappedByType {
			out.UnmappedByType[k] = v
		}
	}
	return out
}

// copySummary copies the temporal summary's only reference field.
func copySummary(in TemporalSummary) TemporalSummary {
	in.ValidIntervals = copySlice(in.ValidIntervals)
	return in
}

// copySurface deep-copies the classification, including every badge and observation list.
func copySurface(in ClassifiedSurface) ClassifiedSurface {
	out := in
	out.ByClass = copySlice(in.ByClass)
	out.ByType = make([]TypeBreakdown, len(in.ByType))
	for i, b := range in.ByType {
		b.ByClass = copySlice(b.ByClass)
		out.ByType[i] = b
	}
	out.Assets = make([]ClassifiedAsset, len(in.Assets))
	for i, a := range in.Assets {
		a.Badges = copySlice(a.Badges)
		a.ObservationIDs = copySlice(a.ObservationIDs)
		a.Sources = copySlice(a.Sources)
		out.Assets[i] = a
	}
	out.Relationships = make([]ClassifiedRelationship, len(in.Relationships))
	for i, r := range in.Relationships {
		r.Badges = copySlice(r.Badges)
		out.Relationships[i] = r
	}
	return out
}

// copySlice copies a slice while preserving the difference between a nil slice and an
// empty one. The two encode the same JSON, but a consumer comparing a view against the
// graph it came from would otherwise see a difference the copy invented.
func copySlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	return append(make([]T, 0, len(in)), in...)
}

// copyAttributes deep-copies an attribute or metadata map one level down, which is as
// deep as the normalizers ever nest: scalars, string sets, and the occasional []any.
func copyAttributes(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch tv := v.(type) {
		case []string:
			out[k] = copySlice(tv)
		case []any:
			out[k] = copySlice(tv)
		case map[string]any:
			out[k] = copyAttributes(tv)
		default:
			out[k] = v
		}
	}
	return out
}
