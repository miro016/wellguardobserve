package scandiff

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Class is the verdict for one event identity across the two scans.
type Class string

// typeFindingRaised is the TypeName of FindingRaised, used as a registry key and to
// scope the findings delta to finding events.
const typeFindingRaised = "FindingRaised"

const (
	// Matched means present in both A and B with equal semantic payload. No change.
	Matched Class = "matched"
	// Changed means present in both A and B, but the semantic payload differs.
	Changed Class = "changed"
	// Missing means present in baseline A, absent in candidate B (the fact disappeared).
	Missing Class = "missing"
	// Unexpected means present in candidate B, absent in baseline A (the fact is new).
	Unexpected Class = "unexpected"
)

// EventDiff is the per-identity verdict. Type and Identity name the fact; Class is
// the verdict; Sources records the contributing tools on each side (informational,
// kept separate so a provenance shift never reads as a content change). Changes
// carries the field-level delta for a Changed verdict (see delta.go). The
// SourceDelta and FieldChange types live in delta.go.
type EventDiff struct {
	Type     string        `json:"type"`
	Identity string        `json:"identity"`
	Class    Class         `json:"class"`
	Sources  SourceDelta   `json:"sources,omitempty"`
	Changes  []FieldChange `json:"changes,omitempty"`
}

// Differ classifies two event streams, carrying the scope options. The zero Differ
// diffs every category; Differ{Opts: DefaultOptions()} restricts to the high-signal
// discovery and finding content.
type Differ struct {
	Opts Options
}

// Classify folds the two streams into per-identity verdicts. It is pure and
// deterministic: it indexes each side by semantic identity, collapses the multiple
// occurrences of an identity to one normalized payload plus a source set, compares
// the payloads, and returns the verdicts sorted by (Type, Identity) so the JSON and
// Markdown are byte-stable. The zero Differ diffs every category; use
// DefaultOptions() (or an explicit Options) to scope the comparison.
func (d Differ) Classify(a, b []events.DomainEvent) []EventDiff {
	ai := d.indexByIdentity(a)
	bi := d.indexByIdentity(b)

	out := make([]EventDiff, 0, len(ai)+len(bi))
	for _, id := range sortedUnion(ai, bi) {
		as, aok := ai[id]
		bs, bok := bi[id]

		switch {
		case aok && !bok:
			af, asrc := collapse(as)
			_ = af
			out = append(out, EventDiff{
				Type:     typeNameOf(as),
				Identity: id,
				Class:    Missing,
				Sources:  SourceDelta{A: asrc},
			})
		case !aok && bok:
			bf, bsrc := collapse(bs)
			_ = bf
			out = append(out, EventDiff{
				Type:     typeNameOf(bs),
				Identity: id,
				Class:    Unexpected,
				Sources:  SourceDelta{B: bsrc},
			})
		default:
			af, asrc := collapse(as)
			bf, bsrc := collapse(bs)
			diff := EventDiff{
				Type:     typeNameOf(as),
				Identity: id,
				Class:    Matched,
				Sources:  SourceDelta{A: asrc, B: bsrc},
			}
			if !fieldsEqual(af, bf) {
				diff.Class = Changed
				diff.Changes = computeChanges(af, bf)
			}
			out = append(out, diff)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

// indexByIdentity groups in-scope events by their semantic identity.
func (d Differ) indexByIdentity(evts []events.DomainEvent) map[string][]events.DomainEvent {
	idx := make(map[string][]events.DomainEvent)
	for _, evt := range evts {
		evt = events.AsValue(evt)
		if !d.Opts.includes(evt.Meta().Category) {
			continue
		}
		id := Identity(evt)
		idx[id] = append(idx[id], evt)
	}
	return idx
}

// collapse merges one identity's occurrences into a single comparable payload and
// the set of contributing sources. Field values are unioned across occurrences (a
// name reported by three providers yields one merged payload), and the producing
// tools are collected separately so a provenance shift is visible without polluting
// the content comparison.
func collapse(occ []events.DomainEvent) (fields []Field, sources []string) {
	merged := make(map[string]map[string]struct{})
	order := make([]string, 0)
	srcSet := make(map[string]struct{})

	for _, e := range occ {
		if s := normalizeSource(e.Meta().Source); s != "" {
			srcSet[s] = struct{}{}
		}
		for _, f := range payloadFields(e) {
			vs, ok := merged[f.Name]
			if !ok {
				vs = make(map[string]struct{})
				merged[f.Name] = vs
				order = append(order, f.Name)
			}
			for _, v := range f.Values {
				vs[v] = struct{}{}
			}
		}
	}

	sort.Strings(order)
	fields = make([]Field, 0, len(order))
	for _, name := range order {
		vals := make([]string, 0, len(merged[name]))
		for v := range merged[name] {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		fields = append(fields, Field{Name: name, Values: vals})
	}

	sources = make([]string, 0, len(srcSet))
	for s := range srcSet {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	if len(sources) == 0 {
		sources = nil
	}
	return fields, sources
}

// fieldsEqual reports whether two collapsed payloads are equal: same field names
// and identical value sets. Both inputs are already sorted by name with sorted
// values, so a positional comparison is exact.
func fieldsEqual(a, b []Field) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name {
			return false
		}
		if !stringsEqual(a[i].Values, b[i].Values) {
			return false
		}
	}
	return true
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// typeNameOf returns the concrete event type name of an identity's occurrences.
func typeNameOf(occ []events.DomainEvent) string {
	if len(occ) == 0 {
		return ""
	}
	return events.TypeName(occ[0])
}

// sortedUnion returns the sorted union of the keys of both indexes.
func sortedUnion(a, b map[string][]events.DomainEvent) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	for k := range b {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
