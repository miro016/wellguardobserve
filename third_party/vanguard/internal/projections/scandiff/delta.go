package scandiff

import "sort"

// This file carries the field-level delta for a Changed event: which fields differ
// and, for set-valued fields, which values were added or removed. It builds on the
// Field representation in payload.go, so scalar and set-valued fields share one
// shape. The SourceDelta type lives here too, alongside the content delta it sits
// next to in EventDiff.

// SourceDelta is the per-side set of contributing tools (EventMeta.Source) for one
// identity, recorded when multiple occurrences are collapsed (see the multiplicity
// note in doc.go). A shift in the source set is informational, kept separate from
// Changes so a provenance change never masquerades as a content change.
type SourceDelta struct {
	A []string `json:"a,omitempty"`
	B []string `json:"b,omitempty"`
}

// FieldChange is one differing field of a Changed event. A and B are the
// normalized, sorted value sets on each side; Added is B \ A and Removed is A \ B.
// A scalar field has single-element A/B; a set-valued field (A/AAAA, NS, SANs,
// CPEs, headers, locations) has many.
type FieldChange struct {
	Name    string   `json:"name"`
	A       []string `json:"a,omitempty"`
	B       []string `json:"b,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// computeChanges pairs two collapsed payloads field-by-field and returns the
// non-empty field changes, sorted by Name. Both inputs are already sorted by name
// with sorted, deduplicated values (see collapse), so this is a merge-join: a field
// on one side only is a full add or remove; a field on both sides reports
// Added = B \ A and Removed = A \ B and is dropped when both are empty.
func computeChanges(a, b []Field) []FieldChange {
	changes := make([]FieldChange, 0)
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j >= len(b) || (i < len(a) && a[i].Name < b[j].Name):
			// Field present in A only: a full removal.
			changes = append(changes, FieldChange{Name: a[i].Name, A: a[i].Values, Removed: a[i].Values})
			i++
		case i >= len(a) || (j < len(b) && b[j].Name < a[i].Name):
			// Field present in B only: a full addition.
			changes = append(changes, FieldChange{Name: b[j].Name, B: b[j].Values, Added: b[j].Values})
			j++
		default:
			// Same field on both sides: compare the value sets.
			fc := FieldChange{
				Name:    a[i].Name,
				A:       a[i].Values,
				B:       b[j].Values,
				Added:   setDifference(b[j].Values, a[i].Values),
				Removed: setDifference(a[i].Values, b[j].Values),
			}
			if len(fc.Added) > 0 || len(fc.Removed) > 0 {
				changes = append(changes, fc)
			}
			i++
			j++
		}
	}
	if len(changes) == 0 {
		return nil
	}
	return changes
}

// setDifference returns the sorted elements of a that are not in b.
func setDifference(a, b []string) []string {
	if len(a) == 0 {
		return nil
	}
	in := make(map[string]struct{}, len(b))
	for _, v := range b {
		in[v] = struct{}{}
	}
	out := make([]string, 0)
	for _, v := range a {
		if _, ok := in[v]; !ok {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
