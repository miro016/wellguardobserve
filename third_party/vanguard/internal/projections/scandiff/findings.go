package scandiff

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Findings are the highest-value entity for the "what changed" question, so they get
// a dedicated, severity-aware breakdown derived from the finding classification: the
// new findings (in candidate B only), the resolved ones (in baseline A only), and
// the ones whose payload changed (a severity escalation or new evidence). The
// new/resolved counts roll up by severity for the one-line summary an operator wants
// first ("adds 1 critical and 2 high, resolves 1 high").

// FindingRef identifies a finding plus the human-facing detail a summary needs.
type FindingRef struct {
	Rule      string `json:"rule"`
	AssetKind string `json:"assetKind"`
	AssetID   string `json:"assetID"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
}

// FindingsDelta is the severity-aware finding comparison between baseline A and
// candidate B. New and Resolved come from the Unexpected and Missing FindingRaised
// identities; Changed from the changed ones. The two by-severity maps roll up New
// and Resolved for the summary line.
type FindingsDelta struct {
	New      []FindingRef `json:"new,omitempty"`
	Resolved []FindingRef `json:"resolved,omitempty"`
	Changed  []FindingRef `json:"changed,omitempty"`

	NewBySeverity      map[string]int `json:"newBySeverity,omitempty"`
	ResolvedBySeverity map[string]int `json:"resolvedBySeverity,omitempty"`
}

// Findings builds the severity-aware finding delta. It classifies only the
// FindingRaised events (scoping to the finding category), then resolves each
// classified identity back to its FindingRef using the highest-severity occurrence
// on the side that carries it (B for new/changed, A for resolved). The result is
// deterministic: lists are sorted by (severity desc, rule, assetID).
func Findings(a, b []events.DomainEvent) FindingsDelta {
	refA := findingRefs(a)
	refB := findingRefs(b)

	d := Differ{Opts: Options{IncludeCategories: []events.Category{events.CategoryFinding}}}
	delta := FindingsDelta{
		NewBySeverity:      map[string]int{},
		ResolvedBySeverity: map[string]int{},
	}
	for _, diff := range d.Classify(a, b) {
		if diff.Type != typeFindingRaised {
			continue
		}
		switch diff.Class {
		case Matched:
			// Unchanged finding: not part of the delta.
		case Unexpected:
			if ref, ok := refB[diff.Identity]; ok {
				delta.New = append(delta.New, ref)
				delta.NewBySeverity[ref.Severity]++
			}
		case Missing:
			if ref, ok := refA[diff.Identity]; ok {
				delta.Resolved = append(delta.Resolved, ref)
				delta.ResolvedBySeverity[ref.Severity]++
			}
		case Changed:
			if ref, ok := refB[diff.Identity]; ok {
				delta.Changed = append(delta.Changed, ref)
			}
		}
	}

	sortFindingRefs(delta.New)
	sortFindingRefs(delta.Resolved)
	sortFindingRefs(delta.Changed)
	if len(delta.NewBySeverity) == 0 {
		delta.NewBySeverity = nil
	}
	if len(delta.ResolvedBySeverity) == 0 {
		delta.ResolvedBySeverity = nil
	}
	return delta
}

// findingRefs maps each finding identity in a stream to the FindingRef of its
// highest-severity occurrence, so a multi-source finding reports its worst severity.
func findingRefs(evts []events.DomainEvent) map[string]FindingRef {
	out := map[string]FindingRef{}
	rank := map[string]int{}
	for _, evt := range evts {
		e, ok := events.AsValue(evt).(events.FindingRaised)
		if !ok {
			continue
		}
		id := Identity(e)
		sev := int(e.Meta().Severity)
		if cur, seen := rank[id]; seen && sev <= cur {
			continue
		}
		rank[id] = sev
		out[id] = FindingRef{
			Rule:      e.Rule,
			AssetKind: e.AssetKind,
			AssetID:   e.AssetID,
			Title:     e.Title,
			Severity:  e.Meta().Severity.String(),
		}
	}
	return out
}

// severityRank orders the severity labels from most to least severe for sorting.
var severityRank = map[string]int{
	events.SeverityCritical.String(): 4,
	events.SeverityHigh.String():     3,
	events.SeverityMedium.String():   2,
	events.SeverityLow.String():      1,
	events.SeverityInfo.String():     0,
}

// sortFindingRefs orders refs by severity descending, then rule, then assetID, so
// the lists are stable and lead with the most severe finding.
func sortFindingRefs(refs []FindingRef) {
	sort.Slice(refs, func(i, j int) bool {
		if severityRank[refs[i].Severity] != severityRank[refs[j].Severity] {
			return severityRank[refs[i].Severity] > severityRank[refs[j].Severity]
		}
		if refs[i].Rule != refs[j].Rule {
			return refs[i].Rule < refs[j].Rule
		}
		return refs[i].AssetID < refs[j].AssetID
	})
}
