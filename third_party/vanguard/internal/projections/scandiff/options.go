package scandiff

import "github.com/velgard-sk/vanguard/internal/collection/events"

// Options scopes which events the event-level diff covers. Lifecycle events
// (ScanStarted/ScanCompleted) almost always match and add noise, and issues
// (IssueObserved) are run-specific operational errors, so a caller can restrict the
// comparison to the high-signal content.
type Options struct {
	// IncludeCategories limits the event-level diff to these EventMeta.Category
	// values. Empty means all categories (no filtering).
	IncludeCategories []events.Category
	// IncludeMatched keeps the Matched entries in the report's Events list. It
	// defaults off: a real scan matches the vast majority of its events, so listing
	// them bloats the JSON for no signal. Matched always lives as a count in the
	// Summary and per type in ByType; turn this on for a full audit or debugging.
	IncludeMatched bool
}

// DefaultOptions is the recommended high-signal scope: discovery and finding
// content. Lifecycle events are bucketed out of the
// event list, and issues are summarized as counts elsewhere (step 4) rather than
// diffed as content, so neither adds noise to the per-event verdicts here.
//
// The zero Options value diffs every category, so this scope is an opt-in default,
// not a hard policy. The recorded rationale lives in doc.go.
func DefaultOptions() Options {
	return Options{IncludeCategories: []events.Category{
		events.CategoryDiscovery,
		events.CategoryFinding,
	}}
}

// includes reports whether an event's category is in scope. An empty
// IncludeCategories admits every category.
func (o Options) includes(c events.Category) bool {
	if len(o.IncludeCategories) == 0 {
		return true
	}
	for _, want := range o.IncludeCategories {
		if want == c {
			return true
		}
	}
	return false
}
