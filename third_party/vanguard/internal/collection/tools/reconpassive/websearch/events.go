package websearch

import (
	"log/slog"
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "websearch"

// SearchStarted is emitted when a dork search begins for a domain.
type SearchStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (SearchStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchStarted) EventName() string { return "websearch: search started" }

// EventLevel returns the log severity.
func (SearchStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// QuerySucceeded is emitted when one dork query returns, with its result
// accounting. Results is the upstream row count; Accepted and Rejected partition
// it. Only accepted rows may become target assets.
type QuerySucceeded struct {
	Domain   string
	Dork     string
	Category string
	// Results is the number of organic rows the search engine returned.
	Results int
	// Accepted is the number of rows owned by the requested root.
	Accepted int
	// Rejected is the number of rows dropped because the root does not own them
	// or because the per-query result cap was already reached.
	Rejected int
}

// ToolName returns the tool identifier.
func (QuerySucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QuerySucceeded) EventName() string { return "websearch: query succeeded" }

// EventLevel returns the log severity.
func (QuerySucceeded) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QuerySucceeded) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("dork", e.Dork),
		slog.String("category", e.Category),
		slog.Int("results", e.Results),
		slog.Int("accepted", e.Accepted),
		slog.Int("rejected", e.Rejected),
	}
}

// ResultsRejected is emitted once per query that returned rows the requested
// root does not own, typically because the search engine ignored or
// reinterpreted the site: operator. It is a diagnostic about upstream search
// quality, not about Vanguard's collection: the engine answered and the response
// parsed, so the event carries no health problem and the query still counts as
// succeeded. Only bounded counts over a closed reason vocabulary are recorded;
// rejected URLs and snippets are never retained, because they are not evidence
// about the target.
type ResultsRejected struct {
	Domain   string
	Dork     string
	Category string
	// Results is the number of organic rows the search engine returned.
	Results int
	// Accepted is the number of rows owned by the requested root.
	Accepted int
	// Rejected is Results minus Accepted.
	Rejected int
	// Reasons counts the rejections by reason: invalid_root, invalid_url,
	// empty_host, ip_literal, unrelated_host, or result_cap.
	Reasons map[string]int
}

// ToolName returns the tool identifier.
func (ResultsRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ResultsRejected) EventName() string { return "websearch: results rejected" }

// EventLevel returns the log severity.
func (ResultsRejected) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ResultsRejected) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("dork", e.Dork),
		slog.String("category", e.Category),
		slog.Int("results", e.Results),
		slog.Int("accepted", e.Accepted),
		slog.Int("rejected", e.Rejected),
	}
	for _, reason := range sortedReasons(e.Reasons) {
		attrs = append(attrs, slog.Int(reason, e.Reasons[reason]))
	}
	return attrs
}

// sortedReasons returns the reason keys in deterministic order so log output and
// captures do not vary between runs.
func sortedReasons(reasons map[string]int) []string {
	out := make([]string, 0, len(reasons))
	for r := range reasons {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// QueryFailed is emitted when a single dork query errors. The search continues
// with the remaining queries, so a partial result is still returned.
type QueryFailed struct {
	Domain   string
	Dork     string
	Category string
	Err      error
}

// ToolName returns the tool identifier.
func (QueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryFailed) EventName() string { return "websearch: query failed" }

// EventLevel returns the log severity.
func (QueryFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("dork", e.Dork),
		slog.String("category", e.Category),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a failed dork query.
func (e QueryFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "websearch.query_failed", Component: e.Category, Target: e.Domain,
	}, true
}

// AssetFound is emitted for each unique URL discovered, carrying its host and the
// dork category that surfaced it so coverage and exposure can be compared.
type AssetFound struct {
	Engine   string
	Domain   string
	URL      string
	Host     string
	Category string
	Snippet  string
}

// ToolName returns the tool identifier.
func (AssetFound) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (AssetFound) EventName() string { return "websearch: asset found" }

// EventLevel returns the log severity.
func (AssetFound) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e AssetFound) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("engine", e.Engine),
		slog.String("domain", e.Domain),
		slog.String("url", e.URL),
		slog.String("host", e.Host),
		slog.String("category", e.Category),
		slog.String("snippet", e.Snippet),
	}
}

// RateLimited is emitted when a search engine returns HTTP 429 or rate-limit status.
type RateLimited struct {
	Engine   string
	Domain   string
	Dork     string
	Category string
	Attempt  int
	Err      error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "websearch: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("engine", e.Engine),
		slog.String("domain", e.Domain),
		slog.String("dork", e.Dork),
		slog.String("category", e.Category),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a search request lost to rate limiting.
func (e RateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "websearch.rate_limited", Component: e.Engine, Target: e.Domain,
	}, true
}

// SearchEngineBlocked is emitted when response bodies indicate anti-bot or CAPTCHA challenges.
type SearchEngineBlocked struct {
	Engine   string
	Domain   string
	Dork     string
	Category string
	Reason   string
	Err      error
}

// ToolName returns the tool identifier.
func (SearchEngineBlocked) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchEngineBlocked) EventName() string { return "websearch: search engine blocked" }

// EventLevel returns the log severity.
func (SearchEngineBlocked) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchEngineBlocked) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("engine", e.Engine),
		slog.String("domain", e.Domain),
		slog.String("dork", e.Dork),
		slog.String("category", e.Category),
		slog.String("reason", e.Reason),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a search request blocked by the upstream engine.
func (e SearchEngineBlocked) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "websearch.engine_blocked", Component: e.Engine, Target: e.Domain,
	}, true
}

// SERPParseError is emitted when search engine SERP result extraction fails due to layout drift.
type SERPParseError struct {
	Engine   string
	Domain   string
	Dork     string
	Category string
	Snippet  string
	Err      error
}

// ToolName returns the tool identifier.
func (SERPParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SERPParseError) EventName() string { return "websearch: serp parse error" }

// EventLevel returns the log severity.
func (SERPParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SERPParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("engine", e.Engine),
		slog.String("domain", e.Domain),
		slog.String("dork", e.Dork),
		slog.String("category", e.Category),
		slog.String("snippet", e.Snippet),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a search response that could not be parsed.
func (e SERPParseError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "websearch.response_invalid", Component: e.Engine, Target: e.Domain,
	}, true
}

// SearchCompleted is emitted when the dork search finishes, summarising the asset
// count and the per-query outcomes.
type SearchCompleted struct {
	Domain string
	// Assets is the deduplicated number of accepted assets across all queries.
	Assets int
	// Results is the upstream row count summed over the succeeded queries.
	Results int
	// Accepted and Rejected partition Results. Accepted counts rows before
	// cross-query deduplication, so it is greater than or equal to Assets.
	Accepted     int
	Rejected     int
	TotalQueries int
	Succeeded    int
	Failed       int
	Truncated    bool
	Degraded     bool
}

// ToolName returns the tool identifier.
func (SearchCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCompleted) EventName() string { return "websearch: search completed" }

// EventLevel returns the log severity.
func (SearchCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("assets", e.Assets),
		slog.Int("results", e.Results),
		slog.Int("accepted", e.Accepted),
		slog.Int("rejected", e.Rejected),
		slog.Int("queries", e.TotalQueries),
		slog.Int("succeeded", e.Succeeded),
		slog.Int("failed", e.Failed),
		slog.Bool("truncated", e.Truncated),
		slog.Bool("degraded", e.Degraded),
	}
}

var (
	_ tooleventlog.HealthEvent = QueryFailed{}
	_ tooleventlog.HealthEvent = RateLimited{}
	_ tooleventlog.HealthEvent = SearchEngineBlocked{}
	_ tooleventlog.HealthEvent = SERPParseError{}
)
