package censys

import (
	"log/slog"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// SearchStarted is emitted when a Censys host search begins for a domain.
type SearchStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (SearchStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchStarted) EventName() string { return "censys: search started" }

// EventLevel returns the log severity.
func (SearchStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// SearchQuerySucceeded is emitted when one of the per-domain CenQL host queries returns.
type SearchQuerySucceeded struct {
	Domain string
	Label  string
	Query  string
	Hits   int
}

// ToolName returns the tool identifier.
func (SearchQuerySucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchQuerySucceeded) EventName() string { return "censys: search query succeeded" }

// EventLevel returns the log severity.
func (SearchQuerySucceeded) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchQuerySucceeded) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
		slog.String("query", e.Query),
		slog.Int("hits", e.Hits),
	}
}

// SearchQueryFailed is emitted when a single CenQL host query errors. The search
// continues with the remaining queries, so a partial result is still returned.
type SearchQueryFailed struct {
	Domain string
	Label  string
	Query  string
	Err    error
}

// ToolName returns the tool identifier.
func (SearchQueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchQueryFailed) EventName() string { return "censys: search query failed" }

// EventLevel returns the log severity.
func (SearchQueryFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchQueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
		slog.String("query", e.Query),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a failed host query.
func (e SearchQueryFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.host_query_failed", Component: e.Label, Target: e.Domain}, true
}

// SearchPaidPlanRequired is emitted when a host search query returns 403, which on
// the free tier means that query type requires a paid plan. The search still tries
// the other query type; Client.Search only reports the tool unavailable once every
// query type attempted in the call has come back 403.
type SearchPaidPlanRequired struct {
	Domain string
	Label  string
}

// ToolName returns the tool identifier.
func (SearchPaidPlanRequired) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchPaidPlanRequired) EventName() string { return "censys: search paid plan required" }

// EventLevel returns the log severity.
func (SearchPaidPlanRequired) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchPaidPlanRequired) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
	}
}

// CollectionHealth reports a host query blocked by account entitlement.
func (e SearchPaidPlanRequired) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.host_access_denied", Component: e.Label, Target: e.Domain}, true
}

// SearchInsufficientBalance is emitted when a host search query fails because the Censys
// account has insufficient balance (an empty query wallet, returned as HTTP 422). It is an
// account-level wall, so Client.Search stops immediately and reports the tool unavailable
// for the rest of the scan rather than retrying the depleted wallet per query and domain.
type SearchInsufficientBalance struct {
	Domain string
	Label  string
}

// ToolName returns the tool identifier.
func (SearchInsufficientBalance) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchInsufficientBalance) EventName() string { return "censys: search insufficient balance" }

// EventLevel returns the log severity.
func (SearchInsufficientBalance) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchInsufficientBalance) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
	}
}

// CollectionHealth reports a host query blocked by an exhausted account balance.
func (e SearchInsufficientBalance) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.host_balance_exhausted", Component: e.Label, Target: e.Domain}, true
}

// SearchRateLimited is emitted when a host search query fails because Censys
// returned HTTP 429 (its concurrent-request / rate limit) and the SDK's retries
// were exhausted. It is a distinct failure event from SearchQueryFailed so the
// operational rollup counts it as a rate-limit hit rather than a generic error.
type SearchRateLimited struct {
	Domain string
	Label  string
	Query  string
	Err    error
}

// ToolName returns the tool identifier.
func (SearchRateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchRateLimited) EventName() string { return "censys: search rate limited" }

// EventLevel returns the log severity.
func (SearchRateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchRateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
		slog.String("query", e.Query),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a host query lost to rate limiting.
func (e SearchRateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.host_rate_limited", Component: e.Label, Target: e.Domain}, true
}

// SearchHostDiscovered is emitted for each unique host found for the domain,
// carrying the service count and the queries that matched it so tool coverage can
// be compared across data sources.
type SearchHostDiscovered struct {
	Domain   string
	IP       string
	Services int
	Sources  []string
}

// ToolName returns the tool identifier.
func (SearchHostDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchHostDiscovered) EventName() string { return "censys: search host discovered" }

// EventLevel returns the log severity.
func (SearchHostDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchHostDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("ip", e.IP),
		slog.Int("services", e.Services),
		slog.String("sources", strings.Join(e.Sources, ", ")),
	}
}

// SearchCacheHit is emitted when a host search in ModeEmbeddedCacheOnly is answered
// from the embedded fixture. It makes the lookup decision visible in the tool stream
// even though no query ran.
type SearchCacheHit struct {
	Domain    string
	Hosts     int
	Truncated bool
}

// retrievalAttr renders the retrieval_source attribute, the shared key that tells an
// operator whether a tool event's data came from the provider or the compiled-in
// fixture.
func retrievalAttr(source string) slog.Attr { return slog.String("retrieval_source", source) }

// ToolName returns the tool identifier.
func (SearchCacheHit) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCacheHit) EventName() string { return "censys: search cache hit" }

// EventLevel returns the log severity.
func (SearchCacheHit) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCacheHit) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("hosts", e.Hosts),
		slog.Bool("truncated", e.Truncated),
		retrievalAttr(retrievalCacheEmbedded),
	}
}

// SearchCacheMiss is emitted when a host search in ModeEmbeddedCacheOnly finds no
// entry for the domain. It is the visible record that the scan produced no Censys
// host observation for that domain: the mode never falls through to the API, and no
// empty result is invented, so without this event the absence would be silent.
type SearchCacheMiss struct {
	Domain string
}

// ToolName returns the tool identifier.
func (SearchCacheMiss) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCacheMiss) EventName() string { return "censys: search cache miss" }

// EventLevel returns the log severity.
func (SearchCacheMiss) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCacheMiss) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), retrievalAttr(retrievalCacheEmbedded)}
}

// SearchCompleted is emitted when the host search finishes, summarising the host
// count and the per-query outcomes.
type SearchCompleted struct {
	Domain       string
	Hosts        int
	Truncated    bool
	TotalQueries int
	Succeeded    int
	Failed       int
	// RetrievalSource is where the search's data came from: "service" for an API
	// answer (including a failed attempt at one) or "cache_embedded" for the
	// compiled-in fixture, so the terminal event alone states the provenance.
	RetrievalSource string
}

// ToolName returns the tool identifier.
func (SearchCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCompleted) EventName() string { return "censys: search completed" }

// EventLevel returns the log severity.
func (SearchCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("hosts", e.Hosts),
		slog.Bool("truncated", e.Truncated),
		slog.Int("queries", e.TotalQueries),
		slog.Int("succeeded", e.Succeeded),
		slog.Int("failed", e.Failed),
		retrievalAttr(e.RetrievalSource),
	}
}

var (
	_ tooleventlog.HealthEvent = SearchQueryFailed{}
	_ tooleventlog.HealthEvent = SearchPaidPlanRequired{}
	_ tooleventlog.HealthEvent = SearchInsufficientBalance{}
	_ tooleventlog.HealthEvent = SearchRateLimited{}
)
