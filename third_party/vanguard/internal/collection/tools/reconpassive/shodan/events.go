package shodan

import (
	"log/slog"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "shodan"

// SearchStarted is emitted when a Shodan search begins for a domain.
type SearchStarted struct {
	Domain string
	Query  string
}

// ToolName returns the tool identifier.
func (SearchStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchStarted) EventName() string { return "shodan: search started" }

// EventLevel returns the log severity.
func (SearchStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
	}
}

// HostDiscovered is emitted for each unique host Shodan indexed for the domain,
// summarising its open-port and vulnerability counts.
type HostDiscovered struct {
	Domain string
	IP     string
	// Ports is the number of distinct port numbers observed on the host.
	Ports int
	Vulns int
	// Services is the number of observed services. It exceeds Ports when one port
	// was observed on both transports, which is two services rather than one.
	Services int
	Sources  []string
}

// ToolName returns the tool identifier.
func (HostDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HostDiscovered) EventName() string { return "shodan: host discovered" }

// EventLevel returns the log severity.
func (HostDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HostDiscovered) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("ip", e.IP),
		slog.Int("ports", e.Ports),
		slog.Int("vulns", e.Vulns),
	}
	if e.Services > 0 {
		attrs = append(attrs, slog.Int("services", e.Services))
	}
	if len(e.Sources) > 0 {
		attrs = append(attrs, slog.String("sources", strings.Join(e.Sources, ", ")))
	}
	return attrs
}

// RateLimited is emitted when a Shodan API call fails due to rate limiting (HTTP 429) or quota exhaustion.
type RateLimited struct {
	Domain  string
	Query   string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "shodan: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a search lost to rate limiting.
func (e RateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "shodan.rate_limited", Target: e.Domain}, true
}

// PaidPlanRequired is emitted when a Shodan API call returns HTTP 401/403 API restriction walls.
type PaidPlanRequired struct {
	Domain     string
	Query      string
	StatusCode int
}

// ToolName returns the tool identifier.
func (PaidPlanRequired) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PaidPlanRequired) EventName() string { return "shodan: paid plan required" }

// EventLevel returns the log severity.
func (PaidPlanRequired) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PaidPlanRequired) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
		slog.Int("status_code", e.StatusCode),
	}
}

// CollectionHealth reports a search blocked by account entitlement.
func (e PaidPlanRequired) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "shodan.access_denied", Target: e.Domain}, true
}

// JSONParseError is emitted when Shodan API response decoding fails.
type JSONParseError struct {
	Domain  string
	Query   string
	Snippet string
	Err     error
}

// ToolName returns the tool identifier.
func (JSONParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (JSONParseError) EventName() string { return "shodan: json parse error" }

// EventLevel returns the log severity.
func (JSONParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JSONParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
		slog.String("snippet", e.Snippet),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a provider response that could not be decoded.
func (e JSONParseError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "shodan.response_invalid", Target: e.Domain}, true
}

// SearchCompleted is emitted when the search finishes, summarising the host count and query statistics.
type SearchCompleted struct {
	Domain            string
	Hosts             int
	Truncated         bool
	TotalMatches      int
	TotalQueries      int
	SuccessfulQueries int
	FailedQueries     int
	Degraded          bool
}

// ToolName returns the tool identifier.
func (SearchCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCompleted) EventName() string { return "shodan: search completed" }

// EventLevel returns the log severity.
func (SearchCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("hosts", e.Hosts),
		slog.Bool("truncated", e.Truncated),
		slog.Int("total_matches", e.TotalMatches),
		slog.Int("queries", e.TotalQueries),
		slog.Int("succeeded", e.SuccessfulQueries),
		slog.Int("failed", e.FailedQueries),
		slog.Bool("degraded", e.Degraded),
	}
}

// SearchFailed is emitted when the Shodan API call errors (low-level connection or network error).
type SearchFailed struct {
	Domain string
	Query  string
	Err    error
}

// ToolName returns the tool identifier.
func (SearchFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchFailed) EventName() string { return "shodan: search failed" }

// EventLevel returns the log severity.
func (SearchFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a failed provider search.
func (e SearchFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "shodan.search_failed", Target: e.Domain}, true
}

var (
	_ tooleventlog.HealthEvent = RateLimited{}
	_ tooleventlog.HealthEvent = PaidPlanRequired{}
	_ tooleventlog.HealthEvent = JSONParseError{}
	_ tooleventlog.HealthEvent = SearchFailed{}
)
