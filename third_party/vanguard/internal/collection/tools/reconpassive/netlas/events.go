package netlas

import (
	"log/slog"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "netlas"

// SearchStarted is emitted when a Netlas search begins for a domain.
type SearchStarted struct {
	Domain string
	Query  string
}

// ToolName returns the tool identifier.
func (SearchStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchStarted) EventName() string { return "netlas: search started" }

// EventLevel returns the log severity.
func (SearchStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
	}
}

// HostDiscovered is emitted for each unique host Netlas indexed for the domain,
// summarising its open-port and vulnerability counts.
type HostDiscovered struct {
	Domain string
	IP     string
	// Ports is the number of distinct port numbers observed on the host.
	Ports int
	Vulns int
	// Services is the number of observed services. It exceeds Ports when one port
	// carried several distinct service observations.
	Services int
	Sources  []string
}

// ToolName returns the tool identifier.
func (HostDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HostDiscovered) EventName() string { return "netlas: host discovered" }

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

// RateLimited is emitted when a Netlas API call fails due to rate limiting (HTTP 429).
type RateLimited struct {
	Domain  string
	Query   string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "netlas: rate limited" }

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
	return tooleventlog.HealthProblem{Code: "netlas.rate_limited", Target: e.Domain}, true
}

// PaidPlanRequired is emitted when a Netlas API call returns HTTP 401/403 API key or query tier restriction walls.
type PaidPlanRequired struct {
	Domain     string
	Query      string
	StatusCode int
}

// ToolName returns the tool identifier.
func (PaidPlanRequired) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PaidPlanRequired) EventName() string { return "netlas: paid plan required" }

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
	return tooleventlog.HealthProblem{Code: "netlas.access_denied", Target: e.Domain}, true
}

// JSONParseError is emitted when a result document cannot be decoded into the expected schema.
type JSONParseError struct {
	Domain     string
	Query      string
	Snippet    string
	RawSnippet string
	BodyBytes  int
	Err        error
}

// ToolName returns the tool identifier.
func (JSONParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (JSONParseError) EventName() string { return "netlas: json parse error" }

// EventLevel returns the log severity.
func (JSONParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JSONParseError) EventAttrs() []slog.Attr {
	snippet := e.Snippet
	if snippet == "" {
		snippet = e.RawSnippet
	}
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("query", e.Query),
		slog.String("snippet", snippet),
		slog.Int("body_bytes", e.BodyBytes),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a provider result that could not be decoded.
func (e JSONParseError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "netlas.response_invalid", Target: e.Domain}, true
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
func (SearchCompleted) EventName() string { return "netlas: search completed" }

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

// SearchFailed is emitted when a Netlas API call errors (low-level connection or network error).
type SearchFailed struct {
	Domain string
	Query  string
	Err    error
}

// ToolName returns the tool identifier.
func (SearchFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchFailed) EventName() string { return "netlas: search failed" }

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
	return tooleventlog.HealthProblem{Code: "netlas.search_failed", Target: e.Domain}, true
}

var (
	_ tooleventlog.HealthEvent = RateLimited{}
	_ tooleventlog.HealthEvent = PaidPlanRequired{}
	_ tooleventlog.HealthEvent = JSONParseError{}
	_ tooleventlog.HealthEvent = SearchFailed{}
)
