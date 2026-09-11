package certspotter

import (
	"log/slog"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "certspotter"

// QueryStarted is emitted when a certspotter issuance query begins for a domain.
type QueryStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (QueryStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryStarted) EventName() string { return "certspotter: query started" }

// EventLevel returns the log severity.
func (QueryStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// CertDiscovered is emitted when a certificate or batch of SANs is extracted from a Certspotter issuance.
type CertDiscovered struct {
	Domain    string
	SHA256    string
	SANsCount int
}

// ToolName returns the tool identifier.
func (CertDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertDiscovered) EventName() string { return "certspotter: cert discovered" }

// EventLevel returns the log severity.
func (CertDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("sha256", e.SHA256),
		slog.Int("sans_count", e.SANsCount),
	}
}

// RateLimited is emitted when Certspotter API rate limit (HTTP 429) is hit.
type RateLimited struct {
	Domain  string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "certspotter: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports exhausted Certspotter rate limiting.
func (e RateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "certspotter.rate_limited", Target: e.Domain}, true
}

// PaidPlanRequired is emitted when Certspotter API returns HTTP 401 or 403 API restriction wall.
type PaidPlanRequired struct {
	Domain     string
	StatusCode int
}

// ToolName returns the tool identifier.
func (PaidPlanRequired) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PaidPlanRequired) EventName() string { return "certspotter: paid plan required" }

// EventLevel returns the log severity.
func (PaidPlanRequired) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PaidPlanRequired) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("status_code", e.StatusCode),
	}
}

// CollectionHealth reports a provider access wall that prevented the query.
func (e PaidPlanRequired) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "certspotter.access_denied", Target: e.Domain}, true
}

// QueryFailed is emitted when the request cannot be built, sent, or its body read.
type QueryFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (QueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryFailed) EventName() string { return "certspotter: query failed" }

// EventLevel returns the log severity.
func (QueryFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a query transport or request failure.
func (e QueryFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "certspotter.query_failed", Target: e.Domain}, true
}

// HTTPStatusError is emitted when certspotter returns an unhandled non-200 status code.
type HTTPStatusError struct {
	Domain     string
	StatusCode int
	Body       string
	Reason     string
}

// ToolName returns the tool identifier.
func (HTTPStatusError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HTTPStatusError) EventName() string { return "certspotter: http status error" }

// EventLevel returns the log severity.
func (HTTPStatusError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HTTPStatusError) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("status_code", e.StatusCode),
		slog.String("body_snippet", e.Body),
	}
	if e.Reason != "" {
		attrs = append(attrs, slog.String("reason", e.Reason))
	}
	return attrs
}

// CollectionHealth reports an unusable provider HTTP response.
func (e HTTPStatusError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "certspotter.http_status_error", Target: e.Domain}, true
}

// JSONParseError is emitted when the response body is not the expected JSON.
type JSONParseError struct {
	Domain     string
	Err        error
	RawSnippet string
	BodyBytes  int
}

// ToolName returns the tool identifier.
func (JSONParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (JSONParseError) EventName() string { return "certspotter: json parse error" }

// EventLevel returns the log severity.
func (JSONParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JSONParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Any("error", e.Err),
		slog.String("snippet", e.RawSnippet),
		slog.Int("body_bytes", e.BodyBytes),
	}
}

// CollectionHealth reports a provider response that could not be decoded.
func (e JSONParseError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "certspotter.response_invalid", Target: e.Domain}, true
}

// SearchCompleted is emitted when a query finishes, summarising the count of certificates analyzed,
// unique subdomains extracted, pagination metrics, and truncation state.
type SearchCompleted struct {
	Domain     string
	Certs      int
	Subdomains int
	Pages      int
	Successes  int
	Failures   int
	Truncated  bool
}

// ToolName returns the tool identifier.
func (SearchCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCompleted) EventName() string { return "certspotter: search completed" }

// EventLevel returns the log severity.
func (SearchCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("certs", e.Certs),
		slog.Int("subdomains", e.Subdomains),
		slog.Int("pages", e.Pages),
		slog.Int("successes", e.Successes),
		slog.Int("failures", e.Failures),
		slog.Bool("truncated", e.Truncated),
	}
}

var (
	_ tooleventlog.HealthEvent = RateLimited{}
	_ tooleventlog.HealthEvent = PaidPlanRequired{}
	_ tooleventlog.HealthEvent = QueryFailed{}
	_ tooleventlog.HealthEvent = HTTPStatusError{}
	_ tooleventlog.HealthEvent = JSONParseError{}
)
