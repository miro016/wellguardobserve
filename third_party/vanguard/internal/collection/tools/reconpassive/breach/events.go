package breach

import (
	"log/slog"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "breach"

// LookupStarted is emitted when a breach lookup begins for a domain.
type LookupStarted struct {
	Domain   string
	Endpoint string
}

// ToolName returns the tool identifier.
func (LookupStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupStarted) EventName() string { return "breach: lookup started" }

// EventLevel returns the log severity.
func (LookupStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupStarted) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{slog.String("domain", e.Domain)}
	if e.Endpoint != "" {
		attrs = append(attrs, slog.String("endpoint", e.Endpoint))
	}
	return attrs
}

// AliasExposed is emitted for each breached email alias found on the domain,
// carrying the breach names that exposed it.
type AliasExposed struct {
	Domain   string
	Alias    string
	Breaches []string
}

// ToolName returns the tool identifier.
func (AliasExposed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (AliasExposed) EventName() string { return "breach: alias exposed" }

// EventLevel returns the log severity.
func (AliasExposed) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e AliasExposed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("alias", e.Alias),
		slog.String("breaches", strings.Join(e.Breaches, ", ")),
	}
}

// RateLimited is emitted specifically when HTTP 429 occurs and retries are exhausted.
type RateLimited struct {
	Domain   string
	Endpoint string
	Attempt  int
	Err      error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "breach: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("endpoint", e.Endpoint),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a lookup lost to rate limiting.
func (e RateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "breach.rate_limited", Target: e.Domain}, true
}

// AuthFailed is emitted for HTTP 401/403 when the API key is rejected or missing permissions.
type AuthFailed struct {
	Domain     string
	Endpoint   string
	StatusCode int
}

// ToolName returns the tool identifier.
func (AuthFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (AuthFailed) EventName() string { return "breach: auth failed" }

// EventLevel returns the log severity.
func (AuthFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e AuthFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("endpoint", e.Endpoint),
		slog.Int("status_code", e.StatusCode),
	}
}

// CollectionHealth reports a lookup rejected by authentication or authorization.
func (e AuthFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "breach.authentication_failed", Target: e.Domain}, true
}

// UpstreamServiceUnavailable is emitted for HTTP 5xx errors indicating API vendor downtime.
type UpstreamServiceUnavailable struct {
	Domain     string
	StatusCode int
	Retryable  bool
}

// ToolName returns the tool identifier.
func (UpstreamServiceUnavailable) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UpstreamServiceUnavailable) EventName() string { return "breach: upstream service unavailable" }

// EventLevel returns the log severity.
func (UpstreamServiceUnavailable) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UpstreamServiceUnavailable) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("status_code", e.StatusCode),
		slog.Bool("retryable", e.Retryable),
	}
}

// CollectionHealth reports a lookup lost to upstream service unavailability.
func (e UpstreamServiceUnavailable) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "breach.upstream_unavailable", Target: e.Domain}, true
}

// LookupCompleted is emitted when a breach lookup finishes, summarising the count
// of exposed aliases and operational execution metrics.
type LookupCompleted struct {
	Domain   string
	Aliases  int
	Queries  int
	Failed   int
	Degraded bool
}

// ToolName returns the tool identifier.
func (LookupCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupCompleted) EventName() string { return "breach: lookup completed" }

// EventLevel returns the log severity.
func (LookupCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("aliases", e.Aliases),
		slog.Int("queries", e.Queries),
		slog.Int("failed", e.Failed),
		slog.Bool("degraded", e.Degraded),
	}
}

// NetworkError is emitted when the request cannot be built or sent (DNS failure,
// connection refused, timeout, context cancellation).
type NetworkError struct {
	Domain    string
	Attempt   int
	Retryable bool
	Err       error
}

// ToolName returns the tool identifier.
func (NetworkError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (NetworkError) EventName() string { return "breach: network error" }

// EventLevel returns the log severity.
func (NetworkError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e NetworkError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("attempt", e.Attempt),
		slog.Bool("retryable", e.Retryable),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a lookup transport failure.
func (e NetworkError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "breach.network_failed", Target: e.Domain}, true
}

// HTTPStatusError is emitted when HIBP returns an unhandled non-success status
// other than 404, 401, 403, 429, or 5xx (which have dedicated typed events).
type HTTPStatusError struct {
	Domain     string
	StatusCode int
	Status     string
	Body       string
	Reason     string
}

// ToolName returns the tool identifier.
func (HTTPStatusError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HTTPStatusError) EventName() string { return "breach: http status error" }

// EventLevel returns the log severity.
func (HTTPStatusError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HTTPStatusError) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("status_code", e.StatusCode),
		slog.String("status", e.Status),
		slog.String("body", e.Body),
	}
	if e.Reason != "" {
		attrs = append(attrs, slog.String("reason", e.Reason))
	}
	return attrs
}

// CollectionHealth reports an unusable provider HTTP response.
func (e HTTPStatusError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "breach.http_status_error", Target: e.Domain}, true
}

// JSONParsingError is emitted when a 200 response body cannot be decoded. It
// carries the raw body snippet and byte count so a schema change or malformed
// payload can be inspected.
type JSONParsingError struct {
	Domain     string
	RawPayload string
	BodyBytes  int
	Err        error
}

// ToolName returns the tool identifier.
func (JSONParsingError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (JSONParsingError) EventName() string { return "breach: json parsing error" }

// EventLevel returns the log severity.
func (JSONParsingError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JSONParsingError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("payload_snippet", e.RawPayload),
		slog.Int("body_bytes", e.BodyBytes),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a provider response that could not be decoded.
func (e JSONParsingError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "breach.response_invalid", Target: e.Domain}, true
}

var (
	_ tooleventlog.HealthEvent = RateLimited{}
	_ tooleventlog.HealthEvent = AuthFailed{}
	_ tooleventlog.HealthEvent = UpstreamServiceUnavailable{}
	_ tooleventlog.HealthEvent = NetworkError{}
	_ tooleventlog.HealthEvent = HTTPStatusError{}
	_ tooleventlog.HealthEvent = JSONParsingError{}
)
