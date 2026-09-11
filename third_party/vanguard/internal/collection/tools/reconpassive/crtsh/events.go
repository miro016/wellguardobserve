package crtsh

import (
	"log/slog"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const (
	toolName                  = "crtsh"
	healthCodeQueryIncomplete = "crtsh.query_incomplete"
)

// SearchStarted is emitted once per query when the search loop begins.
type SearchStarted struct {
	Query      string
	MaxRetries int
}

// ToolName returns the tool identifier.
func (SearchStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchStarted) EventName() string { return "crtsh: search started" }

// EventLevel returns the log severity.
func (SearchStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("max_retries", e.MaxRetries),
	}
}

// CacheHit is emitted when a query in ModeEmbeddedCacheSupport is answered from the
// embedded fixture. It makes the lookup decision visible in the tool stream: the
// search that follows it made no request, so its absence of HTTP events is expected
// rather than a gap.
type CacheHit struct {
	Query string
	Certs int
}

// ToolName returns the tool identifier.
func (CacheHit) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CacheHit) EventName() string { return "crtsh: cache hit" }

// EventLevel returns the log severity.
func (CacheHit) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CacheHit) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("certs", e.Certs),
		retrievalAttr(retrievalCacheEmbedded),
	}
}

// retrievalAttr renders the retrieval_source attribute, the shared key that tells an
// operator whether a tool event's data came from crt.sh or the compiled-in fixture.
func retrievalAttr(source string) slog.Attr { return slog.String("retrieval_source", source) }

// CacheMiss is emitted when a query in ModeEmbeddedCacheSupport is not in the
// embedded fixture, immediately before the ordinary service search it falls through
// to. It shares that search's correlation id, so the miss and the request it caused
// are accounted as one call.
type CacheMiss struct {
	Query string
}

// ToolName returns the tool identifier.
func (CacheMiss) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CacheMiss) EventName() string { return "crtsh: cache miss" }

// EventLevel returns the log severity.
func (CacheMiss) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CacheMiss) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("query", e.Query), retrievalAttr(retrievalCacheEmbedded)}
}

// RequestBuildFailed is emitted when constructing the HTTP request fails.
type RequestBuildFailed struct {
	Query   string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (RequestBuildFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RequestBuildFailed) EventName() string { return "crtsh: failed to build request" }

// EventLevel returns the log severity.
func (RequestBuildFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RequestBuildFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// NetworkError is emitted when the HTTP transport returns an error.
type NetworkError struct {
	Query     string
	Attempt   int
	Retryable bool
	Err       error
}

// ToolName returns the tool identifier.
func (NetworkError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (NetworkError) EventName() string { return "crtsh: network error" }

// EventLevel returns the log severity.
func (NetworkError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e NetworkError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Bool("retryable", e.Retryable),
		slog.Any("error", e.Err),
	}
}

// BodyReadError is emitted when reading the HTTP response body fails.
type BodyReadError struct {
	Query      string
	Attempt    int
	StatusCode int
	Retryable  bool
	Err        error
}

// ToolName returns the tool identifier.
func (BodyReadError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (BodyReadError) EventName() string { return "crtsh: body read error" }

// EventLevel returns the log severity.
func (BodyReadError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e BodyReadError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Int("status_code", e.StatusCode),
		slog.Bool("retryable", e.Retryable),
		slog.Any("error", e.Err),
	}
}

// HTTPStatusError is emitted when crt.sh returns a non-200 HTTP status.
type HTTPStatusError struct {
	Query      string
	Attempt    int
	StatusCode int
	Retryable  bool
	Body       string
}

// ToolName returns the tool identifier.
func (HTTPStatusError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HTTPStatusError) EventName() string { return "crtsh: unexpected HTTP status" }

// EventLevel returns the log severity.
func (HTTPStatusError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HTTPStatusError) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Int("status_code", e.StatusCode),
		slog.Bool("retryable", e.Retryable),
		slog.String("body", e.Body),
	}
	if reason := statusReason(e.StatusCode); reason != "" {
		attrs = append(attrs, slog.String("reason", reason))
	}
	return attrs
}

// statusReason explains notable crt.sh HTTP statuses so a saved capture is
// self-describing in later analysis. crt.sh signals "no certificates" as a 200
// with an empty JSON array, so a 404 on the search route is a transient backend
// anomaly (overload / routing / table swap) and must be retried, not read as an
// empty result. 429 and 5xx are likewise transient.
func statusReason(code int) string {
	switch code {
	case 404:
		return "transient backend fluke on the search route, retry; crt.sh signals no-certs as 200 with an empty array, so 404 is NOT an authoritative empty result"
	case 429:
		return "rate limited (crt.sh allows few concurrent requests per IP), back off and retry"
	case 500, 502, 503, 504:
		return "crt.sh backend overloaded/unavailable, retry"
	default:
		return ""
	}
}

// JSONParseError is emitted when the response body cannot be decoded as JSON.
type JSONParseError struct {
	Query     string
	Attempt   int
	Retryable bool
	Err       error
	BodyBytes int
}

// ToolName returns the tool identifier.
func (JSONParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (JSONParseError) EventName() string { return "crtsh: JSON parse error" }

// EventLevel returns the log severity.
func (JSONParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JSONParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Bool("retryable", e.Retryable),
		slog.Any("error", e.Err),
		slog.Int("body_bytes", e.BodyBytes),
	}
}

// CertParseError is emitted when a single certificate entry cannot be parsed.
type CertParseError struct {
	Query   string
	Attempt int
	Err     error
	Raw     string
}

// ToolName returns the tool identifier.
func (CertParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertParseError) EventName() string { return "crtsh: certificate parse error" }

// EventLevel returns the log severity.
func (CertParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
		slog.String("raw", e.Raw),
	}
}

// SchedulingRetry is emitted before each retry sleep.
type SchedulingRetry struct {
	Query      string
	Attempt    int
	MaxRetries int
	Wait       time.Duration
	Err        error
}

// ToolName returns the tool identifier.
func (SchedulingRetry) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SchedulingRetry) EventName() string { return "crtsh: scheduling retry" }

// EventLevel returns the log severity.
func (SchedulingRetry) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SchedulingRetry) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Int("max_retries", e.MaxRetries),
		slog.Duration("wait", e.Wait),
		slog.Any("error", e.Err),
	}
}

// SchedulingRecheck is emitted before the cooldown that precedes a single
// re-query of a suspicious empty result (a 200 with zero certs that arrived only
// after retryable backend failures). The re-query guards against a momentary
// degraded crt.sh window being recorded as an authoritative "no certificates".
type SchedulingRecheck struct {
	Query   string
	Attempt int
	Wait    time.Duration
}

// ToolName returns the tool identifier.
func (SchedulingRecheck) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SchedulingRecheck) EventName() string { return "crtsh: scheduling degraded-empty recheck" }

// EventLevel returns the log severity.
func (SchedulingRecheck) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SchedulingRecheck) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Duration("wait", e.Wait),
		slog.String("reason", "empty 200 followed retryable backend failures; re-querying once before accepting it as authoritative"),
	}
}

// DegradedEmptyResult is emitted when a search returns zero certificates after
// crt.sh emitted retryable backend failures during the same search and a
// post-cooldown re-query was still empty. The empty result may be a
// degraded-backend artifact rather than an authoritative "no certificates";
// because crt.sh is the sole certificate source, the caller surfaces it as a
// data-quality risk instead of recording a trustworthy zero.
type DegradedEmptyResult struct {
	Query         string
	TotalAttempts int
}

// ToolName returns the tool identifier.
func (DegradedEmptyResult) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DegradedEmptyResult) EventName() string { return "crtsh: degraded empty result" }

// EventLevel returns the log severity.
func (DegradedEmptyResult) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DegradedEmptyResult) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("total_attempts", e.TotalAttempts),
		slog.String("reason", "zero certs after retryable backend failures and a re-query; empty may be degraded, not authoritative"),
	}
}

// CollectionHealth reports that crt.sh could not establish whether the empty
// result was authoritative.
func (e DegradedEmptyResult) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeQueryIncomplete, Target: e.Query}, true
}

// GaveUp is emitted when a search ends without a result: finite retries were
// exhausted, or the search's time budget (MaxQueryTime or an ancestor crawl
// deadline) ran out. It is terminal and error-level, so the operational rollup
// counts the search as a failed call rather than losing it silently.
type GaveUp struct {
	Query         string
	TotalAttempts int
	LastErr       error
}

// ToolName returns the tool identifier.
func (GaveUp) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (GaveUp) EventName() string { return "crtsh: gave up" }

// EventLevel returns the log severity.
func (GaveUp) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e GaveUp) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("total_attempts", e.TotalAttempts),
		slog.Any("last_error", e.LastErr),
	}
}

// CollectionHealth reports the abandoned certificate query.
func (e GaveUp) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeQueryIncomplete, Target: e.Query}, true
}

// OutageBreakerOpened is emitted once, the moment the cross-search outage breaker
// trips: several consecutive searches each spent their whole retry budget without a
// single successful crt.sh response, so crt.sh is treated as down for the rest of
// the run. While open, further searches probe crt.sh once instead of re-paying the
// full per-query budget, so the crawl drains fast instead of grinding one
// MaxQueryTime per remaining name. Any successful response closes the breaker again.
type OutageBreakerOpened struct {
	// ConsecutiveOutages is how many back-to-back no-response searches tripped it.
	ConsecutiveOutages int
	// Threshold is the number of consecutive outages required to open the breaker.
	Threshold int
}

// ToolName returns the tool identifier.
func (OutageBreakerOpened) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (OutageBreakerOpened) EventName() string { return "crtsh: outage breaker opened" }

// EventLevel returns the log severity.
func (OutageBreakerOpened) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e OutageBreakerOpened) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.Int("consecutive_outages", e.ConsecutiveOutages),
		slog.Int("threshold", e.Threshold),
		slog.String("reason", "crt.sh failed every recent search outright; probing once per name until it responds again"),
	}
}

// OutageBreakerSkipped is emitted for each search that is abandoned after a single
// probe because the outage breaker is open. It is the fast-drain counterpart to
// GaveUp: the search still counts as a failed call, but it cost one request instead
// of the whole MaxQueryTime budget.
type OutageBreakerSkipped struct {
	Query   string
	Attempt int
	LastErr error
}

// ToolName returns the tool identifier.
func (OutageBreakerSkipped) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (OutageBreakerSkipped) EventName() string {
	return "crtsh: search abandoned (outage breaker open)"
}

// EventLevel returns the log severity.
func (OutageBreakerSkipped) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e OutageBreakerSkipped) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Any("last_error", e.LastErr),
		slog.String("reason", "crt.sh outage breaker open; probed once and abandoned instead of retrying to the time budget"),
	}
}

// CollectionHealth reports the query abandoned while the outage breaker was open.
func (e OutageBreakerSkipped) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeQueryIncomplete, Target: e.Query}, true
}

// CertDiscovered is emitted when a valid certificate is parsed from crt.sh results.
type CertDiscovered struct {
	Query  string
	CertID int64
	Issuer string
	SANs   int
}

// ToolName returns the tool identifier.
func (CertDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertDiscovered) EventName() string { return "crtsh: cert discovered" }

// EventLevel returns the log severity.
func (CertDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int64("cert_id", e.CertID),
		slog.String("issuer", e.Issuer),
		slog.Int("sans", e.SANs),
	}
}

// RateLimited is emitted when crt.sh HTTP 429 rate limit exhausts retries or aborts.
type RateLimited struct {
	Query   string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "crtsh: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// SearchCompleted is emitted as the universal operational completion summary of a crt.sh search.
type SearchCompleted struct {
	Query      string
	Certs      int
	Subdomains int
	Attempts   int
	Degraded   bool
	Truncated  bool
	// RetrievalSource is where the search's data came from: "service" for a crt.sh
	// answer (including a failed attempt at one) or "cache_embedded" for the
	// compiled-in fixture, so the terminal event alone states the provenance. A cache
	// miss records its own CacheMiss and then this event says "service", making the
	// two-step decision readable in order.
	RetrievalSource string
}

// ToolName returns the tool identifier.
func (SearchCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SearchCompleted) EventName() string { return "crtsh: search completed" }

// EventLevel returns the log severity.
func (SearchCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SearchCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("query", e.Query),
		slog.Int("certs", e.Certs),
		slog.Int("subdomains", e.Subdomains),
		slog.Int("attempts", e.Attempts),
		slog.Bool("degraded", e.Degraded),
		slog.Bool("truncated", e.Truncated),
		retrievalAttr(e.RetrievalSource),
	}
}

var (
	_ tooleventlog.HealthEvent = DegradedEmptyResult{}
	_ tooleventlog.HealthEvent = GaveUp{}
	_ tooleventlog.HealthEvent = OutageBreakerSkipped{}
)
