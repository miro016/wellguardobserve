package censys

import (
	"log/slog"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// CertSearchStarted is emitted when a Censys certificate search begins for a domain.
type CertSearchStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (CertSearchStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertSearchStarted) EventName() string { return "censys: cert search started" }

// EventLevel returns the log severity.
func (CertSearchStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertSearchStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// CertQuerySucceeded is emitted when the certificate CenQL query returns.
type CertQuerySucceeded struct {
	Domain string
	Label  string
	Query  string
	Hits   int
}

// ToolName returns the tool identifier.
func (CertQuerySucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertQuerySucceeded) EventName() string { return "censys: cert query succeeded" }

// EventLevel returns the log severity.
func (CertQuerySucceeded) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertQuerySucceeded) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
		slog.String("query", e.Query),
		slog.Int("hits", e.Hits),
	}
}

// CertQueryFailed is emitted when the certificate CenQL query errors.
type CertQueryFailed struct {
	Domain string
	Label  string
	Query  string
	Err    error
}

// ToolName returns the tool identifier.
func (CertQueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertQueryFailed) EventName() string { return "censys: cert query failed" }

// EventLevel returns the log severity.
func (CertQueryFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertQueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
		slog.String("query", e.Query),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a failed certificate-history query.
func (e CertQueryFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.certificate_query_failed", Component: e.Label, Target: e.Domain}, true
}

// CertPaidPlanRequired is emitted when a certificate query returns 403, indicating
// the certificate search requires a paid plan.
type CertPaidPlanRequired struct {
	Domain string
	Label  string
}

// ToolName returns the tool identifier.
func (CertPaidPlanRequired) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertPaidPlanRequired) EventName() string { return "censys: cert paid plan required" }

// EventLevel returns the log severity.
func (CertPaidPlanRequired) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertPaidPlanRequired) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
	}
}

// CollectionHealth reports a certificate query blocked by account entitlement.
func (e CertPaidPlanRequired) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.certificate_access_denied", Component: e.Label, Target: e.Domain}, true
}

// CertInsufficientBalance is emitted when a certificate query fails because the Censys
// account has insufficient balance (an empty query wallet, returned as HTTP 422). It is an
// account-level wall, so the certificate search reports the tool unavailable rather than
// retrying the depleted wallet.
type CertInsufficientBalance struct {
	Domain string
	Label  string
}

// ToolName returns the tool identifier.
func (CertInsufficientBalance) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertInsufficientBalance) EventName() string { return "censys: cert insufficient balance" }

// EventLevel returns the log severity.
func (CertInsufficientBalance) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertInsufficientBalance) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
	}
}

// CollectionHealth reports a certificate query blocked by an exhausted balance.
func (e CertInsufficientBalance) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.certificate_balance_exhausted", Component: e.Label, Target: e.Domain}, true
}

// CertRateLimited is emitted when the certificate query fails because Censys
// returned HTTP 429 and the SDK's retries were exhausted.
type CertRateLimited struct {
	Domain string
	Label  string
	Query  string
	Err    error
}

// ToolName returns the tool identifier.
func (CertRateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertRateLimited) EventName() string { return "censys: cert rate limited" }

// EventLevel returns the log severity.
func (CertRateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertRateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("label", e.Label),
		slog.String("query", e.Query),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a certificate query lost to rate limiting.
func (e CertRateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "censys.certificate_rate_limited", Component: e.Label, Target: e.Domain}, true
}

// CertCacheHit is emitted when a certificate-history search in
// ModeEmbeddedCacheOnly is answered from the embedded fixture.
type CertCacheHit struct {
	Domain string
	Certs  int
	Names  int
}

// ToolName returns the tool identifier.
func (CertCacheHit) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertCacheHit) EventName() string { return "censys: cert cache hit" }

// EventLevel returns the log severity.
func (CertCacheHit) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertCacheHit) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("certs", e.Certs),
		slog.Int("names", e.Names),
		retrievalAttr(retrievalCacheEmbedded),
	}
}

// CertCacheMiss is emitted when a certificate-history search in
// ModeEmbeddedCacheOnly finds no entry for the domain. The corroboration then counts
// Censys as a source it could not consult, which is the truth: the mode never falls
// through to the API, and an invented empty would assert the domain has no
// certificates - the exact claim the corroboration acts on.
type CertCacheMiss struct {
	Domain string
}

// ToolName returns the tool identifier.
func (CertCacheMiss) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertCacheMiss) EventName() string { return "censys: cert cache miss" }

// EventLevel returns the log severity.
func (CertCacheMiss) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertCacheMiss) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), retrievalAttr(retrievalCacheEmbedded)}
}

// CertSearchCompleted is emitted when the certificate search finishes, summarising
// the certificate count.
type CertSearchCompleted struct {
	Domain    string
	Certs     int
	Truncated bool
	// RetrievalSource is where the search's data came from: "service" for an API
	// answer (including a failed attempt at one) or "cache_embedded" for the
	// compiled-in fixture, so the terminal event alone states the provenance.
	RetrievalSource string
}

// ToolName returns the tool identifier.
func (CertSearchCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertSearchCompleted) EventName() string { return "censys: cert search completed" }

// EventLevel returns the log severity.
func (CertSearchCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertSearchCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("certs", e.Certs),
		slog.Bool("truncated", e.Truncated),
		retrievalAttr(e.RetrievalSource),
	}
}

var (
	_ tooleventlog.HealthEvent = CertQueryFailed{}
	_ tooleventlog.HealthEvent = CertPaidPlanRequired{}
	_ tooleventlog.HealthEvent = CertInsufficientBalance{}
	_ tooleventlog.HealthEvent = CertRateLimited{}
)
