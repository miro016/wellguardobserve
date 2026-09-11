package virustotal

import (
	"log/slog"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "virustotal"

// LookupStarted is emitted when a domain intelligence lookup begins.
type LookupStarted struct {
	Domain   string
	Endpoint string
}

// ToolName returns the tool identifier.
func (LookupStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupStarted) EventName() string { return "virustotal: lookup started" }

// EventLevel returns the log severity.
func (LookupStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("endpoint", e.Endpoint),
	}
}

// LookupCompleted is emitted when a domain intelligence lookup finishes,
// summarising the reputation posture found.
type LookupCompleted struct {
	Domain     string
	Reputation int
	Malicious  int
	Suspicious int
	Categories int
	Queries    int
	Succeeded  int
	Failed     int
	Degraded   bool
}

// ToolName returns the tool identifier.
func (LookupCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupCompleted) EventName() string { return "virustotal: lookup completed" }

// EventLevel returns the log severity.
func (LookupCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("reputation", e.Reputation),
		slog.Int("malicious", e.Malicious),
		slog.Int("suspicious", e.Suspicious),
		slog.Int("categories", e.Categories),
		slog.Int("queries", e.Queries),
		slog.Int("succeeded", e.Succeeded),
		slog.Int("failed", e.Failed),
		slog.Bool("degraded", e.Degraded),
	}
}

// LookupFailed is emitted when the domain object cannot be fetched. The error is
// fatal to the lookup (Lookup returns it), but non-fatal to the overall scan.
type LookupFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (LookupFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupFailed) EventName() string { return "virustotal: lookup failed" }

// EventLevel returns the log severity.
func (LookupFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a failed domain intelligence lookup.
func (e LookupFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "virustotal.lookup_failed", Target: e.Domain}, true
}

// DomainNotFound is emitted when VirusTotal has never observed the domain (HTTP
// 404 / NotFoundError). This is a clean empty result, not a failure: many obscure
// subdomains are simply unknown to VirusTotal, so Lookup returns a nil report and
// a nil error rather than treating it as a tool error.
type DomainNotFound struct {
	Domain string
}

// ToolName returns the tool identifier.
func (DomainNotFound) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DomainNotFound) EventName() string { return "virustotal: domain not found" }

// EventLevel returns the log severity.
func (DomainNotFound) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DomainNotFound) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// SubdomainEnumStarted is emitted when subdomain enumeration begins for a domain.
type SubdomainEnumStarted struct {
	Domain string
	Limit  int
}

// ToolName returns the tool identifier.
func (SubdomainEnumStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SubdomainEnumStarted) EventName() string { return "virustotal: subdomain enumeration started" }

// EventLevel returns the log severity.
func (SubdomainEnumStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SubdomainEnumStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("limit", e.Limit),
	}
}

// SubdomainFound is emitted for each subdomain discovered, mirroring the other
// passive subdomain sources so per-subdomain coverage can be compared.
type SubdomainFound struct {
	Domain    string
	Subdomain string
	LastSeen  time.Time
	Source    string
}

// ToolName returns the tool identifier.
func (SubdomainFound) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SubdomainFound) EventName() string { return "virustotal: subdomain found" }

// EventLevel returns the log severity.
func (SubdomainFound) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SubdomainFound) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("subdomain", e.Subdomain),
		slog.String("source", e.Source),
	}
	if !e.LastSeen.IsZero() {
		attrs = append(attrs, slog.Time("last_seen", e.LastSeen))
	}
	return attrs
}

// SubdomainEnumCompleted is emitted when subdomain enumeration finishes.
type SubdomainEnumCompleted struct {
	Domain    string
	Count     int
	Queries   int
	Succeeded int
	Failed    int
	Truncated bool
	Degraded  bool
}

// ToolName returns the tool identifier.
func (SubdomainEnumCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SubdomainEnumCompleted) EventName() string {
	return "virustotal: subdomain enumeration completed"
}

// EventLevel returns the log severity.
func (SubdomainEnumCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SubdomainEnumCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("count", e.Count),
		slog.Int("queries", e.Queries),
		slog.Int("succeeded", e.Succeeded),
		slog.Int("failed", e.Failed),
		slog.Bool("truncated", e.Truncated),
		slog.Bool("degraded", e.Degraded),
	}
}

// SubdomainEnumFailed is emitted when subdomain enumeration errors. It is
// non-fatal: the subdomains collected before the error are still returned.
type SubdomainEnumFailed struct {
	Domain    string
	Collected int
	Err       error
}

// ToolName returns the tool identifier.
func (SubdomainEnumFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SubdomainEnumFailed) EventName() string { return "virustotal: subdomain enumeration failed" }

// EventLevel returns the log severity.
func (SubdomainEnumFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SubdomainEnumFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("collected", e.Collected),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports incomplete subdomain enumeration.
func (e SubdomainEnumFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "virustotal.subdomains_failed", Target: e.Domain}, true
}

// RateLimited is emitted when VirusTotal API rate limit or quota is exceeded (HTTP 429) after retries.
type RateLimited struct {
	Domain   string
	Endpoint string
	Attempt  int
	Err      error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "virustotal: rate limited" }

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

// CollectionHealth reports a provider request lost to rate limiting.
func (e RateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "virustotal.rate_limited", Target: e.Domain}, true
}

// AuthFailed is emitted when API key authentication fails (HTTP 401/403).
type AuthFailed struct {
	Domain     string
	Endpoint   string
	StatusCode int
	Err        error
}

// ToolName returns the tool identifier.
func (AuthFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (AuthFailed) EventName() string { return "virustotal: auth failed" }

// EventLevel returns the log severity.
func (AuthFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e AuthFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("endpoint", e.Endpoint),
		slog.Int("status_code", e.StatusCode),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a provider request rejected by authentication.
func (e AuthFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "virustotal.authentication_failed", Target: e.Domain}, true
}

// JSONParseError is emitted when JSON decoding of an API response fails.
type JSONParseError struct {
	Domain   string
	Endpoint string
	Snippet  string
	Err      error
}

// ToolName returns the tool identifier.
func (JSONParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (JSONParseError) EventName() string { return "virustotal: json parse error" }

// EventLevel returns the log severity.
func (JSONParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JSONParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("endpoint", e.Endpoint),
		slog.String("snippet", e.Snippet),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports an undecodable provider response.
func (e JSONParseError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "virustotal.response_invalid", Target: e.Domain}, true
}

var (
	_ tooleventlog.HealthEvent = LookupFailed{}
	_ tooleventlog.HealthEvent = SubdomainEnumFailed{}
	_ tooleventlog.HealthEvent = RateLimited{}
	_ tooleventlog.HealthEvent = AuthFailed{}
	_ tooleventlog.HealthEvent = JSONParseError{}
)
