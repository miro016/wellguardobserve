package whois

import (
	"log/slog"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "whois"

// LookupStarted is emitted when a registration lookup begins for a domain.
type LookupStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (LookupStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupStarted) EventName() string { return "whois: lookup started" }

// EventLevel returns the log severity.
func (LookupStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// QueryFailed is emitted when the port-43 WHOIS network query or socket dial fails
// and the RDAP fallback will be attempted next.
type QueryFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (QueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryFailed) EventName() string { return "whois: WHOIS failed, trying RDAP" }

// EventLevel returns the log severity.
func (QueryFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.Any("error", e.Err)}
}

// QuerySkipped is emitted when the port-43 WHOIS leg is skipped because the
// TLD's WHOIS server was already found unreachable earlier in the run, so the
// lookup goes straight to RDAP without paying the dial timeout again.
type QuerySkipped struct {
	Domain string
	TLD    string
}

// ToolName returns the tool identifier.
func (QuerySkipped) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QuerySkipped) EventName() string { return "whois: WHOIS skipped (server down), using RDAP" }

// EventLevel returns the log severity.
func (QuerySkipped) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QuerySkipped) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("tld", e.TLD)}
}

// RdapFailed is emitted when the RDAP HTTPS fallback query or JSON parsing fails.
type RdapFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (RdapFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RdapFailed) EventName() string { return "whois: RDAP fallback failed" }

// EventLevel returns the log severity.
func (RdapFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RdapFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.Any("error", e.Err)}
}

// LookupSucceeded is emitted when a lookup returns registration data. Source
// records which leg answered ("whois" or "rdap") so tool data can be compared.
type LookupSucceeded struct {
	Domain          string
	Source          string
	Registrar       string
	CreatedDate     time.Time
	ExpiryDate      time.Time
	NameserverCount int
}

// ToolName returns the tool identifier.
func (LookupSucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupSucceeded) EventName() string { return "whois: lookup succeeded" }

// EventLevel returns the log severity.
func (LookupSucceeded) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupSucceeded) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("source", e.Source),
		slog.String("registrar", e.Registrar),
		slog.Time("created", e.CreatedDate),
		slog.Time("expires", e.ExpiryDate),
		slog.Int("nameserver_count", e.NameserverCount),
	}
}

// LookupFailed is emitted when overall lookup resolution fails because both the
// WHOIS and RDAP legs failed to return valid registration data.
type LookupFailed struct {
	Domain   string
	WhoisErr error
	RdapErr  error
}

// ToolName returns the tool identifier.
func (LookupFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupFailed) EventName() string { return "whois: lookup failed" }

// EventLevel returns the log severity.
func (LookupFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Any("whois_error", e.WhoisErr),
		slog.Any("rdap_error", e.RdapErr),
	}
}

// LookupCompleted is emitted when a WHOIS/RDAP domain lookup concludes, summarizing execution metrics.
type LookupCompleted struct {
	Domain         string
	WhoisAttempted bool
	RdapAttempted  bool
	Succeeded      bool
	Degraded       bool
}

// ToolName returns the tool identifier.
func (LookupCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupCompleted) EventName() string { return "whois: lookup completed" }

// EventLevel returns the log severity.
func (LookupCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Bool("whois_used", e.WhoisAttempted),
		slog.Bool("rdap_used", e.RdapAttempted),
		slog.Bool("succeeded", e.Succeeded),
		slog.Bool("degraded", e.Degraded),
	}
}

// CollectionHealth reports a lookup only when neither WHOIS nor RDAP produced
// usable registration evidence.
func (e LookupCompleted) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	if e.Succeeded {
		return tooleventlog.HealthProblem{}, false
	}
	return tooleventlog.HealthProblem{Code: "whois.lookup_failed", Target: e.Domain}, true
}

// RateLimited is emitted when an RDAP HTTP 429 rate limit or WHOIS rate limit is hit.
type RateLimited struct {
	Domain  string
	Server  string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "whois: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("server", e.Server),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// WhoisServerThrottled is emitted when port 43 WHOIS servers drop connections or return explicit quota/ban strings.
//
//nolint:revive // named specifically to distinguish from RDAP events
type WhoisServerThrottled struct {
	Domain  string
	Server  string
	Message string
}

// ToolName returns the tool identifier.
func (WhoisServerThrottled) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (WhoisServerThrottled) EventName() string { return "whois: server throttled" }

// EventLevel returns the log severity.
func (WhoisServerThrottled) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e WhoisServerThrottled) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("server", e.Server),
		slog.String("message", e.Message),
	}
}

// RDAPParseError is emitted when failing to decode RDAP JSON payload or registrar date formats.
type RDAPParseError struct {
	Domain  string
	Server  string
	Snippet string
	Err     error
}

// ToolName returns the tool identifier.
func (RDAPParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RDAPParseError) EventName() string { return "whois: RDAP parse error" }

// EventLevel returns the log severity.
func (RDAPParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RDAPParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("server", e.Server),
		slog.String("snippet", e.Snippet),
		slog.Any("error", e.Err),
	}
}

// WhoisParseError is emitted when failing to parse raw WHOIS text format or date strings.
//
//nolint:revive // named specifically to distinguish from RDAP events
type WhoisParseError struct {
	Domain  string
	Server  string
	Snippet string
	Err     error
}

// ToolName returns the tool identifier.
func (WhoisParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (WhoisParseError) EventName() string { return "whois: WHOIS parse error" }

// EventLevel returns the log severity.
func (WhoisParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e WhoisParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("server", e.Server),
		slog.String("snippet", e.Snippet),
		slog.Any("error", e.Err),
	}
}

var _ tooleventlog.HealthEvent = LookupCompleted{}
