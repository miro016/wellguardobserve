package mailsec

import (
	"log/slog"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "mailsec"

// LookupStarted is emitted when a mail-security lookup begins for a domain.
type LookupStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (LookupStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupStarted) EventName() string { return "mailsec: lookup started" }

// EventLevel returns the log severity.
func (LookupStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// LookupCompleted is emitted when a mail-security lookup finishes, summarising
// the posture found.
type LookupCompleted struct {
	Domain            string
	MX                int
	HasSPF            bool
	DMARCSeverity     string
	DKIM              int
	HasBIMI           bool
	HasMTASTS         bool
	TotalQueries      int
	SuccessfulQueries int
	FailedQueries     int
	Degraded          bool
}

// ToolName returns the tool identifier.
func (LookupCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupCompleted) EventName() string { return "mailsec: lookup completed" }

// EventLevel returns the log severity.
func (LookupCompleted) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("mx", e.MX),
		slog.Bool("spf", e.HasSPF),
		slog.String("dmarc_severity", e.DMARCSeverity),
		slog.Int("dkim", e.DKIM),
		slog.Bool("bimi", e.HasBIMI),
		slog.Bool("mtasts", e.HasMTASTS),
		slog.Int("total_queries", e.TotalQueries),
		slog.Int("successful_queries", e.SuccessfulQueries),
		slog.Int("failed_queries", e.FailedQueries),
		slog.Bool("degraded", e.Degraded),
	}
}

// CollectionHealth reports an incomplete mail-security lookup only when one or
// more DNS queries failed. Target-owned policy syntax errors do not contribute to
// FailedQueries.
func (e LookupCompleted) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	if e.FailedQueries <= 0 {
		return tooleventlog.HealthProblem{}, false
	}
	return tooleventlog.HealthProblem{Code: "mailsec.lookup_incomplete", Target: e.Domain}, true
}

// DNSTimeout is emitted when a DNS query times out during mail policy lookups.
type DNSTimeout struct {
	Domain  string
	Type    string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (DNSTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSTimeout) EventName() string { return "mailsec: dns timeout" }

// EventLevel returns the log severity.
func (DNSTimeout) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// DNSServerError is emitted for SERVFAIL/REFUSED resolver errors.
type DNSServerError struct {
	Domain string
	Type   string
	Rcode  string
	Err    error
}

// ToolName returns the tool identifier.
func (DNSServerError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSServerError) EventName() string { return "mailsec: dns server error" }

// EventLevel returns the log severity.
func (DNSServerError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSServerError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.String("rcode", e.Rcode),
		slog.Any("error", e.Err),
	}
}

// RecordParseError is emitted when an email security TXT record exists but fails syntax parsing or violates RFC rules.
type RecordParseError struct {
	Domain string
	Type   string
	RawTXT string
	Err    error
}

// ToolName returns the tool identifier.
func (RecordParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RecordParseError) EventName() string { return "mailsec: record parse error" }

// EventLevel returns the log severity.
func (RecordParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RecordParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.String("raw_txt", e.RawTXT),
		slog.Any("error", e.Err),
	}
}

// PolicyDiscovered is emitted when an individual parsed security policy is evaluated.
type PolicyDiscovered struct {
	Domain     string
	Type       string
	Strictness string
	Raw        string
}

// ToolName returns the tool identifier.
func (PolicyDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PolicyDiscovered) EventName() string { return "mailsec: policy discovered" }

// EventLevel returns the log severity.
func (PolicyDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PolicyDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.String("strictness", e.Strictness),
		slog.String("raw", e.Raw),
	}
}

// QueryRetried is emitted before a transient DNS query failure is retried, so the
// recovery is visible in the tool-event stream (mirrors the asn retry signal).
// Attempt is the 1-based retry number; Err is the failure that triggered it.
type QueryRetried struct {
	Name    string
	Type    string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (QueryRetried) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryRetried) EventName() string { return "mailsec: query retried" }

// EventLevel returns the log severity.
func (QueryRetried) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryRetried) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("name", e.Name),
		slog.String("type", e.Type),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// QueryFailed is emitted when a single DNS query returns an error. Absent
// records (NXDOMAIN) are normal and do not produce this event.
type QueryFailed struct {
	Name string
	Type string
	Err  error
}

// ToolName returns the tool identifier.
func (QueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryFailed) EventName() string { return "mailsec: query failed" }

// EventLevel returns the log severity.
func (QueryFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("name", e.Name),
		slog.String("type", e.Type),
		slog.Any("error", e.Err),
	}
}

var _ tooleventlog.HealthEvent = LookupCompleted{}
