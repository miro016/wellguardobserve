package asn

import (
	"log/slog"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "asn"

// LookupStarted is emitted when an ASN lookup begins for an IP address.
type LookupStarted struct {
	IP        string
	QueryType string
	Resolver  string
}

// ToolName returns the tool identifier.
func (LookupStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupStarted) EventName() string { return "asn: lookup started" }

// EventLevel returns the log severity.
func (LookupStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupStarted) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{slog.String("ip", e.IP)}
	if e.QueryType != "" {
		attrs = append(attrs, slog.String("query_type", e.QueryType))
	}
	if e.Resolver != "" {
		attrs = append(attrs, slog.String("resolver", e.Resolver))
	}
	return attrs
}

// DNSTimeout is emitted when a DNS resolver query times out after exhausting all retries.
type DNSTimeout struct {
	IP        string
	QueryType string
	Attempt   int
	Err       error
}

// ToolName returns the tool identifier.
func (DNSTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSTimeout) EventName() string { return "asn: dns timeout" }

// EventLevel returns the log severity.
func (DNSTimeout) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("query_type", e.QueryType),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// DNSResolutionFailed is emitted when a DNS resolver query fails with an error rcode or network error after exhausting retries.
type DNSResolutionFailed struct {
	IP        string
	QueryType string
	RCode     string
	Err       error
}

// ToolName returns the tool identifier.
func (DNSResolutionFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSResolutionFailed) EventName() string { return "asn: dns resolution failed" }

// EventLevel returns the log severity.
func (DNSResolutionFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSResolutionFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("query_type", e.QueryType),
		slog.String("rcode", e.RCode),
		slog.Any("error", e.Err),
	}
}

// OriginParseFailed is emitted when the origin TXT record cannot be parsed.
type OriginParseFailed struct {
	IP      string
	TXT     string
	RawTXT  string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (OriginParseFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (OriginParseFailed) EventName() string { return "asn: origin parse failed" }

// EventLevel returns the log severity.
func (OriginParseFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e OriginParseFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("txt", e.TXT),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// NameParseFailed is emitted when the AS name TXT record cannot be parsed.
type NameParseFailed struct {
	IP      string
	ASN     int
	TXT     string
	RawTXT  string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (NameParseFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (NameParseFailed) EventName() string { return "asn: name parse failed" }

// EventLevel returns the log severity.
func (NameParseFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e NameParseFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("asn", e.ASN),
		slog.String("txt", e.TXT),
		slog.Int("attempt", e.Attempt),
		slog.Any("error", e.Err),
	}
}

// LookupRetried is emitted before a transient TXT lookup failure is retried, so
// the recovery is visible in the tool-event stream (mirrors crtsh's retry signal).
// Attempt is the 1-based retry number; Err is the failure that triggered it.
type LookupRetried struct {
	Name    string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (LookupRetried) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupRetried) EventName() string { return "asn: lookup retried" }

// EventLevel returns the log severity.
func (LookupRetried) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupRetried) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("name", e.Name), slog.Int("attempt", e.Attempt), slog.Any("error", e.Err)}
}

// LookupSucceeded is emitted when an ASN lookup returns a result.
type LookupSucceeded struct {
	IP      string
	ASN     int
	Prefix  string
	ASName  string
	Country string
}

// ToolName returns the tool identifier.
func (LookupSucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupSucceeded) EventName() string { return "asn: lookup succeeded" }

// EventLevel returns the log severity.
func (LookupSucceeded) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupSucceeded) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("asn", e.ASN),
		slog.String("prefix", e.Prefix),
		slog.String("as_name", e.ASName),
	}
	if e.Country != "" {
		attrs = append(attrs, slog.String("country", e.Country))
	}
	return attrs
}

// LookupCompleted is emitted at the end of an ASN lookup as a final operational summary.
type LookupCompleted struct {
	IP        string
	ASN       int
	Queries   int
	Retries   int
	Successes int
	Failures  int
	Degraded  bool
}

// ToolName returns the tool identifier.
func (LookupCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupCompleted) EventName() string { return "asn: lookup completed" }

// EventLevel returns the log severity.
func (LookupCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("asn", e.ASN),
		slog.Int("queries", e.Queries),
		slog.Int("retries", e.Retries),
		slog.Int("successes", e.Successes),
		slog.Int("failures", e.Failures),
		slog.Bool("degraded", e.Degraded),
	}
}

// CollectionHealth reports an incomplete ASN lookup after retries are exhausted.
func (e LookupCompleted) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	if e.Failures <= 0 {
		return tooleventlog.HealthProblem{}, false
	}
	return tooleventlog.HealthProblem{Code: "asn.lookup_incomplete", Target: e.IP}, true
}

var _ tooleventlog.HealthEvent = LookupCompleted{}
