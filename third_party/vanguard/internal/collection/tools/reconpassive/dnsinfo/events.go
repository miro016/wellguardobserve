package dnsinfo

import (
	"log/slog"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const (
	toolName      = "dnsinfo"
	ptrRecordType = "PTR"
)

// LookupStarted is emitted when a DNS lookup begins for a domain.
type LookupStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (LookupStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupStarted) EventName() string { return "dnsinfo: lookup started" }

// EventLevel returns the log severity.
func (LookupStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// LookupCompleted is emitted when a DNS lookup finishes, summarising what was found.
type LookupCompleted struct {
	Domain   string
	A        int
	AAAA     int
	NS       int
	MX       int
	TXT      int
	SOA      bool
	DNSSEC   bool
	Queries  int
	Failed   int
	Degraded bool
}

// ToolName returns the tool identifier.
func (LookupCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (LookupCompleted) EventName() string { return "dnsinfo: lookup completed" }

// EventLevel returns the log severity.
func (LookupCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e LookupCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("a", e.A),
		slog.Int("aaaa", e.AAAA),
		slog.Int("ns", e.NS),
		slog.Int("mx", e.MX),
		slog.Int("txt", e.TXT),
		slog.Bool("soa", e.SOA),
		slog.Bool("dnssec", e.DNSSEC),
		slog.Int("queries", e.Queries),
		slog.Int("failed", e.Failed),
		slog.Bool("degraded", e.Degraded),
	}
}

// CollectionHealth reports an incomplete DNS lookup when one or more requested
// record queries failed. Clean negative answers are not included in Failed.
func (e LookupCompleted) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	if e.Failed <= 0 {
		return tooleventlog.HealthProblem{}, false
	}
	return tooleventlog.HealthProblem{Code: "dnsinfo.lookup_incomplete", Target: e.Domain}, true
}

// ZoneTransferStarted is emitted when a zone transfer is about to be attempted.
type ZoneTransferStarted struct {
	Domain      string
	Nameservers int
}

// ToolName returns the tool identifier.
func (ZoneTransferStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ZoneTransferStarted) EventName() string { return "dnsinfo: zone transfer started" }

// EventLevel returns the log severity.
func (ZoneTransferStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ZoneTransferStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("nameservers", e.Nameservers),
	}
}

// QueryFailed is emitted when a DNS record query returns an error.
type QueryFailed struct {
	Domain string
	Type   string
	Err    error
}

// ToolName returns the tool identifier.
func (QueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryFailed) EventName() string { return "dnsinfo: query failed" }

// EventLevel returns the log severity.
func (QueryFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.Any("error", e.Err),
	}
}

// QueryNoRecords is emitted when a DNS record query returns a clean negative
// answer (NXDOMAIN). This is an authoritative "no such name" reply, not a
// failure: the crawler routinely probes record types and names that do not exist
// (AAAA on IPv4-only hosts, DNSSEC records on unsigned zones, speculative
// subdomains), so it is logged at debug to keep the warn channel meaningful.
type QueryNoRecords struct {
	Domain string
	Type   string
}

// ToolName returns the tool identifier.
func (QueryNoRecords) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (QueryNoRecords) EventName() string { return "dnsinfo: query no records" }

// EventLevel returns the log severity.
func (QueryNoRecords) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e QueryNoRecords) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
	}
}

// PTRNoRecords is emitted when a reverse DNS (PTR) lookup returns NXDOMAIN. Most
// addresses have no reverse record, so this clean negative answer is logged at
// debug rather than warn.
type PTRNoRecords struct {
	IP string
}

// ToolName returns the tool identifier.
func (PTRNoRecords) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PTRNoRecords) EventName() string { return "dnsinfo: PTR no records" }

// EventLevel returns the log severity.
func (PTRNoRecords) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PTRNoRecords) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP)}
}

// PTRQueryFailed is emitted when a reverse DNS (PTR) lookup fails.
type PTRQueryFailed struct {
	IP  string
	Err error
}

// ToolName returns the tool identifier.
func (PTRQueryFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PTRQueryFailed) EventName() string { return "dnsinfo: PTR query failed" }

// EventLevel returns the log severity.
func (PTRQueryFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PTRQueryFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a reverse lookup failure that has no aggregate
// LookupCompleted event to account for it.
func (e PTRQueryFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return ptrCollectionHealth(e.IP, true)
}

// AXFRFailed is emitted when AXFR fails and IXFR will be tried next.
type AXFRFailed struct {
	Domain     string
	Nameserver string
	Err        error
}

// ToolName returns the tool identifier.
func (AXFRFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (AXFRFailed) EventName() string { return "dnsinfo: AXFR failed, trying IXFR" }

// EventLevel returns the log severity.
func (e AXFRFailed) EventLevel() slog.Level {
	if expectedZoneTransferFailure(e.Err) {
		return slog.LevelDebug
	}
	return slog.LevelWarn
}

// EventAttrs returns the structured key-value pairs for logging and display.
func (e AXFRFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("nameserver", e.Nameserver),
		slog.Any("error", e.Err),
	}
}

// ZoneTransferFailed is emitted when both AXFR and IXFR fail for a nameserver.
type ZoneTransferFailed struct {
	Domain     string
	Nameserver string
	Err        error
}

// ToolName returns the tool identifier.
func (ZoneTransferFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ZoneTransferFailed) EventName() string { return "dnsinfo: zone transfer failed" }

// EventLevel returns the log severity.
func (e ZoneTransferFailed) EventLevel() slog.Level {
	if expectedZoneTransferFailure(e.Err) {
		return slog.LevelDebug
	}
	return slog.LevelWarn
}

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ZoneTransferFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("nameserver", e.Nameserver),
		slog.Any("error", e.Err),
	}
}

// ZoneTransferTargetRejected is emitted when the injected exclusion policy denies a
// zone-transfer destination before any transfer traffic is sent. It is the active
// path's typed policy rejection: a destination named by a hard engagement exclusion
// (the zone, an authoritative hostname, or a nameserver that resolved only to excluded
// addresses) is refused here rather than dialed. Nameserver is empty when the zone
// itself was rejected. It is deliberately distinct from
// ZoneTransferFailed, which records a transfer that was attempted and refused by the
// server; a rejection is never a transfer attempt, a timeout, or a network failure.
// ResolvedIP is the excluded resolved address when the rejection was decided after
// resolution, and empty when the hostname itself matched a domain exclusion.
type ZoneTransferTargetRejected struct {
	Domain     string
	Nameserver string
	ResolvedIP string
	Reason     string
}

// ToolName returns the tool identifier.
func (ZoneTransferTargetRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ZoneTransferTargetRejected) EventName() string { return "dnsinfo: zone transfer target rejected" }

// EventLevel returns the log severity. A policy rejection of an active target is an
// operationally notable decision, so it is logged at warn like a succeeded transfer.
func (ZoneTransferTargetRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ZoneTransferTargetRejected) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("nameserver", e.Nameserver),
	}
	if e.ResolvedIP != "" {
		attrs = append(attrs, slog.String("resolved_ip", e.ResolvedIP))
	}
	return append(attrs, slog.String("reason", e.Reason))
}

// ZoneTransferSucceeded is emitted when a zone transfer returns records.
type ZoneTransferSucceeded struct {
	Domain     string
	Nameserver string
	Records    int
}

// ToolName returns the tool identifier.
func (ZoneTransferSucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ZoneTransferSucceeded) EventName() string { return "dnsinfo: zone transfer succeeded" }

// EventLevel returns the log severity.
func (ZoneTransferSucceeded) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ZoneTransferSucceeded) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("nameserver", e.Nameserver),
		slog.Int("records", e.Records),
	}
}

func expectedZoneTransferFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "refused") ||
		strings.Contains(msg, "not implemented") ||
		strings.Contains(msg, "notimpl") ||
		strings.Contains(msg, "notimp") ||
		strings.Contains(msg, "denied") ||
		strings.Contains(msg, "zone transfer returned no records")
}

// DNSTimeout is emitted when a DNS query times out.
type DNSTimeout struct {
	Domain  string
	Type    string
	Attempt int
	Err     error
}

// ToolName returns the tool identifier.
func (DNSTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSTimeout) EventName() string { return "dnsinfo: DNS timeout" }

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

// CollectionHealth reports a PTR timeout directly. Forward-query timeouts are
// accounted by LookupCompleted and return false here to avoid double counting.
func (e DNSTimeout) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return ptrCollectionHealth(e.Domain, e.Type == ptrRecordType)
}

// DNSServerError is emitted when an upstream DNS server returns SERVFAIL or REFUSED.
type DNSServerError struct {
	Domain string
	Type   string
	Rcode  int
	Err    error
}

// ToolName returns the tool identifier.
func (DNSServerError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSServerError) EventName() string { return "dnsinfo: DNS server error" }

// EventLevel returns the log severity.
func (DNSServerError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSServerError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.Int("rcode", e.Rcode),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a PTR server failure directly. Forward-query failures
// are accounted by LookupCompleted.
func (e DNSServerError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return ptrCollectionHealth(e.Domain, e.Type == ptrRecordType)
}

// DNSRateLimited is emitted when resolver rate limiting or throttling is detected.
type DNSRateLimited struct {
	Domain string
	Type   string
	Err    error
}

// ToolName returns the tool identifier.
func (DNSRateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSRateLimited) EventName() string { return "dnsinfo: DNS rate limited" }

// EventLevel returns the log severity.
func (DNSRateLimited) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSRateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports PTR throttling directly. Forward-query throttling is
// accounted by LookupCompleted.
func (e DNSRateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return ptrCollectionHealth(e.Domain, e.Type == ptrRecordType)
}

// RecordDiscovered is emitted when a valid DNS record is resolved.
type RecordDiscovered struct {
	Domain string
	Type   string
	Value  string
	TTL    uint32
}

// ToolName returns the tool identifier.
func (RecordDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RecordDiscovered) EventName() string { return "dnsinfo: record discovered" }

// EventLevel returns the log severity.
func (RecordDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RecordDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("type", e.Type),
		slog.String("value", e.Value),
		slog.Any("ttl", e.TTL),
	}
}

// ptrCollectionHealth builds the one direct health identity shared by PTR
// failures, which have no aggregate completion event.
func ptrCollectionHealth(target string, failed bool) (tooleventlog.HealthProblem, bool) {
	if !failed {
		return tooleventlog.HealthProblem{}, false
	}
	return tooleventlog.HealthProblem{Code: "dnsinfo.ptr_lookup_failed", Target: target}, true
}

var (
	_ tooleventlog.HealthEvent = LookupCompleted{}
	_ tooleventlog.HealthEvent = PTRQueryFailed{}
	_ tooleventlog.HealthEvent = DNSTimeout{}
	_ tooleventlog.HealthEvent = DNSServerError{}
	_ tooleventlog.HealthEvent = DNSRateLimited{}
)
