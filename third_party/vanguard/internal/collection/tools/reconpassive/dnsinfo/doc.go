// Package dnsinfo provides a DNS lookup client that resolves common record
// types (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, DNSKEY) for a domain and
// exposes a separate AXFR/IXFR method. DNS lookup and PTR collection are passive;
// [Client.ZoneTransfer] directly contacts authoritative infrastructure and callers
// must gate and label it as active reconnaissance. [Client.LookupPTR] also resolves
// one explicitly supplied address for provider-host ownership corroboration. Typed
// events are emitted via a caller-supplied tooleventlog.EventSink.
//
// The passive and active paths differ in one further way: only the active
// [Client.ZoneTransfer] takes a hard exclusion policy. Lookup and LookupPTR send no
// target traffic to a scanned estate and are policy-neutral, so their behavior is
// unchanged whether exclusions are present or not. ZoneTransfer, which opens a TCP
// connection to authoritative infrastructure, accepts a *scopecheck.Exclusions: when
// non-nil it refuses an excluded authoritative hostname or literal before any dial,
// resolves each retained hostname once through the configured resolver, drops every
// excluded resolved address, and dials only an allowed literal - so no transfer can
// reach an excluded zone, nameserver name, or nameserver address, and a refused
// destination is a typed ZoneTransferTargetRejected rather than a transfer failure.
// Each denied zone, nameserver name, or resolved address is also reported through
// the scopecheck rejection sink carried by the context, allowing orchestration to
// project the exact destination and matched rule into its exclusion ledger.
// The engagement's root/include boundary is deliberately not applied to a
// nameserver: an allowed zone may be served by another provider's domain, while an
// explicit exclusion still wins. A nil policy keeps the standalone behavior for
// library and test callers; production orchestration always injects one.
//
// Typical usage:
//
//	c, err := dnsinfo.New(dnsinfo.Config{
//	    Resolver: "8.8.8.8:53",
//	    Timeout:  5 * time.Second,
//	    Sink:     sink,
//	})
//	records, err := c.Lookup(ctx, "example.com")
//	// Only from an explicitly enabled active phase, with the engagement exclusions:
//	zone, err := c.ZoneTransfer(activeCtx, "example.com", records.NS, exclusions)
//
// Negative answers are distinguished from real failures. An NXDOMAIN reply (and
// a NODATA reply, which is rcode SUCCESS with an empty answer) is the expected
// common case when probing record types or speculative names that do not exist,
// so it is reported via the debug-level QueryNoRecords / PTRNoRecords events
// rather than error-level failures.
//
// As individual DNS records are resolved, debug-level RecordDiscovered events
// are emitted. When queries fail, granular error events are emitted:
// DNSTimeout for timeouts, DNSServerError for SERVFAIL/REFUSED replies, and
// DNSRateLimited for throttling or rate-limiting signals. Unclassified errors
// emit QueryFailed or PTRQueryFailed.
//
// When Lookup finishes, an info-level LookupCompleted event summarizes record
// counts, total queries, failed queries, and whether execution was degraded
// (some record types failed while others succeeded).
// [LookupCompleted] implements [tooleventlog.HealthEvent] only when its failed
// query count is positive. The aggregate owns forward-query collection health so
// the granular DNS diagnostics are not counted again. [Client.LookupPTR] has no
// aggregate completion, so its [PTRQueryFailed], [DNSTimeout], [DNSServerError],
// and [DNSRateLimited] outcomes report one direct PTR health problem. NXDOMAIN,
// NODATA, PTR absence, expected zone-transfer refusal, and scope rejection remain
// health-neutral.
package dnsinfo
