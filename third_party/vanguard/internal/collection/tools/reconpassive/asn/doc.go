// Package asn provides a client for resolving IP addresses to their
// Autonomous System Number (ASN) and BGP prefix information via Team Cymru's
// DNS-based lookup service. Typed events are emitted via a caller-supplied
// tooleventlog.EventSink.
//
// Each lookup makes two UDP TXT queries (origin, then AS name). A single UDP
// query against a busy resolver can time out for one IP while every other lookup
// in the run succeeds, silently losing that IP's ASN/netblock data. So a
// transient failure (network/timeout error, or a server-side SERVFAIL/REFUSED) is
// retried up to Config.MaxRetries times with an exponential backoff
// (BackoffMin doubling per attempt, capped at BackoffMax), honouring the context.
// A definitive negative (NXDOMAIN, or a successful response with no TXT answer) is
// a real "no data" and is returned immediately, never retried. Each retry emits a
// LookupRetried event so the recovery is visible in the tool-event stream.
// MaxRetries uses the shared limit encoding: zero means no retries, minus one
// retries until context cancellation, and a positive value is finite.
//
// Granular operational error events such as DNSTimeout and DNSResolutionFailed
// are emitted when DNS failures occur, while OriginParseFailed and NameParseFailed
// report formatting or parsing discrepancies along with raw record payloads.
// Every lookup cycle concludes with a LookupCompleted summary event reporting
// operational metrics including query counts, retries, and degradation status.
// [LookupCompleted] implements [tooleventlog.HealthEvent] only when its failure
// count is positive. The aggregate owns health classification so retry and parsing
// diagnostics are not counted twice; a lookup that recovers after retry remains
// healthy.
//
// Typical usage:
//
//	c, err := asn.New(asn.Config{
//	    Resolver:   "8.8.8.8:53",
//	    Timeout:    5 * time.Second,
//	    MaxRetries: 2,
//	    BackoffMin: 200 * time.Millisecond,
//	    BackoffMax: 2 * time.Second,
//	    Sink:       sink,
//	})
//	record, err := c.Lookup(ctx, "1.2.3.4")
package asn
