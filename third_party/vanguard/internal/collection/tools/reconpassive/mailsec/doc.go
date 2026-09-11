// Package mailsec probes a domain's email-security posture: MX, SPF, DMARC,
// DKIM, BIMI, and MTA-STS DNS records.
//
// It follows the project's tool convention: [Client] is built from a validated
// [Config] (resolver and timeout, like dnsinfo) and does work through
// [Client.Lookup], emitting typed [tooleventlog.Event] values (see events.go).
// Individual record failures are reported as events and skipped, so partial
// results are still returned. Granular DNS failures such as UDP/TCP timeouts
// ([DNSTimeout]) and server errors like SERVFAIL/REFUSED ([DNSServerError]) are
// distinguished from generic query failures. Each discovered policy is evaluated
// and emitted via [PolicyDiscovered] with strictness levels (Reject, Quarantine,
// None). Syntax validation errors (e.g. missing required DMARC/BIMI tags) emit
// [RecordParseError] and mark the inspection degraded. Lookup returns the tool's
// own [MailRecords], and [LookupCompleted] reports quantitative query counters
// and the final degraded state. The orchestrator translates [MailRecords] into a
// domain event.
// [LookupCompleted] implements [tooleventlog.HealthEvent] only when its failed DNS
// query count is positive. The aggregate owns collection health so granular DNS
// failures are not counted twice. Missing records and malformed target-owned SPF,
// DMARC, BIMI, DKIM, or MTA-STS data remain findings or diagnostics, not collector
// degradation.
//
// Each DNS query retries a transient failure (network/timeout error, or a
// server-side SERVFAIL/REFUSED) up to Config.MaxRetries times with an exponential
// backoff (BackoffMin doubling per attempt, capped at BackoffMax), honouring the
// context. Without this a single UDP timeout on the MX query would report MX 0 for
// a live mail domain. A definitive result (NXDOMAIN, or a success) is never
// retried; absent mail records are normal. Each retry emits a QueryRetried event.
// This mirrors the asn tool's retry (the two are separate arch components and
// cannot share a helper).
// MaxRetries uses the shared limit encoding: zero means no retries, minus one
// retries until context cancellation, and a positive value is finite.
//
// DMARC results carry a severity derived from the p= tag so monitoring-only
// policies stand apart from quarantine or reject enforcement. SPF analysis
// recursively follows include: and redirect= chains, tracking worst-case DNS
// lookup and void counts across the full chain; macro-containing targets (e.g.
// %{i}) cannot be resolved statically and are reported as warnings.
package mailsec
