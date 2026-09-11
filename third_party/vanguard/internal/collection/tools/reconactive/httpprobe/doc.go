// Package httpprobe provides active HTTP(S) reachability probing and banner grabbing.
//
// The Client issues GET requests against single URLs or concurrent batches of URLs
// with overall timeouts and capped body reads. It follows redirects up to
// [Config.MaxRedirects], emitting RedirectFollowed or RedirectRejected events so
// redirect chains and policy decisions remain fully observable. Every initial and
// redirect destination is authorized through [Config.Allow] before traffic is sent.
// Response.RedirectTrail is the policy-neutral handoff for those decisions. It is
// consumed before any final-response endpoint event is translated.
//
// The client emits comprehensive system events to an EventSink for operational
// observability:
//   - Lifecycle and summary: ProbeStarted, ProbeCompleted (including Degraded status)
//   - Discovery: ProbeSucceeded, RedirectFollowed
//   - Granular operational failures: ConnectionTimeout, DNSResolutionFailed,
//     ConnectionRefused, TLSHandshakeFailed, RateLimited, WAFBlocked, and fallback
//     ProbeFailed.
//
// Probe verifies TLS certificates. ProbeInsecure skips verification and is for
// HTTPS probes against a bare IP literal, where a valid public certificate has no
// IP SAN and standard verification always fails. That is a reconnaissance dial to
// read status and headers, not a trust decision.
//
// The hostname authorization in [Config.Allow] is only the first half of the
// boundary: it decides a destination by name before resolution. [Config.Exclusions]
// is the second half, enforced at dial time. Both the secure and insecure transports
// dial through one shared resolver-aware policy dialer that resolves a hostname once,
// drops every excluded resolved address, and connects only to an allowed literal,
// while the original hostname is preserved for the HTTP Host header and TLS SNI. An
// all-excluded resolution is a typed policy rejection (surfaced as ProbeFailed or
// RedirectRejected with the reason), never a DNS or connection failure, and no scheme
// fallback or insecure path bypasses it. Ambient proxy discovery is disabled on both
// transports so a process proxy cannot resolve or connect to a rejected destination.
// A nil Exclusions excludes nothing, for standalone use; production injects the
// engagement exclusions.
//
// This is active reconnaissance: it sends traffic to the target. It must only be
// run when the active phase is explicitly enabled.
package httpprobe
