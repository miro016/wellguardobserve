// Package webinfo probes a domain's web presence via active HTTP connections.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Probe], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome. Probe
// performs a redirect-following HTTP(S) probe to capture the final response
// metadata (status, server, headers, TLS) and fetches the home page to detect the
// technology stack (CMS, plugins, JS/CSS libraries, CDN, hosting, and external
// services), returning a [Result]. It also flags [Result.LoginForm] when the
// fetched body has a password input ([HasPasswordInput]), a login-surface signal
// the orchestrator combines with the WWW-Authenticate/401 headers; no extra
// request is made.
// Result.RedirectTrail is the policy-neutral handoff for redirect decisions from
// both HTTP requests. The orchestrator publishes it before using response-derived
// endpoint or technology data.
// Every initial and redirect destination is checked through [Config.Allow] before
// traffic is sent. Policy rejections are counted separately from network failures
// and timeouts in ProbeCompleted.
//
// [Config.Exclusions] extends that boundary through DNS resolution. Both the HEAD
// metadata request and the GET page fetch, and every redirect in either chain, dial
// through one shared resolver-aware policy dialer that resolves a hostname once,
// drops every excluded resolved address, and connects only to an allowed literal
// (the hostname is preserved for the Host header and TLS SNI). Ambient proxy
// discovery is disabled so a process proxy cannot resolve or connect to a rejected
// destination. A rejection - a domain caught before resolution or an all-excluded
// resolution caught at dial - is counted as a policy rejection, never a fetch failure
// or timeout, and it does not trigger the HTTPS-to-HTTP fallback or a second request
// that would bypass it. A nil Exclusions excludes nothing (standalone use); production
// injects the engagement exclusions.
//
// TLS certificate enumeration is handled by the sibling https package; SEO
// analysis is intentionally out of scope.
//
// Lifecycle and operational events report detailed execution progress and health:
//   - ProbeStarted (with initial URL count) and ProbeCompleted bracket every probe.
//     ProbeCompleted reports summary metrics (TotalUrls, SuccessfulFetches,
//     FailedFetches, Timeouts) and a Degraded flag if any HTTP fetch failed or timed out.
//   - TechnologyDiscovered logs each distinct technology stack item identified.
//     The HTML syntax check treats inline script/style bodies as raw text, so a
//     bare "<" inside minified JavaScript no longer degrades stack detection.
//   - Granular operational events (RateLimited, WAFBlocked, RedirectLoopDetected,
//     HTMLParseError) pinpoint specific protocol and parsing anomalies without failing
//     the scan.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into HttpEndpointDiscovered (the HTTP
// probe) and TechnologyFingerprinted (the detected stack).
//
// [StackResult] fields are display strings that may carry a version inline
// ("Microsoft-IIS/10.0", "WordPress 7.0.3") because [DetectStack] reads them straight
// out of headers and body markers. The translator splits the version back out before
// building an event; a name carrying its own version cannot be matched against the
// same product reported by another tool.
//
// [Config.ResolverAddr] points name resolution (every redirect hop included) at a
// specific DNS server so active resolution matches the passive phase, removing the
// divergence where the passive phase resolves a name the active probe then fails
// to look up. Empty uses the system resolver.
package webinfo
