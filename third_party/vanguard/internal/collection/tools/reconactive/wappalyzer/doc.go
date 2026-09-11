// Package wappalyzer fingerprints the web technologies a domain runs, using the
// embedded WappalyzerGo fingerprint database.
//
// # Active traffic
//
// This is an active-phase tool: [Client.Probe] connects to the target and issues
// one bounded HTTP GET. It must only run against in-scope, authorized targets,
// behind the orchestrator's scope, reachability, and budget gates. Nothing in this
// package is safe to call during the passive phase.
//
// # Standalone by design
//
// The package imports no other reconactive tool, no orchestration, domain event,
// projection, report, or app package. It owns its HTTP client, its response limits,
// its fingerprint engine, and its tool events, and it works with every other HTTP
// tool disabled. It never consumes another tool's response body or result: a
// technology reported here was observed by this tool's own request. The orchestrator
// is the single translator from [Result] into domain events.
// Result.RedirectTrail is the policy-neutral handoff for redirect decisions; the
// orchestrator publishes it before deciding whether the fingerprint result is usable.
//
// # Request behaviour
//
// Probe tries https://<domain> first and falls back to http://<domain> when an HTTPS
// transport or body-read failure may be scheme-specific. Cancellation, redirect
// limits, and rejected redirects are final and do not cause more traffic. A non-2xx
// status is not a failure: a 401, 403, or 500 response still carries server and
// framework signals, so it is fingerprinted like any other. Redirects are followed up to
// [Config.MaxRedirects] and each hop is emitted; exceeding the cap ends the attempt.
// Every initial and redirect destination is checked through [Config.Allow] before
// traffic is sent. A nil policy preserves standalone behavior. Ambient HTTP proxy variables are ignored, so
// host routing and the configured resolver cannot be silently replaced by process
// environment.
// [Config.Exclusions] extends that boundary through DNS resolution: the owned
// transport dials through one shared resolver-aware policy dialer, so the HTTPS
// attempt, the HTTP fallback, and every redirect resolve a hostname once, drop every
// excluded resolved address, and connect only to an allowed literal (the hostname is
// kept for Host and TLS SNI). A rejection - a domain caught before resolution or an
// all-excluded resolution caught at dial - is terminal: it does not trigger the
// scheme fallback, and it is never reported as a DNS resolution failure or a
// connection timeout. A nil Exclusions excludes nothing; production injects the
// engagement exclusions.
// The response body is read through a hard [Config.MaxBodyBytes] cap, so a hostile or
// endless body cannot exhaust memory.
//
// TLS certificates are not verified. This is reconnaissance, not a trust decision:
// an expired or self-signed certificate must not hide the technologies behind it, and
// certificate validity is the sibling https tool's subject. A genuine handshake
// failure (protocol mismatch, reset during handshake) still emits
// [TLSHandshakeFailed].
//
// # Fingerprint database
//
// The engine compiles the fingerprint database embedded in the WappalyzerGo library
// once, in [New]. There is no runtime download and no custom fingerprint file, so a
// scan is reproducible and local-first: the same binary against the same response
// always yields the same technologies. Upstream returns matches as an unordered map
// keyed "name" or "name:version", so the adapter parses the version out, drops the
// map order, and sorts by name then version. Categories and CPEs are sorted and
// deduped. Upstream's icon, website, and description are deliberately discarded:
// they are catalogue decoration, not scan facts.
//
// Some upstream rules capture hexadecimal cache-busting asset hashes as versions.
// The adapter drops a plain 7-40 character hexadecimal value: it identifies one
// asset, not a software release, and treating it as a version creates false
// version-disclosure findings.
//
// Evidence is the honest constant [EvidenceSignature]. The upstream API reports that
// a fingerprint matched, not which rule matched or with what confidence, so this
// package does not invent either.
//
// # Privacy
//
// No cookie value or body byte leaves this package. Events carry the URL, status,
// response header *names*, body byte count, and technology metadata only. [Result]
// also carries Server and WWW-Authenticate values: both are server-advertised
// endpoint metadata needed by the translator, not user data. The body is discarded
// once fingerprinting is done.
//
// # Events
//
// [ProbeStarted] and [ProbeCompleted] bracket every valid-host probe;
// ProbeCompleted reports the match count, so a clean empty result is distinguishable
// from a failure on replay.
// [RedirectFollowed] and [TechnologyDiscovered] report progress.
// Every error emits a granular event - [DNSResolutionFailed], [ConnectionTimeout],
// [ConnectionRefused], [TLSHandshakeFailed], [BodyReadFailed],
// [RedirectLimitReached], [RedirectRejected], [RateLimited] - with [ProbeFailed] as
// fallback for errors none of those classify. A probe failure is fatal to the probe
// and non-fatal to the scan; a constructor failure is fatal and is never swallowed.
package wappalyzer
