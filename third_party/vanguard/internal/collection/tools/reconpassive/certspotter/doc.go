// Package certspotter queries the SSLMate certspotter API, a second Certificate
// Transparency aggregator.
//
// It exists for one reason: completeness insurance for the passive phase. crt.sh
// is the sole certificate/subdomain source the crawler walks, and under load crt.sh
// can return HTTP 200 with a truncated certificate set - a silent partial answer
// indistinguishable from a complete one. certspotter is an independent CT
// corroborator: the orchestrator compares the distinct subdomain count crt.sh
// discovered against the count certspotter reports for the same root, and raises a
// coverage IssueObserved when crt.sh is materially short (see the orchestration
// cross-check). Because both sources read the same underlying CT logs, a large
// shortfall on crt.sh's side is a genuine truncation signal rather than the
// expected over-counting a multi-source enumerator (subfinder) would show.
//
// The names certspotter finds are also fed into the discovery pipeline as ordinary
// subdomains (Source = certspotter), so they enrich the asset graph and appear in
// the data-quality subdomains comparison alongside crtsh/subfinder/virustotal.
//
// Beyond the aggregate cross-check, the Client answers a per-query presence question
// via Certs: did certspotter see any current issuance for this exact domain,
// independent of the in-scope name filter? This is the live-cert corroborator for a
// degraded-empty crt.sh answer (a clean HTTP 200 with no names during a crt.sh backend
// outage): any issuance certspotter returns proves the host is not certless, so the
// outage is distinguished from a genuine empty. Because certspotter serves only
// currently-valid certificates, a "no issuance" answer is soft - it cannot see an
// expired-only history - so a full-history source carries more weight when both run.
//
// The Client follows the standard tool shape: a Config, the Subdomains and Certs
// methods, and typed events in events.go. The API token (CERTSPOTTER_API_KEY) is optional - the
// public endpoint serves unauthenticated queries at a lower rate limit - so the
// tool is never gated on a key; a failed query (auth wall via [PaidPlanRequired],
// rate limit via [RateLimited], or network error) emits a granular tool event and
// is non-fatal, simply leaving that run without a cross-check. During extraction,
// [CertDiscovered] is emitted for each batch of SANs, and [SearchCompleted]
// reports summary counts and truncation state when the query finishes.
// Those terminal provider failures implement [tooleventlog.HealthEvent], allowing
// collection to distinguish lost evidence from a successful empty or configured
// truncation without parsing log text. [SearchCompleted] itself remains neutral so
// the same failed query is not counted twice.
package certspotter
