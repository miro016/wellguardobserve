// Package censys queries the Censys GlobalData search platform for the hosts
// associated with a domain, using the official censys-sdk-go library to run CenQL
// queries against the GlobalData Search API.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and exposes two API calls: [Client.Search] for host discovery
// and [Client.Certificates] for certificate-transparency history. Both emit typed
// [tooleventlog.Event] values for every notable outcome, with separate event types
// per API call for easier operational rollup and maintenance (see search_events.go
// and certificates_events.go).
//
// # File layout
//
//   - client.go: [Config], [Client], [New], shared types (searcher interface,
//     rawHit, rawCertHit), error-classification helpers, and small utilities.
//   - search.go: [Client.Search], host types ([HostResult], [DomainHosts]),
//     paging (searchAll), deduplication, and merge logic.
//   - search_events.go: events emitted by [Client.Search] -- [SearchStarted],
//     [SearchQuerySucceeded], [SearchQueryFailed], [SearchPaidPlanRequired],
//     [SearchRateLimited], [SearchHostDiscovered], [SearchCacheHit],
//     [SearchCacheMiss], [SearchCompleted].
//   - certificates.go: [Client.Certificates], certificate types ([CertResult],
//     [DomainCertificates]), paging (searchAllCerts), SAN filtering, and error
//     handling.
//   - certificates_events.go: events emitted by [Client.Certificates] --
//     [CertSearchStarted], [CertQuerySucceeded], [CertQueryFailed],
//     [CertPaidPlanRequired], [CertRateLimited], [CertCacheHit], [CertCacheMiss],
//     [CertSearchCompleted].
//   - sdk.go: real Censys SDK adapter ([sdkSearcher]), retry configuration,
//     in-flight concurrency cap, and SDK response extraction helpers.
//   - cache.go and cache_data.json: the embedded development result fixture, its
//     construction-time validation, and its exact-key lookups.
//
// # Modes
//
// [Config.Mode] is the single switch for the tool; there is no separate enable flag,
// so a mode and a flag can never disagree. [New] dispatches on it:
//
//   - [ModeDisabled]: Censys does not run. No client is constructed (asking [New] for
//     one is a configuration error), no tool log is opened, nothing is scheduled.
//   - [ModeEnabled]: queries the Censys API. Requires Config.APIKey and spends the
//     caller's paid-request budget. The embedded fixture is not consulted at all.
//   - [ModeEmbeddedCacheOnly]: answers from the embedded fixture and never reaches
//     Censys. This is a hard no-network contract: no SDK searcher is built, no API
//     key is required, no paid request is consumed, and a lookup miss stays a miss.
//     There is no fallback to the API for any reason - not a missing domain, not a
//     key that happens to be set, not budget state.
//
// Every result and every terminal event states its retrieval provenance:
// [DomainHosts.RetrievalSource] and [DomainCertificates.RetrievalSource] carry
// "service" or "cache_embedded", [SearchCompleted] and [CertSearchCompleted] expose
// the same value as a retrieval_source attribute, and [SearchCacheHit],
// [SearchCacheMiss], [CertCacheHit], and [CertCacheMiss] make the lookup decision
// itself visible. The strings mirror the events package's RetrievalSource vocabulary,
// which this package cannot import; the orchestrator's translator copies the value
// onto the domain event, leaving the provider attribution ("censys") unchanged.
//
// A cache-only miss returns no result at all (a nil [DomainHosts] or
// [DomainCertificates] with a nil error) after emitting a cache-miss event. That is
// deliberately neither an empty result - which would record an authoritative "Censys
// knows nothing here" observation that was never made - nor an error, since nothing
// failed. [Mode.Enabled] reports whether a mode runs the tool at all;
// [Mode.UsesService] reports whether it reaches the API, and gates the key
// requirement and the paid budget.
//
// # Embedded development cache
//
// The package owns a compiled-in fixture of Censys results (cache_data.json,
// embedded with go:embed) so local development and repeatable tests do not depend
// on Censys availability or spend paid requests. It is a development fixture, not a
// production cache: it has no TTL, refresh, write-through, invalidation, or
// persistence, and the deployed collector reads no cache directory, environment
// override, or runtime path of any kind. Adding results means editing
// cache_data.json and recompiling the collector.
//
// The fixture stores result values only, never saved event envelopes: replaying an
// envelope would leak an old scan id, event id, causation id, correlation id,
// sequence number, and capture time into a new scan. Provider-supplied observation
// times (a service's Censys scan_time, a host's network allocation date) are part of
// the result and are preserved; the surrounding operational and domain events are
// created fresh on every run as usual.
//
// The data is keyed in two independent maps, both by the normalized domain (trimmed
// and lowercased, exactly as [Client.Search] and [Client.Certificates] normalize
// their argument): host searches and certificate-history searches. Lookup is an
// exact in-memory map access with no partial matching and no synthesized answer, so
// an uncached domain is a plain miss. Certificate history is currently empty: crt.sh
// answered for the staged domains, so Censys certificate history was never queried
// and a cache-only history lookup always misses. The current host coverage is
// vissim.no (13 hosts, 50 services) and vissim.tech (2 hosts, 9 services).
//
// The embedded data is decoded as exactly one JSON value and validated when a
// cache-using Client is constructed, so malformed or trailing JSON, an empty or
// unnormalized key, a key that disagrees
// with the stored domain, an unparseable or duplicated host IP, a certificate
// without a fingerprint or listed twice, and an inverted validity window all fail
// fast rather than mid-scan. After construction the parsed data is read-only, so it
// needs no lock, and every lookup returns a deep copy: a caller that mutates a
// result cannot affect a later lookup. Config.MaxHosts is applied to a cached host
// result exactly as it is to a live one, marking the returned copy truncated when
// the cap drops hosts.
//
// # Host search (Search)
//
// [Client.Search] returns discovered hosts as a [DomainHosts] value; each
// [HostResult] carries the services, ASN, location, OS, the software products and
// known CVEs Censys attributes to the host's services, the host-level reputation
// verdict and labels Censys already includes in a search hit, and the queries that
// matched it ("dns", "tls_cert"). This supports comparing tool coverage across
// data providers and lets Censys contribute CVE, software, and reputation
// intelligence alongside shodan and netlas without any extra per-host enrichment
// call: the reputation and labels are extracted from the same search response, not
// fetched separately.
//
// Two queries run per domain, each tried independently so a wall on one does not
// starve the other:
//   - host.services.cert.names: hosts serving a certificate whose SANs include the
//     domain (the leaf certificate on a service, components.Service.Cert.Names)
//   - host.dns.names: hosts with matching DNS forward/reverse names
//
// Results are deduplicated by canonical IP and services are merged across
// queries; when both queries return the same service, its newest scan_time is
// retained. A service is identified by port, application protocol, and transport
// together, so a host answering on tcp/53 and udp/53 keeps two services rather
// than one: the transport is what Censys observed, and merging on the port number
// would destroy it. Transport is normalized to lower-case "tcp" or "udp" as the
// hit is read; any other value Censys reports, including none at all, is left
// empty and means unknown. It is never defaulted to tcp, and the application
// protocol ("DNS", "HTTP") is never read as transport evidence. Service scan_time values are preserved through the domain event so the
// facts graph can date each service and span its host from the earliest to latest
// Censys observation. The host's whois.network allocation date (created) and CIDRs
// ride along in the same search hit and are carried on [HostResult] so the facts graph
// can date the host's provider at network allocation rather than only at the scan
// snapshot. Only the GlobalData.Search endpoint is called, which is
// available on all Censys tiers. The SDK client is built once and configured to retry HTTP 429
// (the Platform's concurrent-request limit, "too many active requests") and 5xx
// with bounded exponential backoff, and to time out a stalled request; a
// scan-wide in-flight cap keeps the tool under the concurrency limit. A genuine
// 403 (a wallet/entitlement wall) is reported via a [SearchPaidPlanRequired] event
// per query, and Search only reports the tool unavailable (stopping Censys for the
// rest of the scan) once every query type attempted in a call has come back 403 -
// a key missing one entitlement keeps using the other. An "insufficient balance"
// response (an empty query wallet, HTTP 422) is a whole-account wall, so the first one
// is reported via a [SearchInsufficientBalance] event and immediately marks the tool
// unavailable for the rest of the scan (no point retrying a depleted wallet). A terminal
// 429 (retries exhausted) is reported via a [SearchRateLimited] event. No
// enterprise/Censeye features are used.
//
// Terminal host and certificate query failures implement
// [tooleventlog.HealthEvent]. Each problem uses the fixed query label as its
// component and excludes CenQL text, response bodies, and SDK error text. Cache-only
// misses, honest empty results, and configured truncation remain health-neutral.
// Completion events do not repeat granular query failures.
//
// # Certificate-transparency history (Certificates)
//
// Alongside the host search, [Client.Certificates] queries the certificate_v1 index
// (cert.names: "<domain>") rather than the live hosts dataset. This is the
// independent CT-history source the degraded-empty corroboration needs: it returns
// certificates a domain ever presented, including expired ones, so it can confirm a
// crt.sh degraded-empty even for a host whose certificates are all historical - the
// case the current-only certspotter source cannot cover. It returns a
// [DomainCertificates]: presence (any certificate_v1 hit, before the in-scope SAN
// filter), the distinct in-scope SANs, and per-certificate metadata (fingerprint,
// common name, issuer, serial, validity) sufficient to backfill a certificate record.
// It reuses the same endpoint, auth, retry, in-flight cap, and 403/429 handling as
// Search; being a paid call, the orchestrator invokes it only on a degraded-empty
// query and under its paid budget.
//
// # Authentication
//
// [ModeEnabled] requires a Censys Personal Access Token. The token is a secret, so
// the app injects it from the CENSYS_API_KEY environment variable onto Config.APIKey
// rather than reading it from the audit configuration file; construction fails when
// service mode is selected without it. [ModeEmbeddedCacheOnly] requires no token and
// cannot use one even when it is present.
//
// Config.OrgID (the SDK's organization_id parameter) is optional but strongly
// recommended: without it, Censys processes requests against the authenticated
// user's free wallet, which is what returns a 403 ([SearchPaidPlanRequired]) on
// query types that require organization credits even though the account has them.
// The app injects it from the CENSYS_ORG_ID environment variable, same as the key.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into CensysHostsDiscovered domain events.
package censys
