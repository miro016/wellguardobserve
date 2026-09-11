// Package orchestration provides coordination of various tool actors.
//
// [FromConfig] maps a validated config.Config (see internal/collection/config) into a
// Config; it lives here, not in config, so config has no dependency on
// orchestration or any tool package. Callers must validate the source config
// first (Config.Validate then Config.ValidateAPIKeys) - FromConfig dereferences
// required pointers and assumes any enabled paid tool already has its key.
//
// It serves as the main entry point for running multi-stage reconnaissance,
// chaining outputs of tools like crtsh to inputs of tools like dnsinfo. It is the
// single translator from tool/system events into domain events, stamping each
// with EventMeta (ScanID, Source, Phase, CausationID).
//
// # Toolset and wiring
//
// To keep the Orchestrator struct focused on state and execution coordination,
// tool client instances are grouped into an unexported toolset struct (toolset.go)
// and initialized together via newToolset. The mapping from external file
// configuration (config.Config) to the orchestrator's internal Config lives in
// wiring.go (FromConfig). This separation simplifies client lifecycle management
// while preserving the orchestrator's role as the composition root and single
// translator.
//
// A client is built only for an enabled tool, so a disabled tool is inert. An
// enabled tool whose constructor fails is a configuration error, not a runtime
// degradation: newToolset returns it named with its tool, New stores it on the
// Orchestrator, and Run refuses to start on it - before a lifecycle
// event is emitted or a single request is sent. A silently nil client would let the
// whole scan run and report a clean result for work that never happened.
//
// Each active per-domain tool is gated on its own client alone. In particular the
// wappalyzer fingerprint probe reads no other HTTP tool's flag and none reads it, so
// it runs standalone or beside https/webinfo/httpprobe without duplicating or
// suppressing them.
//
// # crt.sh and Censys modes
//
// Config carries no EnableCrtsh or EnableCensys flag. Each of those two tools is
// controlled solely by the mode in its own tool config - Config.Crtsh.Mode and
// Config.Censys.Mode - because each has a third behaviour beyond on/off: results
// compiled into the tool package as a development fixture. FromConfig converts the
// validated config strings into crtsh.Mode and censys.Mode, and the mode is then the
// single authority at every boundary:
//
//   - construction and scheduling: newToolset builds a client when Mode.Enabled(),
//     so a disabled tool is inert exactly as a false flag made it. Censys cache-only
//     construction needs no API key; the service mode still does.
//   - paid budget: takeCensysPaidBudget spends the paid-lookup budget only when
//     censys.Mode.UsesService(). Cache-only host searches and degraded-empty
//     certificate corroboration both cost nothing, so neither is throttled by the
//     budget nor decrements it.
//   - enumeration sources: both non-disabled crt.sh modes enumerate subdomains, so
//     both arm the discovery-collapse guard (hasEnumerationSource).
//
// A cache-only Censys lookup that misses returns no result at all rather than an
// empty one, so spawnCensys publishes no domain event and the corroboration counts
// Censys as a source it could not consult. An invented empty would assert an
// observation Censys never made.
//
// # Translation layer
//
// The mechanical mapping from a tool's result type to the domain events it
// produces lives in the internal/collection/orchestration/translate subpackage, not here.
// Each translate function is pure - it takes a tool result plus the identity the
// orchestrator threads in (ScanID, CausationID, ToolCorrID) and returns typed
// events - which keeps this package focused on the scheduling, concurrency,
// budget, scope, and lifecycle logic. The orchestrator stays the single place
// that decides what to emit and that raises the control-plane events itself
// (coverage, scope, budget, circuit-breaker, reachability, and the lifecycle
// brackets); translate owns the per-tool Source labels (translate.Source*), which
// the orchestrator aliases and reuses as the tool name in its correlation IDs so
// the call tag and the event source share one definition.
//
// # One scheduled, bounded-concurrency pipeline (no phase split)
//
// There is no hard passive-then-active phase boundary. Run starts the discovery
// sources and then waits once (o.wg.Wait) for the whole pipeline to drain. The
// work in between is scheduled as its inputs land, all under a single
// sem/wg concurrency limiter:
//
//   - Discovery sources (crt.sh crawler, certspotter, subfinder, the VirusTotal
//     subdomain pass, websearch dorks) feed the same per-domain passive fan-out:
//     spawnDns/spawnWhois/spawnMailsec plus the paid lookups (fanOutPaid).
//   - When a domain's DNS lookup finishes, spawnDns immediately schedules that
//     domain's active probes (scheduleDomainProbe: https/smtp/webinfo/wappalyzer)
//     and any explicitly enabled AXFR check (scheduleZoneTransfer),
//     gated by scope, budget and reachability - it no longer waits for all discovery.
//   - When a new IP is recorded, spawnAsn immediately schedules that IP's active
//     port scan + HTTP probe (scheduleHostScan), independent of the ASN lookup.
//     Port scans also take a dedicated host slot, keeping their per-runner packet
//     rate and aggregate concurrency explicit without consuming every shared slot.
//
// The active schedulers run inside goroutines that already hold a sem slot, so
// they acquire their own slot inside the freshly launched child (never two at
// once) to avoid a hold-and-wait deadlock at low MaxConcurrency; wg.Add runs in
// the parent so every child is counted against the single end-of-run barrier. The
// active-host budget is therefore consumed in arrival (DNS-completion) order,
// which is roughly shallowest-first because the crawler discovers breadth-first.
// EventMeta.Phase still tags each event passive or active for grouping and the
// audit join; only the PhaseStarted/PhaseCompleted lifecycle events are gone.
//
// Several independent subdomain sources feed the same per-domain fan-out: the
// crt.sh crawler, the certspotter second Certificate Transparency source, and
// subfinder (which aggregates many third-party passive sources). When Vanguard's
// own VirusTotal subdomain pass is enabled, FromConfig withholds the VirusTotal
// key from subfinder so one scan never spends VT quota on the same root through
// both paths. FromConfig is the policy authority for that decision, so it hands
// subfinder both the keys and a subfinder.ProviderStatus per keyed source
// (subfinderProviderPolicy): a withheld key is declared handled elsewhere and names
// the owning Vanguard tool, and only a key the policy asked for and does not have
// is declared missing. Without that declaration the tool sees an empty key map and
// reports deliberate policy as an absent credential. Ambient host provider config
// stays forbidden either way: Vanguard config is the single source of truth, so a
// scan behaves identically on a developer machine and a fresh server.
// Each discovered domain event is stamped with its discovery source
// (DnsDomainNameDiscovered.DiscoverySource) and its producing tool
// (EventMeta.Source); a name found by several tools accumulates provenance from
// each, so multi-tool coverage is preserved.
//
// # Provider-only hosts rejoin the asset graph
//
// A Censys/Shodan/Netlas host whose IP the domain's own DNS never resolved is not
// just a display facet: spawnCensys/spawnShodan/spawnNetlas (spawn.go), after
// publishing their *HostsDiscovered facet, call ingestProviderHosts with the
// facet's host IPs. It maps them to inferred IPAddressDiscovered events (Source
// the provider, Confidence inferred, RecordType empty - translate.
// ProviderIPAddresses), publishes them (so the IP becomes a first-class
// Inventory.IPs node, appears in entity_IPAddress.json, and gets HostView's
// Version/Confidence), and runs the same ASN lookup the DNS path uses, so a
// provider-only host also gets ASN/netblock attribution. Which of the two callers
// makes that one lookup depends on whether the corroboration collector runs at all:
// under the corroborated policy with the active host tools enabled the collector
// needs the prefix synchronously and owns the call, and in every other case -
// including a passive-only execution under that policy - ingestProviderHosts calls
// lookupASNs itself, so passive attribution never depends on active tooling. Either
// way the run makes exactly one lookup per address: handleProviderHost is told
// whether the prefix is still owed (providerState.hasNetblock), and an address this
// run already enriched is not looked up again.
// When DNS confirms a provider-registered address before corroboration is
// queued, the confirmed shortcut completes the provider-owned ASN lookup before it
// schedules the host; DNS cannot consume registration ownership and make both paths
// skip enrichment. A later DNS resolution of the same address never downgrades it:
// Inventory.applyIPAddress
// keeps the strongest Confidence seen regardless of arrival order.
//
// This means the IP registration set (targetState, via registerIPs) now has two
// producers - spawnDns and the three provider spawns - both funnelled through the
// same registerIPs/lookupASNs helpers spawnAsn uses. Because of that, the active
// host scan cannot be gated on registration newness any more: whichever source sees
// an IP first would silently suppress the other's scan (in particular, a provider
// registering an IP first must never suppress the DNS-confirmed scan of the same
// address). The host-scan claim (targetState workHostScan) is the separate,
// dedicated scan dedup for this reason - claimed inside scheduleHostScan itself,
// before it takes active-host budget, so every caller (spawnAsn calls
// scheduleHostScan for every resolved IP, new or already-seen, and the provider path
// calls it for an approved candidate) shares one dedup no matter which source
// registers an IP first. It is not authorization state: only approvedIPs, recorded after the
// budget gate and persisted as ActiveTargetApproved, means an address may receive
// target-facing traffic.
//
// ingestProviderHosts passes every result to handleProviderHost, which applies the
// three-state ProviderHostProbePolicy. never records a skip; always trusts the
// provider assertion; corroborated waits for independent ownership evidence: an
// in-scope PTR, a routed prefix that also contains a DNS-confirmed estate address,
// or an in-scope DNS SAN returned by one TLS handshake to port 443 using the
// provider-attributed name as SNI. The certificate preflight makes no HTTP request
// and performs no protocol sweep. Passive PTR/ASN checks run first, and the final
// decisions wait until the passive work drains so a late DNS/ASN result cannot make
// the verdict depend on goroutine order. Every allow or skip emits one auditable
// Source "provider-probe" IssueObserved with the concrete reason.
//
// Only approved addresses enter scheduleHostScan and take the host-scan claim or the
// active budget. A skipped provider candidate therefore cannot suppress a later
// DNS-confirmed scan of the same address. The evidence is entirely this run's own:
// the direct-DNS confirmations and netblocks its passive phase recorded, plus the
// PTR and certificate evidence the corroboration collector gathers, all judged by
// the finalizer before the terminal stages.
//
// The provider facet events also retain each source's observation time: per-service
// scan_time for Censys, the newest banner time for Shodan, and the newest response
// indexing time for Netlas. Those real-world/provider times feed the facts timeline;
// EventMeta.CapturedAt continues to record when Vanguard made the query.
//
// # CT coverage cross-check
//
// crt.sh is the crawler's sole certificate source and can return HTTP 200 with a
// truncated certificate set - a silent partial answer. The distinct subdomains each
// source contributed are tracked in the certs subpackage's Coverage tracker
// (certCoverage), and after the passive phase crossCheckCTCoverage (certs_coverage.go)
// compares crt.sh's count against the certspotter corroborator's (both read the same
// CT logs). It raises a coverage IssueObserved (Source "coverage") for either of two
// gaps, so a CT coverage problem is visible in the report rather than passing as
// complete: crt.sh materially short - below CertspotterCrossCheckMinRatio of
// certspotter's count - is a likely-truncated crt.sh response; certspotter returning
// nothing while crt.sh found names is an inert cross-check (the second source is
// present but corroborated nothing - a keyless recent-window limit, rate limiting, or
// a failed query). The two are mutually exclusive on the certspotter count, so at most
// one fires. The pure decisions and the per-source tracker live in the
// internal/collection/orchestration/certs subpackage (certs.CrtshCoverageShortfall,
// certs.CertspotterInert, certs.Coverage); when the cross-check is disabled (ratio 0)
// neither fires, and a genuinely certless root (both sources empty) is never flagged.
//
// # Degraded-empty corroboration
//
// The other way crt.sh answers imperfectly is a degraded empty: a clean HTTP 200 with
// no certificates emitted only after the backend was degraded mid-search, which the
// crawler flags with a DomainSearchDegraded system event. Rather than record a silent
// zero, corroborateDegraded (corroborate.go) consults the independent CT sources for
// that same query and acts on the pure certs.Decide verdict:
//
//   - History source first: the censys certificate index (historyCertAdapter) indexes
//     CT history, so it corroborates a host whose certs are all expired - the case the
//     live source cannot see. It is gated by the circuit breaker and the paid budget.
//   - Live source: certspotter (liveCertAdapter) proves a currently-valid cert exists.
//     Its blind spot is a host whose certs are all expired, where it falsely agrees
//     "empty"; because agreement only downgrades and disagreement confirms, this is
//     tolerable, and when both run censys carries the decision.
//   - Confirmed (any source saw a cert): a High crawler IssueObserved, and the
//     recovered names re-enter the per-domain fan-out while the recovered certificates
//     are emitted as CertificateDiscovered - backfilling the data the degraded empty
//     lost. Downgraded (all consulted sources empty): a low-severity issue, a likely
//     real empty. NoCorroboration (no source configured, or every available source
//     errored): the pre-corroboration generic Medium crawler issue stands.
//
// The consult-and-act runs on o.wg (wg.Add in the crawler callback, before the single
// wg.Wait) with one sem slot bounding the network calls, released before the backfill
// fan-out so the fan-out spawns never hold two slots at once. Both sources are
// optional; an absent key leaves the source nil (fewer corroborations, never a fatal).
//
// # Discovery-collapse guards
//
// The CT cross-check is one case of a broader rule: a crippled enumeration must
// never present as a clean scan. Two more guards in coverage.go cover the general
// gap, both raising the same coverage IssueObserved (Source "coverage", so they
// land in the report's Coverage gaps section):
//
//   - subfinder zero-result: a subfinder run with every source enabled (all: true)
//     that returns 0 subdomains almost always means a missing provider key (an
//     authenticated source such as VirusTotal ran blind), not a target without
//     subdomains. flagSubfinderZeroResult raises a Medium Issue from runSubfinder.
//   - discovery floor: when the whole passive phase discovers only the root and its
//     registrable apex (the floor a scan always reaches), the surface has collapsed
//     to the bare root. flagDiscoveryCollapse raises a High Issue from runDiscovery
//     after the pipeline drains, gated by hasEnumerationSource so a root-only result
//     with no enumerator running is not flagged. The pure decisions live in
//     coverage.go (subfinderLikelyMisconfigured, discoveryCollapsed).
//
// whois is the exception to the per-name fan-out: it runs once per registrable
// apex (eTLD+1), not once per discovered name. Registration data is a property of
// the registrable apex, every subdomain shares its parent's registration, and a
// registry's RDAP/WHOIS server returns 404 for a non-registrable name. So
// spawnWhois reduces the name to its apex (whois.RegistrableApex, via the
// public-suffix list) and deduplicates by apex before looking up.
//
// # Scope and budget
//
// A run stays focused on one customer. [Scope] (root suffix plus include/exclude
// lists and a crawl-depth cap) decides which discovered names get the expensive
// (paid) and active work: fanOutPaid consults it before the breach/censys/
// virustotal/shodan/netlas lookups, and scheduleDomainProbe consults it before
// https/smtp/webinfo. Budgets cap the paid calls per tool and the active host
// count; the active-host budget is spent in arrival order as domains resolve
// (roughly shallowest-first). Out-of-scope or over-budget work is skipped
// but never dropped silently: each decision is emitted as an info-level
// IssueObserved (Source "scope" or "budget"), so the canonical event stream, the
// report, and the audit stay complete. Tool correlation (ToolCorrID) still ties
// every produced domain event back to the exact tool call.
//
// Hard exclusions are a stronger, separate boundary layered before all of that.
// The engagement's scope.domains.exclude and scope.ip_ranges.exclude lists compile
// (in setScope) into one scopecheck.Exclusions matcher the gate owns. Every active
// admission path consults it first: scheduleDomainProbe denies an excluded name
// before the in-scope and depth gates; scheduleHostScan (via ipHardExcluded) denies
// an excluded address before the scan claim and the active-host budget; spawnAsn
// withholds an address whose only domain association is excluded, while a shared
// address kept alive by one non-excluded name stays reachable unless the address
// itself is excluded; handleProviderHost denies before the certificate
// preflight; and allowRequest and goscansWebScope each
// re-check exclusions before trusting an approval registry, so an approval already
// granted cannot re-authorize a destination an exclusion forbids. A provider-only IP
// with several recorded names selects a non-excluded association for its certificate
// preflight instead of letting an alphabetically earlier excluded name suppress an
// allowed one. A denied admission sets no claim, reserves no budget,
// receives no ActiveTargetApproved, and enters no GoScans target list. The
// admission decision is emitted once per (target kind, normalized target, matched
// rule) as an active-phase IssueObserved with class events.IssueClassExclusion - never
// as a network failure or an unreachability result. Active tool contexts also carry
// a scopecheck rejection observer. Resolver-aware dialers and manual derived-target
// checks report every excluded nameserver, MX, SNI, redirect, or DNS answer through
// it; orchestration projects the exact normalized destination and matched rule into
// the same deduplicated issue ledger. Partial answer sets remain usable through their
// allowed destinations while every withheld destination stays auditable. Passive
// discovery is unchanged: an excluded name or address is still resolved, published,
// and folded into the inventory and projections.
// Invalid programmatic exclusion values become Orchestrator.initErr, so Run stops
// before lifecycle events or traffic just as file configuration validation does.
//
// Config.ProviderHostProbePolicy is scope-adjacent but distinct: it does not decide
// which domain gets expensive work (that is still [Scope] and the provider facet
// only existing for an in-scope domain), it decides what ownership evidence a
// provider-only IP needs before the full active sweep. An approved host shares the
// same active-host budget as every other scheduleHostScan/scheduleDomainProbe call;
// see "Provider-only hosts rejoin the asset graph" above.
//
// Target-facing HTTP authorization uses the policy-neutral scopecheck package.
// It normalizes HTTP(S) destinations, carries the scheduler-approved origin and
// discovery depth in context, and exposes a typed rejection without importing
// orchestration into a tool. The Orchestrator owns the injected callback: exact IP
// literals must be present in gate.approvedIPs, known DNS names reuse their recorded
// discovery depth, and a newly referenced DNS name is evaluated one edge beyond an
// approved origin. The origin is looked up in the registry matching its kind - an IP
// origin in approvedIPs, a DNS origin in approvedDomains - so an approved literal-IP
// source is never reported as unapproved. Because an approved IP has no DNS
// discovery depth, a name first referenced from one (a redirect from a literal-IP
// request to its virtual host) is judged at the fixed derived depth
// ipOriginDerivedDepth; root, include, and exclude still decide the rest. Scope.InScope remains the only root/include/exclude/depth policy,
// so scheduling and request-time rejections use the same reasons. Construction
// injects that callback into webinfo, wappalyzer, httpprobe, and the HTTP portion
// of https. Direct active call paths also attach an origin when a scheduler context
// is not already carrying one, keeping tests and future callers under the same
// request invariant.
//
// GoScans webcrawler and webenum are the exception at the integration boundary:
// their upstream implementation owns a manual redirect loop and exposes no pre-dial
// authorization callback. By default the production phase clears both module flags
// before construction and emits a goscans-coverage issue. Other GoScans modules
// continue to run. Vendor code remains unmodified.
//
// Config.GoScansIgnoreHTTPScope (tools.goscans.ignore_http_scope) is the deliberate
// escape hatch from that default, for an engagement whose mandate tolerates a
// request to wherever a crawl leads. It readmits the two modules, tells the actor to
// accept them (goscans.Config.AllowUnscopedWebModules, which otherwise refuses them
// before the first packet), and records the override once for the run as an
// IssueObserved from Source "goscans-unscoped".
//
// The boundary is then applied to the answers rather than to the requests, which is
// the whole trade: the run may touch a destination it would not have permitted, and
// in exchange the crawl's coverage is kept and stays classifiable.
// goscansInterceptor.markWebScope re-runs the request policy over every endpoint the
// modules fetched - goscansWebScope restates allowRequest for a destination whose
// request context is gone - and leaves an endpoint the policy would have allowed as
// ordinary evidence. Only one it would have refused is stamped
// EventMeta.UnscopedRequest, and its host is reported once per run under the same
// source. The inventory carries the mark into the asset's Provenance and the report
// renders those web applications as "unscoped". Nothing else in the scan sets the
// flag, so filtering it out yields exactly the scope-enforced evidence.
//
// Redirect decisions are published before a caller decides whether a partial tool
// result is usable. Each hop becomes HttpRedirectObserved with its tool correlation
// and causal chain intact. A rejected hop additionally raises one active-phase
// IssueObserved from Source "scope" per normalized source-host/destination-host
// pair for the scan. The gate deduplicates only that operator issue; independent
// tools retain their own redirect events as corroborating evidence.
//
// A per-tool circuit breaker complements the budget for the paid providers. When a
// paid client returns toolerr.ErrProviderUnavailable (a paid-plan or membership
// wall, an auth refusal, or an exhausted daily quota - distinct from a transient
// per-domain error), markToolUnavailable latches the tool and every later spawn for
// it short-circuits via toolIsUnavailable. This turns a useless free-tier key into
// a single call rather than one guaranteed failure per discovered domain, and emits
// one IssueObserved (Source "circuit-breaker") explaining the gap. The data-quality
// reliability model already excludes such unavailable calls, so a tripped provider
// reads "n/a", not 0%.
//
// This cross-cutting run policy state - the scope rules, approved domain and IP
// registries, per-tool paid-call and combined active-host budget counters, the
// per-tool circuit-breaker map, and decision dedup sets - is grouped into one
// unexported gate type (gate.go), guarded by its own mutex separate from the
// gate's own mutex. Discovery and scan-dedup claims never authorize traffic. The gate
// exposes intention-revealing methods for scope, budget, approval, and dedup; the
// orchestrator's thin wrappers turn first-time control decisions into IssueObserved.
// The gate owns only the policy state, never the event emission - emitting needs the
// scanID, publish, and the event vocabulary, which stay on the orchestrator so it
// remains the single translator into domain events.
//
// # Active-phase resolution and reachability
//
// The active probes resolve names through the same DNS server the passive phase
// uses (the dnsinfo resolver, threaded into the https and webinfo client configs
// as ResolverAddr), so an active probe never fails to look up a name discovery
// already resolved. The scanner's own IPv6 capability is checked once, before any
// active probe is scheduled (hasIPv6Connectivity, set in Run). When the scanner
// has no IPv6 route, an IPv6-only target is unreachable: the per-IP port scan and the
// per-domain web probes against such a target are skipped and recorded
// as a low-severity coverage IssueObserved, rather than producing an empty result
// that is indistinguishable from a clean one. The per-domain skip raises one issue
// per enabled web probe, under that probe's own source (https, webinfo, wappalyzer -
// emitWebProbeIPv6Skips), so "which tool was enabled but did not run" is answerable
// by filtering the stream on source instead of being buried under one tool's label.
// The per-IP skip additionally stamps the
// IP asset with an IPReachabilityObserved carrying the typed verdict: the IPv6
// no-route skip, a down/filtered host that answered no TCP probe, or (on a successful
// scan) reachable. The typed state keeps the IPv6 coverage gap distinct from a
// down/filtered host, so the report's attack-surface count and next-steps name only
// the IPv6 gap and the asset carries its own reachability rather than leaving it to be
// inferred from an issue. A successful scan also folds the open
// ports' nmap service ostype hints into a single host OS guess (HostOSGuessed), an
// inferred OS family stamped on the IP asset; it is a weak signal, never asserted.
// The smtp probe is not skipped on an
// IPv6-only domain because it targets the MX hosts, which resolve to their own
// (often IPv4) addresses.
//
// # The two transports
//
// A port-scanned host gets one pass per enabled transport, and they are siblings
// rather than a chain. The TCP sweep runs first, then the UDP pass, sequentially
// inside the one concurrency slot and under the one deadline that host's single
// admission bought: enabling UDP admits no extra host and spends no extra budget
// unit. Each pass takes its own correlation id, so the two sets of tool events
// never fold into one call and a rollup does not read the deliberate pair as a
// duplicate concurrent scan.
//
// The UDP pass is never skipped because TCP found nothing, and never skipped
// because TCP failed: a host that ignores every TCP probe can still answer a UDP
// one, and a broken TCP pass says nothing about the other transport. Only a
// cancelled context or a scope refusal stops it, and both are decided inside the
// pass, before any process exists. A profile with UDP disabled runs no UDP pass
// at all, and the TCP flow is exactly what it was before UDP existed.
//
// Reachability is decided once, after every enabled pass has finished. A positive
// answer on either transport proves the host is there: an open TCP port, a TCP
// answer to the tiebreaker, a confirmed UDP service, or an ICMP port-unreachable
// from the host itself. The UDP side of that is read from the result's state
// counts rather than its per-port slices, so a refusal nmap reported only as a
// collapsed same-state group counts exactly like an individually listed one.
// UDP silence proves nothing - the probe may simply not have
// been the payload that service answers - so it can neither establish
// unreachability nor erase a positive from the other transport. When no pass got a
// conclusive answer the host is stamped unreachable-by-no-response as before, and
// the recorded reason and coverage issue name what each enabled transport actually
// observed, so "no conclusive reply on either" stays distinguishable from "UDP was
// never attempted".
//
// A pass that failed produces no verdict about the target at all. Its loss is
// already reported as a health event under the component that lost it (udp-nmap
// for the UDP pass), and turning a local scanner failure into "this host is
// unreachable" would write a statement about the scanner into the customer's
// estate.
//
// The UDP pass's own evidence is published before that decision is taken, not
// after it. A confirmed service and an ambiguous port are results of the UDP pass
// itself, so they reach the stream even when the host is stamped unreachable or
// the TCP pass failed; only the TCP follow-up chain depends on a verdict.
//
// Only a confirmed UDP response becomes a ServiceDiscovered, with Protocol "udp"
// and the same causation chain a TCP service carries. open|filtered is silence and
// is recorded once per host as a coverage IssueObserved - health-neutral, like
// every other coverage record - because it is neither a service nor a clean
// negative; closed and filtered are not services either, and their reasons stay in
// the tool stream. TCP/N and UDP/N on one host stay two services: nothing merges
// them.
//
// Everything downstream of the port scan stays TCP-only. A UDP result never feeds
// an HTTP probe, never enters the GoScans input set, and never contributes to the
// host OS guess; the TCP follow-up chain is gated on the TCP pass's own verdict,
// so a host proven reachable by UDP alone does not turn an inconclusive TCP sweep
// into a definitive one. Every UDP consumer opts in explicitly.
//
// The smtp probe is instead gated on a mail signal: it runs only for a domain
// that dnsinfo resolved at least one MX record for (domainHasMX, consulted via
// domainHasMailRoute). A domain with no MX handles no mail, so the STARTTLS probe
// cannot succeed; skipping it is a definite negative, not a coverage gap, so no
// Issue is emitted. When dnsinfo is disabled the MX signal is unavailable and the
// probe is not gated. When the probe does run, every MX host timing out on TCP/25
// is itself a coverage gap: it is the signature of a blocked outbound-25 egress
// (common on cloud runners) rather than a target weakness, so
// Result.EgressLikelyBlocked drives a low-severity coverage IssueObserved and the
// missing MX TLS posture is recorded as "could not collect" rather than a clean
// result (the mx-no-starttls detector already skips errored hosts, so no false
// finding is raised).
//
// Likewise the web probes (https, webinfo, wappalyzer) are gated on the domain
// resolving to any address (domainResolvable, over domainHasIPv4/domainHasIPv6): a discovered name
// that resolved to nothing (NXDOMAIN, common for cert-SAN and subfinder guesses)
// cannot be dialled and the probe would fail "no such host". This too is a
// definite negative, not a coverage gap, so it is skipped without an Issue. It is
// distinct from the IPv6-only skip above, which IS a coverage gap (the target
// exists but the scanner cannot route to it) and so emits an Issue.
//
// # One invocation, one set of state
//
// Everything the active and terminal phases read is accumulated by the invocation
// they belong to. The targetState claims and identities, the providerState ownership
// evidence, and the terminalSeedState seeds are all populated as a side effect of
// this run's passive discovery: a name enters the claim sets when this run decides to
// do work for it, an address is registered when this run resolves it, and an approval
// is recorded when this run's admission gates grant one.
//
// There is no door through which a previous collection can enter. The orchestrator
// holds no projection of a prior run, reads no persisted event stream, and imports no
// projection component, so it cannot suppress work on the strength of evidence it did
// not observe. Collecting the same engagement again is a new invocation that plans
// its work from configuration alone, into a destination of its own.
//
// The scan identity is still injected through Config.ScanID: the app mints it, writes
// it into the capture manifest, and hands it here, so the manifest and the event
// stream of one collection cannot disagree. Run generates its own only when none was
// given.
//
// The active-host budget (MaxActiveHosts) is the shared gate for both the per-domain
// probe and the per-IP host scan (takeActiveBudget, consulted in scheduleHostScan as
// well as scheduleDomainProbe), so a run that resolves a large estate cannot turn
// into an unbounded host-scan sweep. Each call site knows statically whether its
// address came from DNS or from a provider facet, so handleProviderHost applies the
// three-state policy with the evidence this run gathered.
//
// # GoScans (terminal active substage)
//
// GoScans (internal/collection/tools/reconactive/goscans) is an active free tool that runs its
// own nmap-backed discovery per approved host and then assesses the services it
// found (banner, TLS, SSH, bounded web crawl, bounded web enumeration). Its
// discovery deliberately overlaps the port scanner and its TLS assessment overlaps
// the https probe: two independent observations of one service are worth more than
// one, but only while the two stay independent, so the tool shares no client,
// process, argument list, cache, temporary directory, or result with any other tool,
// and consumes no other tool's output.
//
// It is a terminal substage of the active phase (goscansPhase, called from Run after
// the single wg.Wait). Running
// last gives it the complete passive host view, keeps its own nmap invocation from
// racing the port scanner's, and guarantees its child processes are gone before the
// run ends, because the actor removes its temporary tree and drains its workers
// before Run returns.
//
// Target approval is separated from tool execution. handleProviderHost applies the
// provider-only ownership policy, then scheduleHostScan applies per-IP dedup and the
// active-host budget once. Every enabled per-IP tool acts on that one decision: the port scanner starts
// streaming, and captureGoScansTarget records the address for the terminal pass. An
// approved host therefore costs one budget unit whether one tool or both probe it,
// because the budget guards targets rather than implementations. The capture is
// independent of the port scanner, so a GoScans-only configuration approves and
// assesses hosts normally (hostToolsEnabled treats either tool as reason enough to
// approve), and enabling or disabling GoScans does not change which hosts the port
// scanner is asked to scan. The one gate the substage applies for itself is
// reachability: an IPv6-only host with no IPv6 route is not captured, and the gap is
// recorded under Source "goscans-coverage" rather than borrowing the port scanner's.
//
// The target snapshot is deterministic. goscansPlan sorts the approved addresses
// canonically (numerically, IPv4 before IPv6), applies goscans.max_targets as a
// lower cap inside the global budget with one Source "budget" IssueObserved per
// dropped target, and attaches each host's virtual-host candidates. Those candidates
// come from ordinary passive IP observations only (recordGoScansHostName, called for
// every address this run attributes a name to), re-checked against [Scope] at plan
// time; the actor
// lowercases, deduplicates, and caps them. Output from another active tool never
// seeds or suppresses GoScans work.
//
// The external runtime the tool runs on is not read from the configuration file,
// because the file names paths and the run needs versions. An app resolves them once
// at startup and passes them in through [Config.SetGoScansRuntime], which takes plain
// strings so an app records what it found without depending on the tool package. The
// actor reports them on its own lifecycle event, so a result is attributable to the
// nmap and the SSLyze that produced it. Leaving it unset is normal in a test and
// reports the runtime as absent.
//
// The actor's sink is wrapped in goscansInterceptor, which does three independent
// things with every tool event: forwards it to the app-wired sink (so
// the collection's tools/tool_goscans.log and the canonical tool-event stream stay the record of what
// the tool did), translates the result-bearing ones into domain observations
// (translate.GoScansEvent), and keeps the terminal run summary. The actor knows
// nothing of this - it emits into a sink exactly as it would with no orchestrator
// present - so the orchestrator remains the single translator from tool vocabulary
// to domain vocabulary.
//
// The translation yields ordinary, tool-neutral observations: services (with the
// transport preserved, and an unmodelled one quarantined as an issue rather than
// defaulted), banners, host profiles, reachability, OS guesses, names and addresses,
// NSE script evidence, TLS assessments with their certificates, SSH postures, and
// HTTP endpoints. Every one carries Source "goscans" and the substage's per-run
// ToolCorrID, so an observation this tool and the port scanner both made stays two
// observations rather than one merged claim. One policy decision stays here rather
// than in the pure translator: goscansInScope drops a discovered virtual host the
// run's scope excludes, because a hosting provider's reverse-DNS name is a real
// observation and an out-of-scope asset at the same time.
//
// Every skip is audited as an IssueObserved: no approved hosts or an incomplete run
// (Source "goscans"), an over-budget target (Source "budget"), a tool that could not
// be built (Source "circuit-breaker"), an unreachable host or a degraded run (Source
// "goscans-coverage"). The tool's own module failures translate under Source
// "goscans" and set IssueObserved.Class to what went wrong ("coverage", "timeout",
// "dependency", "parser", ...), which is what the report buckets on: this one tool
// raises both coverage gaps and tool failures, so its Source cannot decide.
//
// A module the planner did not run because the service was never a subject of it -
// a TLS check on an FTP port - translates to nothing. There is one such skip per
// service per module, they outnumbered the real gaps ten to one in real scans, and
// every one of them says the planner worked rather than anything about the target.
// The record of what the planner decided stays in the collection's tools/tool_goscans.log and in
// ScanCompleted.Skipped. A skip the tool marks Eligible is the opposite - the
// service was a valid subject and went unassessed anyway, which is a cap - and that
// does translate, as a coverage issue.
//
// # Mutable state ownership and lock domains
//
// The orchestrator holds no bookkeeping maps of its own. Everything a run
// accumulates belongs to one of four concrete, unexported state owners, each with
// its own mutex, plus the gate for cross-cutting policy. The locks are leaves: no
// owner's lock is ever held while another lock is taken. A holder that needs another
// owner's data copies a snapshot under that owner's lock, releases it, and consumes
// the copy afterwards, so no tool call, event publication, wait-group wait, or gate
// call ever runs under a state lock (goscansPlan and drainCandidates both follow
// this shape).
//
// targetState (targets.go) owns discovery and scheduling identity: the per-tool
// first-wins claim sets (one per workKind - DNS, whois, the paid lookups, zone
// transfer, host scan, and the coverage-issue dedup), each domain's first-discovery
// event id and crawl depth, the per-domain address-family and MX signals, and the
// registered addresses with their causation ids. A claim answers "was this already
// scheduled", never "may this receive traffic"; none of it authorizes anything.
//
// providerState (provider_state.go) owns provider-host corroboration: the
// DNS-confirmed addresses, each address's routed prefix, the customer-confirmed
// prefixes, the queued provider-only candidates, and the independently collected PTR
// and certificate names. drainCandidates removes the queue under the lock and the
// orchestrator judges the copies outside it, so a verdict never depends on which
// evidence goroutine arrived first. Direct DNS evidence is never downgraded by a
// later provider sighting.
//
// terminalSeedState (terminal_seeds.go) owns the terminal stages' seeds: the
// detection stage's endpoint URLs and technology tags, and the GoScans substage's
// approved hosts, virtual-host names, and observed ports. Each is filled only when
// its stage is enabled, from ordinary discovery observations, never from another
// active tool's output.
//
// projectionState (projection_state.go) owns the folded read models the terminal
// stages plan from, and the mutex that lets many tool goroutines fold at once. It is
// nil unless a terminal stage needs it; every method is nil-safe. apply folds one
// event; read borrows the projection for a callback that must copy out what it needs
// and must not publish, call a tool, or reach into another owner while the projection
// lock is held.
//
// certCoverage (the certs subpackage) self-synchronizes with its own mutex, so
// recordDomainEventID records into it without nesting it under any other lock.
//
// The gate (gate.go) owns cross-cutting policy: scope, the paid and active budget
// counters, the per-tool circuit breaker, the decision-dedup sets, and the approved
// domain and IP registries. The approval registries are the only authorization state
// in the package; a discovery or dedup claim never implies permission to send
// traffic. No other owner's lock is ever held across a gate call.
//
// Execution coordination and immutable wiring - no lock. wg, sem, and portScanSem
// are self-synchronizing primitives. cfg, tools, detectors, requestAllow,
// httpProbePorts, historyCerts, liveCerts, certspotterMemo, and initErr are written
// once in New and only read afterwards. scanID and ipv6Usable are written once at
// the top of Run, before any goroutine that reads them is started.
package orchestration
