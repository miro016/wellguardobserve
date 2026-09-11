// Package netlas queries the Netlas internet-scan platform for the hosts Netlas
// has indexed for a domain, building on the low-level pkg/netlas HTTP wrapper
// (Netlas has no official Go SDK).
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Search], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome. Search
// runs a single "domain:<domain>" responses query, pages through up to MaxPages of
// results, deduplicates the matching scan documents by IP, and aggregates each
// host's observed services, routing (ASN/org/ISP), location, JARM fingerprint,
// software, and known vulnerabilities (CVEs), returning a [DomainHosts] of
// [HostResult] values.
//
// One Netlas document describes one service, so a host carries services rather
// than a port list beside an unordered protocol list: those two lists could not be
// joined back together, and which protocol belonged to which port was lost.
// [Service] keeps the port and its application protocol together.
//
// Its transport is left empty, which means unknown. The responses index this tool
// reads supplies an application protocol per document but no transport field this
// package has seen in a recorded response, and an application protocol is not
// transport evidence: "dns" on port 53 does not establish udp any more than the
// port number does. The field exists so a proven transport can be filled in
// without reshaping the event; until a recorded response supplies one, unknown is
// the honest answer and is never turned into tcp to satisfy a consumer. Each host also retains the newest @timestamp across its response
// documents, which is the Netlas indexing time and normally close to the provider's scan
// time; the domain event carries it into the facts timeline. Documents whose shape Netlas
// changed are skipped per-item and reported via [JSONParseError] with truncated snippets,
// rather than failing the whole
// search, marking the operational outcome in [SearchCompleted] as degraded.
//
// Operational failures during search emit typed events: [RateLimited] on HTTP 429
// quota exhaustion, [PaidPlanRequired] on HTTP 401/403 tier walls, or [SearchFailed]
// for network transport errors. [HostDiscovered] events are enriched with service counts
// and source attribution to allow consistent cross-provider comparison against Censys
// and Shodan.
// The granular terminal failures implement [tooleventlog.HealthEvent]. Query text,
// response snippets, and errors stay only in the canonical tool event; the health
// problem contains a stable code and target. Clean empty and configured truncated
// results remain neutral, and [SearchCompleted] does not duplicate a failure.
//
// Netlas is a paid API and search requests draw down the account's request budget,
// so the key is a secret: the app injects it from the NETLAS_API_KEY environment
// variable onto Config.APIKey rather than the audit configuration file, and the
// tool stays inert when the key is absent. MaxPages bounds how many paid pages a
// single domain lookup can consume.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into NetlasHostsDiscovered domain events.
// Netlas is a host-intelligence source in the same class as censys and shodan; it
// is kept as its own provider facet so the per-provider coverage can be compared
// (the data-quality use case), and its CVE data feeds a netlas-known-vulnerabilities
// detector.
package netlas
