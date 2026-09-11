// Package shodan queries the Shodan host-intelligence platform for the hosts
// Shodan has indexed for a domain, using the shadowscatcher/shodan SDK.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Search], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome. Search
// runs a single hostname:<domain> query, deduplicates the matching service
// banners by IP, and aggregates each host's observed services, routing
// (ASN/org/ISP), software products, location, and known vulnerabilities (CVEs),
// returning a [DomainHosts] of [HostResult] values.
//
// A host carries services, not a port list: Shodan states the IP transport on
// each banner, and a port number on its own cannot say whether tcp/53 or udp/53
// was seen. [Service] therefore keeps the port and its transport together, two
// banners on one port with different transports stay two services, and the
// transport is normalized to "tcp" or "udp" as the banner is read. A banner that
// reports neither leaves the transport empty, which means unknown: it is never
// defaulted to tcp, and neither the port number nor an application protocol is
// read as transport evidence. Each host retains the newest banner timestamp
// across its matching services so the domain event can date passive host and service
// facts independently from the Vanguard scan time.
//
// Operational failures during search emit typed events: [RateLimited] on HTTP 429
// quota exhaustion, [PaidPlanRequired] on HTTP 401/403 tier walls, or [JSONParseError]
// when response decoding fails. [HostDiscovered] events are enriched with service counts
// and source attribution to allow consistent cross-provider comparison against Censys
// and Netlas, and [SearchCompleted] records query success and degradation counters.
// The granular terminal failures implement [tooleventlog.HealthEvent]. Query text,
// response snippets, and errors stay only in the canonical tool event; the health
// problem contains a stable code and target. Clean empty and configured truncated
// results remain neutral, and [SearchCompleted] does not duplicate a failure.
//
// Shodan is a paid API and each search consumes one query credit, so the key is a
// secret: the app injects it from the SHODAN_API_KEY environment variable onto
// Config.APIKey rather than the audit configuration file, and the tool stays
// inert when the key is absent. The SDK is constructed with rate-limit waiting
// enabled so the free/standard tier limit does not produce 429 errors.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into ShodanHostsDiscovered domain events.
// Shodan's distinguishing value over the other host sources (censys) is the CVE
// data, which the orchestrator's shodan-vulnerabilities detector turns into
// findings.
package shodan
