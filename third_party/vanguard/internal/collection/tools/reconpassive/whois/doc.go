// Package whois provides domain registration lookups via WHOIS and RDAP.
//
// Primary lookup uses traditional port-43 WHOIS via github.com/likexian/whois,
// parsed into structured data by github.com/likexian/whois-parser. When WHOIS
// fails (e.g. port 43 blocked by Cloudflare for .tech TLD), the package falls
// back to RDAP (Registration Data Access Protocol) which queries registration
// data over HTTPS/JSON using IANA's bootstrap service.
//
// An RDAP entity's registrar/registrant/admin/tech display name comes from its
// jCard vcardArray ("fn", then "org"; see vcardNameOrg in rdap.go), not its
// Handle - Handle is only the registry's numeric entity ID (e.g. an IANA
// registrar ID) and is used solely as a last-resort fallback when the vCard is
// missing or malformed.
//
// The tool follows the same shape as the other Vanguard tools: a Client built
// from a Config, emitting typed events (see events.go) to a tooleventlog.Sink
// rather than logging directly. Raw WHOIS transport stays behind an injectable
// function variable so tests can use canned fixtures instead of live network.
//
// Lifecycle and operational events report detailed execution progress and health:
//   - LookupStarted and LookupCompleted bracket every lookup, with LookupCompleted
//     reporting whether WHOIS/RDAP were attempted, overall success, and whether the
//     lookup was degraded (missing key dates, rate limited, or failed leg).
//   - QueryFailed (socket/network) and RdapFailed (HTTPS/JSON) distinguish specific
//     transport errors from LookupFailed (overall resolution failure).
//   - RateLimited, WhoisServerThrottled, WhoisParseError, and RDAPParseError report
//     granular operational anomalies without failing the scan.
//
// [LookupCompleted] implements [tooleventlog.HealthEvent] only when neither lookup
// leg succeeded. A failed WHOIS leg followed by successful RDAP, missing optional
// dates, and throttling that recovers remain health-neutral. The aggregate owns the
// classification so the preceding diagnostic events are not counted twice.
//
// When a TLD's port-43 WHOIS server is unreachable (e.g. Cloudflare blocks port
// 43 for .tech, .no), the first failure is remembered for the run and later
// lookups for that TLD skip straight to RDAP instead of paying the dial timeout
// again. This is a per-Client, per-run cache (see QuerySkipped in events.go).
//
// The orchestrator calls Lookup once per registrable apex (eTLD+1), not per
// discovered subdomain: a subdomain is not a registrable object, so a registry
// returns 404 for it, and it shares the apex's registration anyway. The Client
// itself looks up whatever name it is given; RegistrableApex (apex.go) reduces a
// discovered name to its registrable apex, and the orchestrator deduplicates the
// lookups by that apex.
//
// Every Registration records its Source ("whois" or "rdap"), the leg that
// answered. This makes the same field set comparable across data sources and,
// later, across tools (e.g. paid sources like Censys or Shodan) so tool
// efficiency and data quality can be evaluated.
//
// Primary API:
//   - New(Config) builds a Client.
//   - (*Client).Lookup(ctx, domain) returns a Registration (WHOIS, RDAP fallback).
package whois
