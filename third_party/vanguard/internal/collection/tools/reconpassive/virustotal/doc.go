// Package virustotal queries the VirusTotal API v3 for domain intelligence,
// using the official vt-go library to fetch domain reputation, analysis vote
// counts, categories, tags, popularity ranks, JARM fingerprint, registrar, and
// known subdomains.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through two methods, emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome:
//   - [Client.Lookup] fetches the intelligence report ([DomainReport]) for a domain.
//   - [Client.Subdomains] enumerates the domain's known subdomains.
//
// A not-found domain (VirusTotal never observed it, HTTP 404) is a normal empty
// result, not a failure: [Client.Lookup] emits [DomainNotFound] and returns a nil
// report with [ErrDomainNotFound], so unknown subdomains do not pollute the tool's
// error count or reliability score. Genuine operational failures emit typed events
// ([RateLimited] on HTTP 429 quota exhaustion, [AuthFailed] on HTTP 401/403 walls,
// [JSONParseError] on malformed responses, or [LookupFailed] for network errors).
// Those failures and [SubdomainEnumFailed] implement [tooleventlog.HealthEvent]
// because an attempted API operation lost evidence. [DomainNotFound], clean empty
// results, and configured truncation remain health-neutral. Failure classification
// emits one granular event per failed operation, so aggregate completion events are
// not health-bearing.
//
// Subdomain enumeration emits [SubdomainFound] enriched with last observed DNS
// resolution timestamps and source attribution, concluding with an operational
// summary in [SubdomainEnumCompleted] tracking query counts and degradation.
//
// The two are split so the orchestrator can run the reputation lookup per
// discovered domain while enumerating subdomains only where it wants to (for
// example once on the root), and so subdomain enumeration can be gated
// independently via Config.EnableSubdomains.
//
// Usage requires a VirusTotal API key; the free tier allows 4 requests per
// minute. The key is a secret, so the app injects it from the VIRUSTOTAL_API_KEY
// environment variable onto Config.APIKey rather than reading it from the audit
// configuration file; the tool stays inert when the key is absent.
//
// No enterprise-only features are used. Only the domains endpoint and the
// subdomains relationship are called, both available on the free tier.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into DnsDomainNameDiscovered (subdomains)
// and DomainReputationDiscovered (intelligence report) domain events.
package virustotal
