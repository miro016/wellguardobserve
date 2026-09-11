// Package websearch performs passive asset discovery via SerpAPI, running a set
// of Google dork queries against a root domain to surface URLs a search engine
// already knows about. The dorks target classes of exposure (auth and admin
// interfaces, API endpoints, configuration and environment files, backups and
// database dumps, open directory listings, WordPress paths, and pre-production
// environments), each tagged with a category (see dork.go).
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Search], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome,
// including per-query failures. Granular operational errors such as HTTP 429
// rate limits ([RateLimited]), CAPTCHA/anti-bot blocks ([SearchEngineBlocked]),
// and SERP layout extraction failures ([SERPParseError]) are emitted with raw
// snippets or attempt counters to distinguish anti-scraping countermeasures
// from generic network failures. [SearchCompleted] reports total quantitative
// counters along with Truncated and Degraded flags.
// The granular operational failures implement [tooleventlog.HealthEvent] because
// the affected query could not contribute evidence. Honest no-results responses
// and configured result caps remain health-neutral, and [SearchCompleted] does not
// duplicate the per-query failures.
//
// Search returns the deduplicated [Asset] values as a [DomainAssets]; each asset
// carries its URL, host, snippet text, and the dork (and category) that found
// it, which supports comparing tool coverage and judging exposure.
//
// A SERP response is untrusted input: a search engine may ignore or reinterpret
// the site: operator and answer with unrelated third-party pages. This package
// is therefore the trust boundary that decides what may become a target asset.
// Every row is classified against the requested root before it is deduplicated,
// returned, or emitted as [AssetFound]: a row is owned only when its normalized
// URL hostname equals the root or ends in a dot plus the root, so a deceptive
// suffix such as example.com.attacker.test is never accepted. Invalid URLs,
// empty hosts, and IP literals are rejected too.
//
// Rejected rows are a diagnostic about upstream search quality, not a collection
// failure: the engine answered and the response parsed. They therefore do not
// implement [tooleventlog.HealthEvent], and a query whose rows are all rejected
// is a successful empty query. Accounting is explicit and bounded: on
// [QuerySucceeded] and [SearchCompleted], Results is the upstream row count and
// Accepted plus Rejected partitions it, while Assets is the deduplicated
// accepted total. [ResultsRejected] adds per-query counts over a closed reason
// vocabulary. Rejected URLs and snippets are never retained, because they are
// not evidence about the target. Operator drift is measured; it cannot create
// target assets.
//
// Queries run sequentially to respect SerpAPI rate limits, and results are
// deduplicated by URL across all queries. A SerpAPI "no results" response is
// treated as an empty result, not an error.
//
// Usage requires a SerpAPI key. The key is a secret, so the app injects it from
// the SERPAPI_API_KEY environment variable onto Config.APIKey rather than reading
// it from the audit configuration file; the tool stays inert when the key is
// absent.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into DnsDomainNameDiscovered (in-scope
// result hosts) and WebAssetsDiscovered (the dork hits) domain events.
package websearch
