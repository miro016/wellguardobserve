// Package crtsh provides a resilient client for the crt.sh certificate
// transparency API. It handles retries with exponential backoff and jitter,
// caps response body size, and emits typed events via a caller-supplied
// tooleventlog.EventSink. Parsed certificates are returned directly.
//
// Completeness over speed: crt.sh is the only source of certificate data, and
// the subdomains it discovers from certificate SANs are not a subset of any
// other tool (subfinder aggregates different passive DNS feeds and returns no
// certificates). A crt.sh failure therefore loses data that nothing else can
// supply, so the default posture is to retry until it succeeds (MaxRetries == -1,
// see Config). Config.MaxQueryTime caps the total wall-clock time of a single
// search only when set to a non-negative value; "-1s" leaves it unbounded and
// "0s" permits no wait. Setting either finite cap re-introduces the
// possibility of a give-up, which trades completeness for bounded run time - the
// crawler tolerates the resulting miss (it still records the names other tools
// found) but the certificate data for that query is gone. An ancestor context
// deadline (the crawler's per-domain budget) ends a search the same way even when
// both caps are unset. However it ends, an abandoned search emits a terminal
// GaveUp event (error level) instead of returning silently, and every search
// finishes by emitting a universal [SearchCompleted] event with operational
// metrics and degradation/truncation flags.
//
// Outage breaker: MaxRetries and MaxQueryTime bound one search, but on their own
// they do not bound a whole crawl against a crt.sh that is answering nothing. Under
// never-give-up, a total crt.sh outage makes every remaining name ride the full
// MaxQueryTime, so the crawl grinds one time budget per name for as long as the
// outage lasts while producing no data. The Client therefore keeps an across-search
// circuit breaker (see breaker.go). It stays closed while crt.sh answers at all, and
// opens only after several consecutive searches each end without a single successful
// response (see the outageThreshold constant). While open, each search probes crt.sh
// once and, on failure, abandons immediately (a terminal [OutageBreakerSkipped])
// instead of re-paying the retry budget, so the crawl drains in roughly one request
// per name; the transition emits one [OutageBreakerOpened]. Any successful response
// closes the breaker, so a recovered crt.sh resumes full completeness-first retries.
// The breaker never trips on ordinary flakiness because a within-search recovery is a
// success that resets the streak; it only fires on a sustained, total outage. During certificate parsing,
// [CertDiscovered] is emitted for each record, and HTTP 429 rate limit walls
// emit [RateLimited]. Every event a search emits carries a per-search
// correlation id, so the operational rollup records the search as one call - a
// failed one when it gave up - rather than losing it.
//
// Degraded empty: crt.sh signals "no certificates" as an HTTP 200 with an empty
// JSON array, the same shape it can return as a short/empty body while the backend
// is overloaded. An empty result is therefore suspect when retryable backend
// failures (502/404/HTML/timeouts) occurred earlier in the same search. The client
// does not accept such an empty at face value: it re-queries once after a cooldown
// (Config.DegradedRecheckDelay), and if the result is still empty it returns
// SearchResult.DegradedEmpty = true so the caller surfaces the completeness risk as
// a data-quality issue instead of recording a silent authoritative zero. A clean
// empty (no prior failures) is accepted as the genuine "no certificates" answer.
//
// Silent truncation: the retry and degraded-empty guards cover errors, timeouts,
// and a degraded empty, but not crt.sh returning HTTP 200 with a short but
// non-empty body (a partially truncated certificate set that looks complete). That
// residual risk is covered outside this package by the certspotter second CT
// source: the orchestration cross-check compares the subdomain count this crawler
// discovered against certspotter's for the same root and raises a coverage
// IssueObserved when crt.sh is materially short (see
// internal/collection/tools/reconpassive/certspotter and orchestration/coverage.go).
//
// Modes: Config.Mode is the single switch for the tool; there is no separate enable
// flag, so a mode and a flag can never disagree. New dispatches on it. ModeDisabled
// runs nothing - no client is constructed (asking New for one is a configuration
// error), no tool log is opened, and the certificate crawler is not started.
// ModeEnabled queries crt.sh and never consults the fixture. ModeEmbeddedCacheSupport
// consults the fixture first: a hit returns before any URL construction, HTTP
// request, retry accounting, degraded-empty handling, or outage-breaker mutation, and
// is bracketed by the usual started/completed events so it is accounted as one call;
// a miss emits a cache-miss event and enters the ordinary search loop with its retry
// and error behaviour unchanged, sharing the same correlation id. Both non-disabled
// modes enumerate subdomains, so both count as an enumeration source
// (Mode.Enabled reports which modes run the tool).
//
// Retrieval provenance: SearchResult.RetrievalSource carries "service" or
// "cache_embedded", and [SearchCompleted] exposes the same value as a
// retrieval_source attribute, so an operator can tell from either the returned value
// or the tool stream where the certificates came from. A cache miss that falls
// through to the service reports "service" - the fixture decided nothing about the
// data finally returned - with its own [CacheMiss] event recording the miss that
// preceded it. The strings mirror the events package's RetrievalSource vocabulary,
// which this package cannot import; the crawler carries the value and the
// orchestrator's translator copies it onto the domain event, leaving the provider
// attribution ("crtsh") unchanged.
//
// Embedded development cache: the package owns a compiled-in fixture of crt.sh
// results (cache_data.json, embedded with go:embed) so local development and
// repeatable tests do not depend on crt.sh availability. It is a development
// fixture, not a production cache: it has no TTL, refresh, write-through,
// invalidation, or persistence, and the deployed collector reads no cache
// directory, environment override, or runtime path of any kind. Adding results
// means editing cache_data.json and recompiling the collector.
//
// The fixture stores result values only, never saved event envelopes: replaying an
// envelope would leak an old scan id, event id, causation id, correlation id,
// sequence number, and capture time into a new scan. Provider-supplied timestamps
// (certificate validity and CT log entry times) are part of the result and are
// preserved; the surrounding operational and domain events are created fresh on
// every run as usual.
//
// The data is keyed by the exact request query, so FetchDomain ("example.com") and
// FetchSubdomains ("%.example.com") are distinct entries. Lookup is an exact
// in-memory map access with no partial matching and no synthesized answer, so an
// uncached query is a plain miss that falls through to the unchanged service path.
// The current coverage is 245 certificates for each vissim.no query and 13 for each
// vissim.tech query.
//
// The embedded data is decoded as exactly one JSON value and validated when a
// cache-using Client is constructed, so malformed or trailing JSON, an empty or
// unnormalized query key, a wildcard key
// with no domain, a certificate without an id or listed twice within one query, a
// missing CT log timestamp, and an inverted validity window all fail fast rather
// than mid-crawl. After construction the parsed data is read-only, so it needs no
// lock, and every lookup returns a deep copy: a caller that mutates a result cannot
// affect a later lookup.
//
// All events emitted by this package are defined in events.go and implement
// the tooleventlog.Event interface. Terminal [GaveUp], [DegradedEmptyResult], and
// [OutageBreakerSkipped] events also implement [tooleventlog.HealthEvent] because
// they prove the attempted query did not produce trustworthy complete evidence.
// Retry events and [SearchCompleted] remain health-neutral, including a search
// that recovered after retrying.
//
// Typical usage:
//
//	c, err := crtsh.New(&crtsh.Config{
//	    Mode:         crtsh.ModeEnabled,
//	    Timeout:      10 * time.Second,
//	    MaxRetries:   3,
//	    BackoffMin:   500 * time.Millisecond,
//	    BackoffMax:   30 * time.Second,
//	    MaxBodyBytes: 10 << 20,
//	    Sink:         sink,
//	})
//	certs, err := c.FetchDomain(ctx, domain)
//	certs, err := c.FetchSubdomains(ctx, domain)
package crtsh
