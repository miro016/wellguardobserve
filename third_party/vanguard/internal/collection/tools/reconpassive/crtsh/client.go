package crtsh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Mode selects where a Client's results come from. It is the single switch for the
// tool: there is no separate enable flag, so a mode cannot disagree with one.
type Mode string

const (
	// ModeDisabled means crt.sh does not run. No client is constructed, no tool log
	// is opened, and the certificate crawler is not started.
	ModeDisabled Mode = "disabled"
	// ModeEnabled queries crt.sh. The embedded fixture is not consulted at all.
	ModeEnabled Mode = "enabled"
	// ModeEmbeddedCacheSupport consults the embedded fixture first and falls back to
	// the service on a miss. A hit returns before any URL construction, HTTP request,
	// retry accounting, degraded-empty handling, or outage-breaker mutation; a miss
	// enters the ordinary search loop with its behaviour unchanged.
	ModeEmbeddedCacheSupport Mode = "embedded_cache_support"
)

// Modes lists the accepted mode values, for configuration validation and error
// messages.
func Modes() []Mode { return []Mode{ModeDisabled, ModeEnabled, ModeEmbeddedCacheSupport} }

// Enabled reports whether the mode runs the tool at all, so the caller constructs a
// client, opens its tool log, and starts the crawler. Both running modes enumerate
// subdomains, so both count as an enumeration source. It tests for the running modes
// rather than "not disabled", so an unset or unrecognised mode is inert instead of
// being treated as a request to run something the constructor will then reject.
func (m Mode) Enabled() bool { return m == ModeEnabled || m == ModeEmbeddedCacheSupport }

// Config holds configuration for the Client.
type Config struct {
	// Mode selects the result source: crt.sh, the embedded fixture with crt.sh as
	// fallback, or nothing at all. It is required; there is no default.
	Mode Mode
	// BaseURL is the crt.sh API endpoint. Defaults to "https://crt.sh/".
	BaseURL string
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration
	// MaxRetries is the number of retries after the first attempt. Minus one means
	// retry indefinitely (never give up) until the search succeeds or ctx /
	// MaxQueryTime cancels it. crt.sh is the only source of certificate data and
	// its subdomain set is not a subset of any other tool, so completeness is
	// favoured over speed: a transient crt.sh outage must not silently drop data.
	MaxRetries int
	// MaxQueryTime bounds the total wall-clock time spent on one search (all
	// attempts and backoff combined). Minus one means unlimited; zero means no wait.
	MaxQueryTime time.Duration
	// BackoffMin is the initial backoff before the first retry.
	BackoffMin time.Duration
	// BackoffMax caps exponential backoff growth.
	BackoffMax time.Duration
	// DegradedRecheckDelay is the cooldown before re-querying a suspicious empty
	// result: a 200 with zero certificates that arrived only after crt.sh emitted
	// retryable backend failures during the same search. crt.sh signals "no
	// certificates" the same way it can return a short/empty body while degraded,
	// so an empty preceded by 502/404/HTML is re-queried once after this delay
	// before being accepted, in case the degraded window was momentary. Zero means
	// re-query immediately (no cooldown); the app config requires a positive value.
	DegradedRecheckDelay time.Duration
	// MaxBodyBytes caps the response body size to prevent unbounded memory use.
	MaxBodyBytes int64
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client queries crt.sh for certificate transparency records.
type Client struct {
	cfg  Config
	http *http.Client
	// breaker is the across-search outage guard. Per-search retries default to
	// never-give-up (MaxRetries == -1) because crt.sh is the sole certificate
	// source; the breaker is the missing across-search bound that stops a total
	// crt.sh outage from making every remaining crawl name ride the full
	// MaxQueryTime. See breaker.go.
	breaker crtshBreaker
	// cache is the embedded result fixture, non-nil only on a cache-supported
	// Client. When set, a cached query is answered from compiled-in data before any
	// URL construction, HTTP request, retry accounting, or breaker mutation; a miss
	// falls through to the unchanged service path.
	cache *cache
}

// New validates cfg and returns a Client for the configured mode. cfg is taken by
// pointer (it is a heavy struct) and copied; the caller's value is not mutated.
// ModeEmbeddedCacheSupport additionally decodes and validates the compiled-in fixture
// here, so malformed fixture data fails at construction rather than mid-crawl; the
// HTTP client is still built because a miss uses the ordinary service path.
// ModeDisabled is not a client: the caller must not construct one, and asking for it
// is a configuration error rather than a silently inert client.
func New(cfg *Config) (*Client, error) {
	conf := *cfg
	if conf.BaseURL == "" {
		conf.BaseURL = "https://crt.sh/"
	}
	c := &Client{
		cfg:  conf,
		http: &http.Client{Timeout: conf.Timeout},
	}
	switch conf.Mode {
	case ModeEnabled:
		return c, nil
	case ModeEmbeddedCacheSupport:
		data, err := loadCache()
		if err != nil {
			return nil, err
		}
		c.cache = data
		return c, nil
	case ModeDisabled:
		return nil, fmt.Errorf("crtsh: Config.Mode %q does not construct a client", conf.Mode)
	default:
		return nil, fmt.Errorf("crtsh: Config.Mode %q is invalid (one of: %s)", conf.Mode, modeList())
	}
}

// modeList renders the accepted modes for an error message.
func modeList() string {
	names := make([]string, 0, len(Modes()))
	for _, m := range Modes() {
		names = append(names, string(m))
	}
	return strings.Join(names, ", ")
}

const (
	// retrievalService and retrievalCacheEmbedded are the two values stamped on a
	// result's RetrievalSource and on the retrieval_source event attribute. They
	// mirror the events package's RetrievalSource vocabulary, which this package
	// cannot import; the crawler carries the value and translation copies it straight
	// onto the domain event.
	retrievalService       = "service"
	retrievalCacheEmbedded = "cache_embedded"
)

// SearchResult is the outcome of one crt.sh search.
type SearchResult struct {
	// Certs are the parsed certificates the search returned (possibly empty).
	Certs []Certificate
	// DegradedEmpty is true when the search returned zero certificates only after
	// crt.sh emitted retryable backend failures (502/404/HTML/timeouts) during the
	// same search, and a re-query after a cooldown still came back empty. The empty
	// result may be a degraded-backend artifact rather than an authoritative "no
	// certificates", so the caller must treat it as a data-quality risk instead of
	// recording a trustworthy zero. crt.sh is the sole certificate source, so a
	// silently accepted degraded empty collapses subdomain discovery.
	DegradedEmpty bool
	// RetrievalSource states where this result came from: "service" for a crt.sh
	// answer, "cache_embedded" for the compiled-in fixture. A cache miss that falls
	// through to the service reports "service": the fixture decided nothing about the
	// data that was finally returned. It is empty on a failed search, which returned
	// no observation to attribute.
	RetrievalSource string
}

// searchCorrSeq makes each search's correlation id unique within the process.
// crt.sh is driven as a stream of searches with no caller-assigned per-call id, so
// each search self-assigns one; the operational rollup then counts every search as
// its own call with its own latency and outcome instead of dropping it.
var searchCorrSeq atomic.Uint64

// nextSearchCorrID returns a fresh correlation id for one search.
func nextSearchCorrID(query string) string {
	return fmt.Sprintf("crtsh-%d-%s", searchCorrSeq.Add(1), query)
}

// FetchDomain returns certificates for the exact domain from crt.sh. It stamps the
// target on the context (the crawler drives crtsh directly, so nothing upstream sets
// it) so every emitted tool event is attributed to the domain rather than left blank.
func (c *Client) FetchDomain(ctx context.Context, domain valueobjects.DnsDomainName) (SearchResult, error) {
	ctx = tooleventlog.WithTarget(ctx, domain.String())
	return c.lookup(ctx, domain.String())
}

// FetchSubdomains returns certificates for all subdomains of domain from crt.sh. It
// stamps the exact domain (not the "%." wildcard query) as the target so the exact and
// wildcard searches attribute to the same domain in the tool log.
func (c *Client) FetchSubdomains(ctx context.Context, domain valueobjects.DnsDomainName) (SearchResult, error) {
	ctx = tooleventlog.WithTarget(ctx, domain.String())
	return c.lookup(ctx, "%."+domain.String())
}

// lookup answers one query, consulting the embedded fixture first in
// ModeEmbeddedCacheSupport. A hit returns before any URL is built, so no HTTP
// request, retry, degraded-empty recheck, or outage-breaker update happens for it; a
// miss falls into the unchanged service loop and shares this call's correlation id,
// so the miss and the search it caused are accounted as one call.
func (c *Client) lookup(ctx context.Context, query string) (SearchResult, error) {
	if c.cache == nil {
		return c.search(ctx, query)
	}
	if tooleventlog.CorrIDFrom(ctx) == "" {
		ctx = tooleventlog.WithCorrID(ctx, nextSearchCorrID(query))
	}
	result, ok := c.cache.resultFor(query)
	if !ok {
		c.emit(ctx, CacheMiss{Query: query})
		// The miss decided nothing about the data the service returns next, so the
		// result and its terminal event are attributed to the service path.
		return c.search(ctx, query)
	}
	result.RetrievalSource = retrievalCacheEmbedded
	// A cache hit is still one accounted search: started/completed bracket it exactly
	// as a served query, with no attempt because none was made.
	c.emit(ctx, SearchStarted{Query: query, MaxRetries: c.cfg.MaxRetries})
	c.emit(ctx, CacheHit{Query: query, Certs: len(result.Certs)})
	for i := range result.Certs {
		cert := &result.Certs[i]
		c.emit(ctx, CertDiscovered{Query: query, CertID: cert.ID, Issuer: cert.IssuerName, SANs: len(cert.Domains)})
	}
	c.emit(ctx, SearchCompleted{
		Query:           query,
		Certs:           len(result.Certs),
		Subdomains:      countSubdomains(result.Certs),
		RetrievalSource: retrievalCacheEmbedded,
	})
	return result, nil
}

func (c *Client) search(ctx context.Context, query string) (result SearchResult, retErr error) {
	u, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return SearchResult{}, fmt.Errorf("crtsh: invalid base URL: %w", err)
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("output", "json")
	u.RawQuery = q.Encode()
	rawURL := u.String()

	// A positive MaxQueryTime caps the whole search so one permanently-broken name
	// cannot hang forever. This trades completeness for bounded time: the
	// certificate data for a capped query is lost (no other tool supplies it).
	// Zero leaves the search bounded only by MaxRetries, which itself defaults to
	// never-give-up (MaxRetries == -1) so complete data is the out-of-the-box
	// behaviour.
	//
	// parentCtx is captured before the MaxQueryTime wrapper so the outage breaker
	// can tell our own time budget running out (a crt.sh outage) from the parent
	// scan being cancelled (not a crt.sh failure, must not count against crt.sh).
	parentCtx := ctx
	if c.cfg.MaxQueryTime >= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.MaxQueryTime)
		defer cancel()
	}

	// Each search is one tool invocation. Stamp a per-search correlation id (unless
	// the caller already set one) so every event the search emits shares it and the
	// search is accounted as a single correlated call.
	if tooleventlog.CorrIDFrom(ctx) == "" {
		ctx = tooleventlog.WithCorrID(ctx, nextSearchCorrID(query))
	}

	c.emit(ctx, SearchStarted{Query: query, MaxRetries: c.cfg.MaxRetries})

	var (
		res           SearchResult
		totalAttempts int
	)
	defer func() {
		c.emit(ctx, SearchCompleted{
			Query:           query,
			Certs:           len(res.Certs),
			Subdomains:      countSubdomains(res.Certs),
			Attempts:        totalAttempts,
			Degraded:        res.DegradedEmpty || totalAttempts > 1,
			Truncated:       len(res.Certs) >= 10000,
			RetrievalSource: retrievalService,
		})
	}()

	var lastErr error
	backoff := c.cfg.BackoffMin
	// MaxRetries == -1 means retry indefinitely: completeness is the priority, so a
	// transient crt.sh outage (502/timeout/rate-limit) must not drop certificate
	// data. The loop is then bounded only by ctx (scan cancellation or, when set,
	// MaxQueryTime). A non-retryable error still returns immediately.
	infinite := c.cfg.MaxRetries == -1

	// degradedHistory records whether crt.sh emitted any retryable backend failure
	// during this search (502/404/HTML/timeout). An empty 200 after such failures is
	// suspect: crt.sh can return a short/empty body while degraded, which is
	// indistinguishable from its real "no certificates" signal. rechecked bounds the
	// suspicious-empty re-query to a single extra attempt after a cooldown.
	degradedHistory := false
	rechecked := false

	// Across-search outage breaker. probeOnly is fixed for this search: when the
	// breaker is already open, do a single probe instead of the full retry budget.
	// The deferred classification then updates the breaker from this search's
	// outcome - a reached crt.sh (retErr == nil) closes it, a crt.sh-side no-response
	// (retryable failures throughout, no parent cancellation) is an outage that opens
	// it after outageThreshold in a row.
	probeOnly := c.breaker.isOpen()
	defer func() {
		if ev, ok := c.recordSearchOutcome(retErr == nil, degradedHistory, parentCtx.Err() != nil); ok {
			c.emit(ctx, ev)
		}
	}()

	for attempt := 0; ; attempt++ {
		totalAttempts = attempt + 1
		if ctx.Err() != nil {
			c.emitRateLimited(ctx, query, attempt, lastErr)
			c.emitDeadlineGaveUp(ctx, query, attempt, lastErr)
			return SearchResult{}, ctx.Err()
		}

		certs, retryable, err := c.attempt(ctx, rawURL, query, attempt)
		if err == nil {
			if len(certs) > 0 || !degradedHistory {
				res = SearchResult{Certs: certs, RetrievalSource: retrievalService}
				return res, nil
			}
			if !rechecked {
				rechecked = true
				c.emit(ctx, SchedulingRecheck{Query: query, Attempt: attempt, Wait: c.cfg.DegradedRecheckDelay})
				if err := c.wait(ctx, query, attempt+1, c.cfg.DegradedRecheckDelay, lastErr); err != nil {
					return SearchResult{}, err
				}
				continue
			}
			c.emit(ctx, DegradedEmptyResult{Query: query, TotalAttempts: attempt + 1})
			res = SearchResult{Certs: certs, DegradedEmpty: true, RetrievalSource: retrievalService}
			return res, nil
		}
		lastErr = err
		if retryable {
			degradedHistory = true
		}
		if !retryable {
			c.emitDeadlineGaveUp(ctx, query, attempt+1, lastErr)
			return SearchResult{}, err
		}
		if probeOnly {
			// Breaker open: crt.sh failed every one of the last outageThreshold
			// searches. Probe once, then abandon fast instead of paying the whole
			// retry budget again, so the crawl drains in ~one request per name
			// instead of one MaxQueryTime per name. A probe that succeeds takes the
			// return-nil path above and closes the breaker.
			c.emit(ctx, OutageBreakerSkipped{Query: query, Attempt: attempt + 1, LastErr: lastErr})
			return SearchResult{}, fmt.Errorf("crtsh: abandoned %q: crt.sh outage breaker open: %w", query, lastErr)
		}
		if !infinite && attempt >= c.cfg.MaxRetries {
			c.emitRateLimited(ctx, query, attempt, lastErr)
			break
		}

		sleep := addJitter(backoff)
		c.emit(ctx, SchedulingRetry{
			Query:      query,
			Attempt:    attempt,
			MaxRetries: c.cfg.MaxRetries,
			Wait:       sleep,
			Err:        lastErr,
		})

		if err := c.wait(ctx, query, attempt+1, sleep, lastErr); err != nil {
			return SearchResult{}, err
		}

		backoff = nextBackoff(backoff, c.cfg.BackoffMax)
	}

	c.emit(ctx, GaveUp{
		Query:         query,
		TotalAttempts: c.cfg.MaxRetries + 1,
		LastErr:       lastErr,
	})
	return SearchResult{}, fmt.Errorf("crtsh: gave up on %q after %d retries: %w", query, c.cfg.MaxRetries, lastErr)
}

// attempt performs one HTTP request. Returns (certs, retryable, error).
func (c *Client) attempt(ctx context.Context, rawURL, query string, attempt int) ([]Certificate, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		c.emit(ctx, RequestBuildFailed{Query: query, Attempt: attempt, Err: err})
		return nil, false, fmt.Errorf("crtsh: build request: %w", err)
	}
	req.Header.Set("User-Agent", randomUserAgent())

	resp, err := c.http.Do(req)
	if err != nil {
		retryable := isRetryableNetErr(ctx, err)
		c.emit(ctx, NetworkError{Query: query, Attempt: attempt, Retryable: retryable, Err: err})
		return nil, retryable, err
	}

	body, readErr := readCapped(resp.Body, c.cfg.MaxBodyBytes)
	_ = resp.Body.Close()

	if readErr != nil {
		// A body-cap overflow is deterministic, so it must not be retried (it would
		// loop forever under never-give-up). Other read errors are transient.
		retryable := !errors.Is(readErr, errBodyTooLarge) && isRetryableNetErr(ctx, readErr)
		c.emit(ctx, BodyReadError{
			Query:      query,
			Attempt:    attempt,
			StatusCode: resp.StatusCode,
			Retryable:  retryable,
			Err:        readErr,
		})
		return nil, retryable, readErr
	}

	if resp.StatusCode != http.StatusOK {
		retryable := isRetryableStatus(resp.StatusCode)
		c.emit(ctx, HTTPStatusError{
			Query:      query,
			Attempt:    attempt,
			StatusCode: resp.StatusCode,
			Retryable:  retryable,
			Body:       string(body),
		})
		return nil, retryable, fmt.Errorf("crtsh: status %d", resp.StatusCode)
	}

	var raw []rawCertificate
	if decErr := json.Unmarshal(body, &raw); decErr != nil {
		retryable := looksLikeHTML(body)
		c.emit(ctx, JSONParseError{
			Query:     query,
			Attempt:   attempt,
			Retryable: retryable,
			Err:       decErr,
			BodyBytes: len(body),
		})
		return nil, retryable, decErr
	}

	certs := make([]Certificate, 0, len(raw))
	for i := range raw {
		cert, parseErr := parseCert(&raw[i])
		if parseErr != nil {
			c.emit(ctx, CertParseError{
				Query:   query,
				Attempt: attempt,
				Err:     parseErr,
				Raw:     string(raw[i].bytes()),
			})
			continue
		}
		c.emit(ctx, CertDiscovered{
			Query:  query,
			CertID: cert.ID,
			Issuer: cert.IssuerName,
			SANs:   len(cert.Domains),
		})
		certs = append(certs, cert)
	}

	return certs, false, nil
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

// countSubdomains counts the distinct domain names across a search's certificates,
// for the SearchCompleted metric.
func countSubdomains(certs []Certificate) int {
	seen := make(map[string]struct{})
	for i := range certs {
		for _, d := range certs[i].Domains {
			seen[d] = struct{}{}
		}
	}
	return len(seen)
}

// recordSearchOutcome feeds one finished search into the outage breaker and returns
// the event to emit when the outcome trips it. succeeded is whether the search
// reached crt.sh (any successful response); sawFailure is whether it saw at least one
// retryable crt.sh failure; parentCancelled is whether the parent context (not this
// search's own MaxQueryTime budget) ended it, in which case it is a scan shutdown, not
// a crt.sh outage, and must not count against crt.sh.
func (c *Client) recordSearchOutcome(succeeded, sawFailure, parentCancelled bool) (tooleventlog.Event, bool) {
	if succeeded {
		c.breaker.recordSuccess()
		return nil, false
	}
	if sawFailure && !parentCancelled {
		if n, tripped := c.breaker.recordOutage(); tripped {
			return OutageBreakerOpened{ConsecutiveOutages: n, Threshold: outageThreshold}, true
		}
	}
	return nil, false
}

// emitDeadlineGaveUp records a search that ended because its time budget ran out
// (MaxQueryTime or an ancestor crawl deadline) as a terminal failure, so an
// abandoned query is a visible failed call instead of vanishing silently. A plain
// cancellation (scan shutdown) is not a crt.sh failure and is left unrecorded.
func (c *Client) emitDeadlineGaveUp(ctx context.Context, query string, attempts int, lastErr error) {
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	c.emit(ctx, GaveUp{Query: query, TotalAttempts: attempts, LastErr: lastErr})
}

func (c *Client) emitRateLimited(ctx context.Context, query string, attempt int, err error) {
	if err != nil && strings.Contains(err.Error(), "status 429") {
		c.emit(ctx, RateLimited{Query: query, Attempt: attempt, Err: err})
	}
}

func (c *Client) wait(ctx context.Context, query string, attempt int, sleep time.Duration, lastErr error) error {
	select {
	case <-ctx.Done():
		c.emitRateLimited(ctx, query, attempt, lastErr)
		c.emitDeadlineGaveUp(ctx, query, attempt, lastErr)
		return ctx.Err()
	case <-time.After(sleep):
		return nil
	}
}
