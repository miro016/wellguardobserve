package websearch

import (
	"context"
	"fmt"
	"strings"

	serpapi "github.com/serpapi/serpapi-golang"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// defaultMaxResultsPerQuery caps URLs returned per single dork query.
const (
	defaultMaxResultsPerQuery = 20
	engineGoogle              = "google"
)

// Config holds configuration for the Client.
type Config struct {
	// APIKey is the SerpAPI API key. Required: the app injects it from the
	// SERPAPI_API_KEY environment variable rather than the config file, so the
	// secret stays out of the audit configuration.
	APIKey string
	// MaxResultsPerQuery caps the assets returned per dork query. Zero falls back
	// to defaultMaxResultsPerQuery.
	MaxResultsPerQuery int
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client performs passive asset discovery by running Google dork queries through
// SerpAPI. Each query targets a class of exposure (auth, admin, config files,
// backups, open directory listings, and so on) scoped to the root domain. Queries
// run sequentially to respect SerpAPI rate limits, and results are deduplicated
// by URL across all queries.
type Client struct {
	cfg      Config
	searcher searcher
}

// New validates cfg and returns a Client backed by the real SerpAPI SDK.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("websearch: Config.APIKey is required")
	}
	if cfg.MaxResultsPerQuery <= 0 {
		cfg.MaxResultsPerQuery = defaultMaxResultsPerQuery
	}
	client := serpapi.NewClient(serpapi.NewSerpApiClientSetting(cfg.APIKey))
	return &Client{cfg: cfg, searcher: &sdkSearcher{client: client}}, nil
}

// Asset is a single URL discovered through a dork query, with the host it lives
// on and the dork (and its category) that surfaced it.
type Asset struct {
	URL      string
	Host     string
	Dork     string
	Category string
	Snippet  string
}

// DomainAssets groups the assets discovered for a single domain.
type DomainAssets struct {
	Domain string
	Assets []Asset
}

// searcher abstracts the SerpAPI SDK for testability.
type searcher interface {
	search(params map[string]string) (map[string]any, error)
}

// sdkSearcher implements searcher using the real SerpAPI SDK.
type sdkSearcher struct {
	client serpapi.SerpApiClient
}

func (s *sdkSearcher) search(params map[string]string) (map[string]any, error) {
	return s.client.Search(params)
}

// Search runs the Google dork queries for domain and returns the deduplicated
// assets discovered. Every upstream row is checked against the requested root
// before it can become an asset, so a search engine that ignores the site:
// operator cannot inject third-party pages into the target. Individual query
// failures are reported as events and skipped, so partial results are still
// returned; only a cancelled context is a hard error.
func (c *Client) Search(ctx context.Context, domain string) (*DomainAssets, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.emit(ctx, SearchStarted{Domain: domain})

	seen := make(map[string]struct{})
	var assets []Asset
	var total, succeeded, failed int
	var results, accepted, rejected int
	var truncated, degraded bool

	for _, dork := range buildGoogleDorks(domain) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		total++

		out, err := c.runQuery(ctx, domain, dork)
		if err != nil {
			failed++
			degraded = true
			continue
		}
		succeeded++
		if out.truncated {
			truncated = true
		}
		results += out.results
		accepted += len(out.assets)
		rejected += out.rejected
		c.emit(ctx, QuerySucceeded{
			Domain:   domain,
			Dork:     dork.query,
			Category: dork.category,
			Results:  out.results,
			Accepted: len(out.assets),
			Rejected: out.rejected,
		})
		if out.rejected > 0 {
			c.emit(ctx, ResultsRejected{
				Domain:   domain,
				Dork:     dork.query,
				Category: dork.category,
				Results:  out.results,
				Accepted: len(out.assets),
				Rejected: out.rejected,
				Reasons:  out.reasons,
			})
		}

		for _, a := range out.assets {
			if _, ok := seen[a.URL]; ok {
				continue
			}
			seen[a.URL] = struct{}{}
			assets = append(assets, a)
			c.emit(ctx, AssetFound{
				Engine:   engineGoogle,
				Domain:   domain,
				URL:      a.URL,
				Host:     a.Host,
				Category: a.Category,
				Snippet:  a.Snippet,
			})
		}
	}

	c.emit(ctx, SearchCompleted{
		Domain:       domain,
		Assets:       len(assets),
		Results:      results,
		Accepted:     accepted,
		Rejected:     rejected,
		TotalQueries: total,
		Succeeded:    succeeded,
		Failed:       failed,
		Truncated:    truncated,
		Degraded:     degraded,
	})
	return &DomainAssets{Domain: domain, Assets: assets}, nil
}

// runQuery executes a single dork query against SerpAPI. A SerpAPI "no results"
// response is treated as an empty result, not an error.
func (c *Client) runQuery(ctx context.Context, domain string, dork expandedDork) (queryOutcome, error) {
	params := map[string]string{
		"engine": engineGoogle,
		"q":      dork.query,
		"num":    "20",
	}
	result, err := c.searcher.search(params)
	if err != nil {
		switch {
		case isSerpAPINoResults(err):
			return queryOutcome{}, nil
		case isRateLimitError(err):
			c.emit(ctx, RateLimited{Engine: engineGoogle, Domain: domain, Dork: dork.query, Category: dork.category, Attempt: 1, Err: err})
		case isSearchEngineBlockedError(err):
			c.emit(ctx, SearchEngineBlocked{Engine: engineGoogle, Domain: domain, Dork: dork.query, Category: dork.category, Reason: err.Error(), Err: err})
		default:
			c.emit(ctx, QueryFailed{Domain: domain, Dork: dork.query, Category: dork.category, Err: err})
		}
		return queryOutcome{}, fmt.Errorf("serpapi search: %w", err)
	}
	out, err := parseGoogleResults(result, dork, domain, c.cfg.MaxResultsPerQuery)
	if err != nil {
		snippet := fmt.Sprintf("%v", result)
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		c.emit(ctx, SERPParseError{Engine: engineGoogle, Domain: domain, Dork: dork.query, Category: dork.category, Snippet: snippet, Err: err})
		return queryOutcome{}, err
	}
	return out, nil
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "429") ||
		strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "throttled")
}

func isSearchEngineBlockedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "captcha") ||
		strings.Contains(msg, "turnstile") ||
		strings.Contains(msg, "blocked") ||
		strings.Contains(msg, "unusual traffic") ||
		strings.Contains(msg, "automated queries") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "403")
}

// isSerpAPINoResults reports whether the SerpAPI error indicates Google returned
// a valid response with zero organic results. These are not API failures.
func isSerpAPINoResults(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "hasn't returned any results") ||
		strings.Contains(msg, "has not returned any results") ||
		strings.Contains(msg, "did not return any results")
}

// queryOutcome is the accounting for one dork query. results is the upstream row
// count and partitions exactly into len(assets) plus rejected, so operator drift
// is measurable without the rejected rows becoming evidence about the target.
type queryOutcome struct {
	assets    []Asset
	results   int
	rejected  int
	reasons   map[string]int
	truncated bool
}

// parseGoogleResults extracts the root-owned assets from SerpAPI Google organic
// results, capped at maxResults and tagged with the dork's query and category.
// Rows on hosts the root does not own are counted by reason and dropped.
func parseGoogleResults(result map[string]any, dork expandedDork, root string, maxResults int) (queryOutcome, error) {
	if errVal, hasErr := result["error"]; hasErr {
		return queryOutcome{}, fmt.Errorf("serpapi error: %v", errVal)
	}
	if errVal, hasErr := result["error_message"]; hasErr {
		return queryOutcome{}, fmt.Errorf("serpapi error: %v", errVal)
	}
	organicRaw, ok := result["organic_results"]
	if !ok {
		if len(result) > 0 && result["search_metadata"] == nil {
			return queryOutcome{}, fmt.Errorf("missing organic_results in SERP layout")
		}
		return queryOutcome{}, nil
	}
	organic, ok := organicRaw.([]any)
	if !ok {
		return queryOutcome{}, fmt.Errorf("organic_results not a list")
	}

	out := queryOutcome{reasons: make(map[string]int)}
	for _, item := range organic {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		link, _ := m["link"].(string)
		if link == "" {
			continue
		}
		out.results++

		host, reason := classifyResult(link, root)
		if reason == "" && len(out.assets) >= maxResults {
			reason = reasonResultCap
			out.truncated = true
		}
		if reason != "" {
			out.rejected++
			out.reasons[reason]++
			continue
		}
		snippet, _ := m["snippet"].(string)
		out.assets = append(out.assets, Asset{
			URL:      link,
			Host:     host,
			Dork:     dork.query,
			Category: dork.category,
			Snippet:  snippet,
		})
	}
	if len(out.reasons) == 0 {
		out.reasons = nil
	}
	return out, nil
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}
