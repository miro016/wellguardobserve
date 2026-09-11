package certspotter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"golang.org/x/sync/singleflight"
)

// Config holds configuration for the Client.
type Config struct {
	// BaseURL is the certspotter API endpoint. Defaults to
	// "https://api.certspotter.com".
	BaseURL string
	// APIKey is the optional SSLMate certspotter API token. It is supplied via the
	// CERTSPOTTER_API_KEY environment variable for higher rate limits; the public
	// endpoint also serves unauthenticated queries (more tightly rate limited), so
	// the key is optional, not required.
	APIKey string
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration
	// MaxBodyBytes caps the response body size to prevent unbounded memory use.
	MaxBodyBytes int64
	// MaxPages caps how many result pages are fetched (certspotter paginates by an
	// "after" cursor). Defaults to 1.
	MaxPages int
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client queries the SSLMate certspotter API, a second Certificate Transparency
// aggregator used to cross-check the crt.sh crawler's subdomain coverage.
type Client struct {
	cfg  Config
	http *http.Client
	// sf collapses concurrent identical queries into a single HTTP fetch (see fetch).
	sf singleflight.Group
}

// New validates cfg and returns a Client. cfg is taken by pointer (it is a heavy
// struct) and copied; the caller's value is not mutated.
func New(cfg *Config) (*Client, error) {
	conf := *cfg
	if conf.BaseURL == "" {
		conf.BaseURL = "https://api.certspotter.com"
	}
	if conf.MaxPages <= 0 {
		conf.MaxPages = 1
	}
	return &Client{
		cfg:  conf,
		http: &http.Client{Timeout: conf.Timeout},
	}, nil
}

// issuance is one certspotter CT issuance, reduced to the DNS names it covers.
type issuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	SHA256    string   `json:"cert_sha256"`
	TBSSHA256 string   `json:"tbs_sha256"`
}

func (i issuance) fingerprint() string {
	if i.SHA256 != "" {
		return i.SHA256
	}
	if i.TBSSHA256 != "" {
		return i.TBSSHA256
	}
	return i.ID
}

// Subdomains returns the distinct in-scope DNS names certspotter has seen in CT
// logs for domain and its subdomains. It is the second CT corroborator the
// orchestrator compares against the crt.sh crawler's coverage: a materially
// shorter crt.sh set against this one signals a truncated crt.sh response.
func (c *Client) Subdomains(ctx context.Context, domain string) ([]string, error) {
	out, _, err := c.fetch(ctx, domain)
	return out, err
}

// Certs reports whether certspotter has seen any current certificate issuance for
// domain, alongside the distinct in-scope DNS names those issuances carry. present
// is true when any issuance was returned at all - before the in-scope name filter -
// so it is the binary "certspotter is not empty for this query" signal the
// degraded-empty corroboration consumes.
//
// present can be true with len(names) == 0: an issuance existed but all its SANs were
// out of the queried scope (for example a shared wildcard certificate). That still
// proves the host is not certless, which is what the corroboration decision needs.
//
// certspotter serves only currently-valid certificates, so present reflects live
// issuance rather than full CT history. Any error (including a 429 rate limit) is
// surfaced to the caller, which treats it as "no corroboration".
func (c *Client) Certs(ctx context.Context, domain string) (names []string, present bool, err error) {
	return c.fetch(ctx, domain)
}

// fetch is the shared core of Subdomains and Certs. It dedupes concurrent identical
// queries: the degraded-empty corroboration and the discovery cross-check can both
// query certspotter for the same root at the same instant (see the orchestration
// package), and the keyless tier answers one of two concurrent requests with a 429. A
// per-domain singleflight collapses them into one HTTP fetch whose result both callers
// share, removing the self-inflicted rate limit and the duplicate work. It is not a
// cache: singleflight releases the key once the call returns, so a later query for the
// same domain re-fetches.
func (c *Client) fetch(ctx context.Context, domain string) (names []string, sawIssuance bool, err error) {
	v, err, _ := c.sf.Do(domain, func() (any, error) {
		n, saw, ferr := c.fetchOnce(ctx, domain)
		if ferr != nil {
			return nil, ferr
		}
		return fetchResult{names: n, sawIssuance: saw}, nil
	})
	if err != nil {
		return nil, false, err
	}
	r := v.(fetchResult)
	return r.names, r.sawIssuance, nil
}

// fetchResult carries fetchOnce's two success values across the singleflight any
// boundary.
type fetchResult struct {
	names       []string
	sawIssuance bool
}

// fetchOnce walks the certspotter issuance pages for domain, accumulating the distinct
// in-scope DNS names and reporting whether any issuance was seen at all. sawIssuance
// is set as soon as a page returns a non-empty batch, before and independent of the
// in-scope filter, so a live certificate whose SANs are all out of scope still counts
// as "not empty".
func (c *Client) fetchOnce(ctx context.Context, domain string) (names []string, sawIssuance bool, err error) {
	c.emit(ctx, QueryStarted{Domain: domain})

	var (
		certs     int
		pages     int
		successes int
		failures  int
		truncated bool
	)
	seen := make(map[string]struct{})
	defer func() {
		c.emit(ctx, SearchCompleted{
			Domain:     domain,
			Certs:      certs,
			Subdomains: len(seen),
			Pages:      pages,
			Successes:  successes,
			Failures:   failures,
			Truncated:  truncated,
		})
	}()

	after := ""
	for page := 0; page < c.cfg.MaxPages; page++ {
		if ctx.Err() != nil {
			failures++
			return nil, false, ctx.Err()
		}
		batch, ferr := c.fetchPage(ctx, domain, after)
		pages++
		if ferr != nil {
			failures++
			return nil, false, ferr
		}
		successes++
		if len(batch) == 0 {
			break
		}
		sawIssuance = true
		certs += len(batch)
		for i := range batch {
			c.emit(ctx, CertDiscovered{
				Domain:    domain,
				SHA256:    batch[i].fingerprint(),
				SANsCount: len(batch[i].DNSNames),
			})
			for _, name := range batch[i].DNSNames {
				if n := normalizeName(name); n != "" && inScope(n, domain) {
					seen[n] = struct{}{}
				}
			}
		}
		after = batch[len(batch)-1].ID
		if after == "" {
			break
		}
		if page == c.cfg.MaxPages-1 {
			truncated = true
		}
	}

	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, sawIssuance, nil
}

// fetchPage performs one HTTP request for a page of issuances.
func (c *Client) fetchPage(ctx context.Context, domain, after string) ([]issuance, error) {
	u, err := url.Parse(c.cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("certspotter: invalid base URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/issuances"
	q := u.Query()
	q.Set("domain", domain)
	q.Set("include_subdomains", "true")
	q.Set("expand", "dns_names")
	q.Set("limit", "256")
	if after != "" {
		q.Set("after", after)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		c.emit(ctx, QueryFailed{Domain: domain, Err: err})
		return nil, fmt.Errorf("certspotter: build request: %w", err)
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		c.emit(ctx, QueryFailed{Domain: domain, Err: err})
		return nil, fmt.Errorf("certspotter: request failed: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxBody()))
	_ = resp.Body.Close()
	if readErr != nil {
		c.emit(ctx, QueryFailed{Domain: domain, Err: readErr})
		return nil, fmt.Errorf("certspotter: read body: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			c.emit(ctx, RateLimited{Domain: domain, Attempt: 1, Err: fmt.Errorf("rate limit exceeded")})
			return nil, fmt.Errorf("certspotter: status %d (rate limit exceeded)", resp.StatusCode)
		case http.StatusUnauthorized, http.StatusForbidden:
			c.emit(ctx, PaidPlanRequired{Domain: domain, StatusCode: resp.StatusCode})
			return nil, fmt.Errorf("certspotter: status %d (paid plan required)", resp.StatusCode)
		default:
			c.emit(ctx, HTTPStatusError{
				Domain:     domain,
				StatusCode: resp.StatusCode,
				Body:       truncateSnippet(string(body), 512),
				Reason:     statusReason(resp.StatusCode),
			})
			return nil, fmt.Errorf("certspotter: status %d", resp.StatusCode)
		}
	}

	var batch []issuance
	if err := json.Unmarshal(body, &batch); err != nil {
		c.emit(ctx, JSONParseError{
			Domain:     domain,
			Err:        err,
			RawSnippet: truncateSnippet(string(body), 512),
			BodyBytes:  len(body),
		})
		return nil, fmt.Errorf("certspotter: decode response: %w", err)
	}
	return batch, nil
}

func statusReason(code int) string {
	switch code {
	case http.StatusUnauthorized:
		return "unauthorized (missing or invalid API token)"
	case http.StatusForbidden:
		return "forbidden (paid plan required or endpoint restricted)"
	case http.StatusTooManyRequests:
		return "rate limit exceeded"
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return "upstream service unavailable"
	default:
		return http.StatusText(code)
	}
}

func truncateSnippet(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}

func (c *Client) maxBody() int64 {
	if c.cfg.MaxBodyBytes > 0 {
		return c.cfg.MaxBodyBytes
	}
	return 10 << 20 // 10 MiB default guard
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

// normalizeName lowercases a CT DNS name and drops a wildcard prefix and trailing
// dot, so "*.Example.com." compares as "example.com".
func normalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	return name
}

// inScope reports whether name is the root domain or a subdomain of it, filtering
// any stray out-of-scope SAN a shared certificate might carry.
func inScope(name, root string) bool {
	return name == root || strings.HasSuffix(name, "."+root)
}
