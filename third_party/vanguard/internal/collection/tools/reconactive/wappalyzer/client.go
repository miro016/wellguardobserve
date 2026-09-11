package wappalyzer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

const (
	defaultMaxRedirects = 10
	defaultMaxBodyBytes = 512 * 1024
	defaultUserAgent    = "vanguard-recon/1.0"
)

// errRedirectLimit ends an attempt whose redirect chain exceeded MaxRedirects. The
// http client wraps it in a *url.Error, so callers match it with errors.Is.
var errRedirectLimit = errors.New("redirect limit reached")

// Config holds configuration for the Client. Zero values take the package defaults;
// negative values are rejected by [New] rather than silently corrected, because a
// negative bound in a config file is a mistake, not an intent.
type Config struct {
	// Timeout bounds each HTTP attempt, redirects included. Required: there is no
	// sensible default for how long an operator will wait per target.
	Timeout time.Duration
	// MaxRedirects caps the redirect hops one attempt follows. Zero uses 10.
	MaxRedirects int
	// MaxBodyBytes is the hard cap on body bytes read for fingerprinting. Zero uses
	// 512 KiB. The cap is what keeps a hostile or endless body from exhausting memory.
	MaxBodyBytes int64
	// UserAgent is sent with every request. Empty uses "vanguard-recon/1.0".
	UserAgent string
	// ResolverAddr is the DNS server (host:port) names resolve through, so active
	// resolution matches the passive phase instead of drifting to the OS default.
	// Empty uses the system resolver.
	ResolverAddr string
	// Allow authorizes every normalized HTTP request host before traffic is sent.
	// Nil permits valid HTTP(S) targets for standalone use.
	Allow scopecheck.Allow
	// Exclusions is the hard traffic boundary enforced at dial time on both the HTTPS
	// attempt and the HTTP fallback, and on every redirect: a hostname is resolved
	// once, excluded answers are dropped, and only an allowed literal is dialed (the
	// hostname is kept for Host and TLS SNI). Nil excludes nothing (standalone use);
	// production injects the engagement exclusions.
	Exclusions *scopecheck.Exclusions
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client fingerprints web technologies with the embedded WappalyzerGo database. It
// owns its HTTP transport and its fingerprint engine, so it works with every other
// HTTP tool disabled. A Client is safe for concurrent use: the engine is read-only
// after construction.
type Client struct {
	cfg       Config
	engine    *wappalyzergo.Wappalyze
	transport *http.Transport
	// dialer is the shared resolver-aware policy dialer the transport dials through.
	// Tests may override its Resolver.
	dialer *scopecheck.PolicyDialer
}

// New validates cfg, compiles the embedded fingerprint database once, and returns a
// Client. A database that fails to compile is returned as an error and never
// swallowed: a tool that reports itself enabled must be able to do its job.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("wappalyzer: Config.Timeout must be positive")
	}
	if cfg.MaxRedirects < 0 {
		return nil, fmt.Errorf("wappalyzer: Config.MaxRedirects must not be negative")
	}
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("wappalyzer: Config.MaxBodyBytes must not be negative")
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = defaultMaxRedirects
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if strings.TrimSpace(cfg.UserAgent) == "" {
		cfg.UserAgent = defaultUserAgent
	}

	engine, err := wappalyzergo.New()
	if err != nil {
		return nil, fmt.Errorf("wappalyzer: load embedded fingerprints: %w", err)
	}

	// The transport dials through the shared policy dialer so every connection - the
	// HTTPS attempt, the HTTP fallback, and each redirect - is resolved once and
	// filtered against the exclusions before a socket opens. Ambient proxies stay
	// disabled (no Proxy field): a process proxy must not reach a rejected destination.
	dialer := &scopecheck.PolicyDialer{
		Exclusions: cfg.Exclusions,
		Resolver:   policyResolver(newResolver(cfg.ResolverAddr)),
		Dialer:     &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second},
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		// Reconnaissance, not a trust decision: an expired or self-signed certificate
		// must not hide the technologies behind it. Certificate validity is the
		// sibling https tool's subject.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
	}
	return &Client{cfg: cfg, engine: engine, transport: transport, dialer: dialer}, nil
}

// policyResolver adapts the client's *net.Resolver to the scopecheck.Resolver the
// policy dialer expects. A nil resolver stays nil so the dialer falls back to the
// system default rather than wrapping a nil pointer in a non-nil interface.
func policyResolver(r *net.Resolver) scopecheck.Resolver {
	if r == nil {
		return nil
	}
	return r
}

// newResolver returns a resolver that sends queries to addr (host:port), or nil for
// the system default when addr is empty. nil is a valid net.Dialer.Resolver, so
// callers wire it in unconditionally.
func newResolver(addr string) *net.Resolver {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// Probe fingerprints one domain: HTTPS first, HTTP only if HTTPS failed, redirects
// bounded, body capped, then the embedded database run against the final response.
// A non-2xx status is a normal outcome and is fingerprinted like any other; only a
// transport or body-read failure on both schemes fails the probe. The returned error
// is non-fatal to a scan - the caller records it and moves to the next domain.
func (c *Client) Probe(ctx context.Context, domain string) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	domain, err := normalizeDomain(domain)
	if err != nil {
		c.emit(ctx, ProbeFailed{Domain: domain, Err: err})
		return nil, fmt.Errorf("wappalyzer: %w", err)
	}

	httpsURL := "https://" + domain
	c.emit(ctx, ProbeStarted{Domain: domain, URL: httpsURL})

	att, httpsErr := c.attempt(ctx, domain, httpsURL)
	trail := attemptTrail(att)
	if httpsErr != nil {
		// HTTP fallback is for HTTPS transport/body failures. A cancelled call, a
		// redirect loop, or a redirect outside scope is already a final outcome;
		// retrying it over plaintext hides the real failure and may send extra traffic.
		if !allowsHTTPFallback(ctx, httpsErr) {
			err := fmt.Errorf("probe %s failed via https: %w", domain, httpsErr)
			c.emit(ctx, ProbeFailed{Domain: domain, URL: httpsURL, Err: err})
			c.emit(ctx, ProbeCompleted{Domain: domain, Degraded: true})
			return &Result{Domain: domain, RedirectTrail: trail}, fmt.Errorf("wappalyzer: %w", err)
		}
		var httpErr error
		att, httpErr = c.attempt(ctx, domain, "http://"+domain)
		trail = append(trail, attemptTrail(att)...)
		if httpErr != nil {
			err := fmt.Errorf("probe %s failed via https (%w) and http (%w)", domain, httpsErr, httpErr)
			c.emit(ctx, ProbeFailed{Domain: domain, URL: httpsURL, Err: err})
			c.emit(ctx, ProbeCompleted{Domain: domain, Degraded: true})
			return &Result{Domain: domain, RedirectTrail: trail}, fmt.Errorf("wappalyzer: %w", err)
		}
	}

	result := &Result{
		Domain:          domain,
		FinalURL:        att.finalURL,
		Scheme:          schemeOf(att.finalURL),
		StatusCode:      att.statusCode,
		Title:           extractTitle(att.body),
		Server:          att.header.Get("Server"),
		Headers:         headerNames(att.header),
		WWWAuthenticate: att.header.Get("WWW-Authenticate"),
		LoginForm:       hasPasswordInput(att.body),
		BodyBytes:       len(att.body),
		Redirects:       att.redirects,
		RedirectTrail:   trail,
		Technologies:    fingerprint(c.engine, att.header, att.body),
	}

	for _, tech := range result.Technologies {
		c.emit(ctx, TechnologyDiscovered{
			Domain: domain, URL: result.FinalURL,
			TechName: tech.Name, Version: tech.Version,
			Categories: tech.Categories, CPEs: tech.CPEs,
		})
	}
	c.emit(ctx, ProbeCompleted{
		Domain:     domain,
		FinalURL:   result.FinalURL,
		StatusCode: result.StatusCode,
		Matches:    len(result.Technologies),
		BodyBytes:  result.BodyBytes,
		Redirects:  result.Redirects,
	})
	return result, nil
}

// attemptResult is one scheme's bounded GET outcome. The body lives only long enough
// to be fingerprinted; it never leaves the package.
type attemptResult struct {
	finalURL   string
	statusCode int
	header     http.Header
	body       []byte
	redirects  int
	trail      []scopecheck.RedirectObservation
}

// attempt performs one bounded GET against rawURL. Every failure path emits its
// granular event before returning, so an operator can tell a refused connection from
// a timeout from a truncated body without reading Go error text.
func (c *Client) attempt(ctx context.Context, domain, rawURL string) (*attemptResult, error) {
	hops := 0
	trail := make([]scopecheck.RedirectObservation, 0, c.cfg.MaxRedirects)
	client := &http.Client{
		Timeout:   c.cfg.Timeout,
		Transport: c.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > c.cfg.MaxRedirects {
				c.emit(req.Context(), RedirectLimitReached{
					Domain: domain, URL: req.URL.String(), Limit: c.cfg.MaxRedirects,
				})
				return errRedirectLimit
			}
			last := via[len(via)-1]
			status := 0
			if req.Response != nil {
				status = req.Response.StatusCode
			}
			hop := len(via)
			observation := scopecheck.RedirectObservation{
				FromURL: last.URL.String(), ToURL: req.URL.String(), Status: status, Hop: hop,
			}
			if err := scopecheck.Check(req.Context(), c.cfg.Allow, req.URL); err != nil {
				var rejected *scopecheck.RejectedError
				if errors.As(err, &rejected) {
					observation.Disposition = scopecheck.DispositionRejected
					observation.Reason = rejected.Reason
					trail = append(trail, observation)
					c.emit(req.Context(), RedirectRejected{
						Domain: domain, FromURL: observation.FromURL, ToURL: observation.ToURL,
						Status: status, Hop: hop, Reason: rejected.Reason,
					})
				}
				return fmt.Errorf("authorize redirect to %s: %w", req.URL, err)
			}
			hops++
			observation.Disposition = scopecheck.DispositionFollowed
			trail = append(trail, observation)
			c.emit(req.Context(), RedirectFollowed{
				Domain: domain, FromURL: last.URL.String(), ToURL: req.URL.String(),
				Status: status, Hop: hops,
			})
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		c.emit(ctx, ProbeFailed{Domain: domain, URL: rawURL, Err: err})
		return nil, fmt.Errorf("build request for %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if err := scopecheck.Check(ctx, c.cfg.Allow, req.URL); err != nil {
		c.emit(ctx, ProbeFailed{Domain: domain, URL: rawURL, Err: err})
		return &attemptResult{trail: trail}, fmt.Errorf("authorize request %s: %w", rawURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.emitTransportErr(ctx, domain, rawURL, err)
		return &attemptResult{redirects: hops, trail: trail}, fmt.Errorf("get %s: %w", rawURL, err)
	}
	body, readErr := readCapped(resp.Body, c.cfg.MaxBodyBytes)
	_ = resp.Body.Close()
	if readErr != nil {
		c.emit(ctx, BodyReadFailed{Domain: domain, URL: rawURL, BytesRead: len(body), Err: readErr})
		return &attemptResult{redirects: hops, trail: trail}, fmt.Errorf("read body of %s: %w", rawURL, readErr)
	}

	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	// A 429 is reported but not treated as a failure: the response still carries CDN
	// and WAF signatures worth fingerprinting.
	if resp.StatusCode == http.StatusTooManyRequests {
		c.emit(ctx, RateLimited{Domain: domain, URL: finalURL, StatusCode: resp.StatusCode})
	}
	return &attemptResult{
		finalURL:   finalURL,
		statusCode: resp.StatusCode,
		header:     resp.Header.Clone(),
		body:       body,
		redirects:  hops,
		trail:      trail,
	}, nil
}

// emitTransportErr classifies a client.Do error into the granular event that names
// the actual failure, falling back to ProbeFailed only for errors none of them fit.
func (c *Client) emitTransportErr(ctx context.Context, domain, rawURL string, err error) {
	var rejected *scopecheck.RejectedError
	if errors.Is(err, errRedirectLimit) || errors.As(err, &rejected) {
		// CheckRedirect emitted the event with the exact rejected URL.
		return
	}
	if isTimeout(err) {
		c.emit(ctx, ConnectionTimeout{Domain: domain, URL: rawURL, Timeout: c.cfg.Timeout.String()})
		return
	}
	errStr := strings.ToLower(err.Error())
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "server misbehaving") {
		c.emit(ctx, DNSResolutionFailed{Domain: domain, URL: rawURL, Err: err})
		return
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(errStr, "refused") {
		c.emit(ctx, ConnectionRefused{Domain: domain, URL: rawURL})
		return
	}
	// ErrSchemeMismatch is the plaintext-HTTP-on-an-HTTPS-request case: there is no
	// TLS on that port at all. It belongs with the handshake failures, and it is what
	// makes the HTTP fallback fire for a plaintext-only host.
	var tlsErr *tls.RecordHeaderError
	if errors.Is(err, http.ErrSchemeMismatch) || errors.As(err, &tlsErr) ||
		strings.Contains(errStr, "tls:") || strings.Contains(errStr, "handshake") {
		c.emit(ctx, TLSHandshakeFailed{Domain: domain, URL: rawURL, Err: err})
		return
	}
	c.emit(ctx, ProbeFailed{Domain: domain, URL: rawURL, Err: err})
}

// allowsHTTPFallback reports whether an HTTPS failure means trying plaintext HTTP
// can add signal. Policy failures and caller cancellation are final.
func allowsHTTPFallback(ctx context.Context, err error) bool {
	return ctx.Err() == nil &&
		!errors.Is(err, errRedirectLimit) &&
		!isPolicyRejection(err)
}

func isPolicyRejection(err error) bool {
	var rejected *scopecheck.RejectedError
	return errors.As(err, &rejected)
}

func attemptTrail(att *attemptResult) []scopecheck.RedirectObservation {
	if att == nil {
		return nil
	}
	return append([]scopecheck.RedirectObservation(nil), att.trail...)
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

// readCapped reads at most maxBytes. It reads one byte past the cap to detect an
// oversized body and then truncates, so the cap is a hard limit on retained bytes.
func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return b, err
	}
	if int64(len(b)) > maxBytes {
		return b[:maxBytes], nil
	}
	return b, nil
}

// normalizeDomain trims, lower-cases, and drops a trailing root dot. It rejects
// anything that is not a bare host: a URL, a path, or embedded whitespace means the
// caller passed the wrong thing, and guessing would probe an unintended target.
func normalizeDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", errors.New("domain is empty")
	}
	if strings.ContainsAny(d, " \t\r\n/?#@") || strings.Contains(d, "://") {
		return "", fmt.Errorf("domain %q is not a bare host name", domain)
	}
	return d, nil
}

// schemeOf returns the scheme of a URL, empty when it cannot be parsed.
func schemeOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}
