package webinfo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

const (
	defaultMaxRedirects = 10
	defaultMaxBodyBytes = 512 * 1024
)

// Config holds configuration for the Client.
type Config struct {
	// Timeout bounds each HTTP probe / page fetch.
	Timeout time.Duration
	// MaxRedirects caps redirects followed before the probe gives up. Zero falls
	// back to defaultMaxRedirects.
	MaxRedirects int
	// MaxBodyBytes caps the page body read for stack detection. Zero falls back to
	// defaultMaxBodyBytes.
	MaxBodyBytes int64
	// ResolverAddr is the DNS server (host:port) the probe resolves names through,
	// so active resolution matches the passive phase (which uses the configured
	// resolver, not the OS default). Empty means the system resolver. Each redirect
	// hop is resolved through it too. Sharing the passive resolver removes the
	// divergence where the passive phase resolves a name the active phase then
	// fails to look up.
	ResolverAddr string
	// Allow authorizes every normalized HTTP request host before traffic is sent.
	// Nil permits valid HTTP(S) targets for standalone use.
	Allow scopecheck.Allow
	// Exclusions is the hard traffic boundary enforced at dial time on both the HEAD
	// metadata request and the GET page fetch, and on every redirect in each chain: a
	// hostname is resolved once, excluded answers are dropped, and only an allowed
	// literal is dialed. Nil excludes nothing (standalone use); production injects the
	// engagement exclusions.
	Exclusions *scopecheck.Exclusions
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

type probeStats struct {
	totalUrls         int
	successfulFetches int
	failedFetches     int
	timeouts          int
	policyRejections  int
}

// Client probes a domain's web presence via active HTTP connections: it follows
// redirects to capture the final response metadata (status, server, headers, TLS)
// and fetches the home page to detect the technology stack (CMS, plugins, JS/CSS
// libraries, CDN, hosting, and external services).
type Client struct {
	cfg      Config
	resolver *net.Resolver
	// dialer is the shared resolver-aware policy dialer both request chains use.
	// Tests may override its Resolver.
	dialer *scopecheck.PolicyDialer
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("webinfo: Config.Timeout must be positive")
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = defaultMaxRedirects
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	resolver := newResolver(cfg.ResolverAddr)
	dialer := &scopecheck.PolicyDialer{
		Exclusions: cfg.Exclusions,
		Resolver:   policyResolver(resolver),
		Dialer:     &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second},
	}
	return &Client{cfg: cfg, resolver: resolver, dialer: dialer}, nil
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

// newResolver returns a *net.Resolver that sends queries to addr (host:port), or
// nil for the system default when addr is empty. nil is a valid value for
// net.Dialer.Resolver, so callers wire it in unconditionally.
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

// Probe runs the HTTP probe and technology-stack detection for domain. The HTTP
// probe is the core step: if it fails over both HTTPS and HTTP the probe returns
// an error. A failed page fetch is non-fatal (no stack is detected).
func (c *Client) Probe(ctx context.Context, domain string) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		err := fmt.Errorf("webinfo: domain is empty")
		c.emit(ctx, ProbeFailed{Domain: domain, Err: err})
		return nil, err
	}
	c.emit(ctx, ProbeStarted{Domain: domain, UrlsCount: 2})

	stats := &probeStats{}
	httpResult, err := c.lookupHTTP(ctx, domain, stats)
	result := &Result{Domain: domain, HTTP: httpResult}
	if httpResult != nil {
		result.RedirectTrail = append(result.RedirectTrail, httpResult.Redirects...)
	}
	if err != nil {
		c.emit(ctx, ProbeFailed{Domain: domain, Err: err})
		c.emit(ctx, ProbeCompleted{
			Domain:            domain,
			TotalUrls:         stats.totalUrls,
			SuccessfulFetches: stats.successfulFetches,
			FailedFetches:     stats.failedFetches,
			Timeouts:          stats.timeouts,
			PolicyRejections:  stats.policyRejections,
			Degraded:          true,
		})
		return result, fmt.Errorf("webinfo: %w", err)
	}

	if page, pageErr := c.fetchPage(ctx, domain, stats); pageErr != nil {
		if page != nil {
			result.RedirectTrail = append(result.RedirectTrail, page.RedirectTrail...)
		}
		c.emit(ctx, PageFetchFailed{Domain: domain, Err: pageErr})
	} else {
		result.RedirectTrail = append(result.RedirectTrail, page.RedirectTrail...)
		result.Stack = DetectStack(page.Headers, page.Body, domain)
		result.LoginForm = HasPasswordInput(page.Body)
		c.emitTechnologyEvents(ctx, page.BaseURL, result.Stack)
	}

	c.emit(ctx, ProbeCompleted{
		Domain:            domain,
		FinalURL:          httpResult.FinalURL,
		StatusCode:        httpResult.StatusCode,
		CMS:               stackCMS(result.Stack),
		Technologies:      countTechnologies(result.Stack),
		TotalUrls:         stats.totalUrls,
		SuccessfulFetches: stats.successfulFetches,
		FailedFetches:     stats.failedFetches,
		Timeouts:          stats.timeouts,
		PolicyRejections:  stats.policyRejections,
		Degraded:          stats.failedFetches > 0 || stats.timeouts > 0,
	})
	return result, nil
}

func stackCMS(s *StackResult) string {
	if s == nil {
		return ""
	}
	return s.CMS
}

// countTechnologies counts the distinct stack signals detected, used only for the
// completion event summary.
func countTechnologies(s *StackResult) int {
	if s == nil {
		return 0
	}
	n := len(s.Plugins) + len(s.JSLibs) + len(s.CSSLibs)
	for _, v := range []string{s.CMS, s.Server, s.PoweredBy, s.CDN, s.Hosting} {
		if v != "" {
			n++
		}
	}
	return n
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func (c *Client) emitTechnologyEvents(ctx context.Context, u string, s *StackResult) {
	if s == nil {
		return
	}
	if s.CMS != "" {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: s.CMS, Category: "CMS"})
	}
	for _, p := range s.Plugins {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: p, Category: "CMS Plugin"})
	}
	if s.Server != "" {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: s.Server, Category: "Web Server"})
	}
	if s.PoweredBy != "" {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: s.PoweredBy, Category: "Web Framework"})
	}
	if s.CDN != "" {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: s.CDN, Category: "CDN"})
	}
	if s.Hosting != "" {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: s.Hosting, Category: "Hosting"})
	}
	for _, js := range s.JSLibs {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: js, Category: "JavaScript Framework"})
	}
	for _, css := range s.CSSLibs {
		c.emit(ctx, TechnologyDiscovered{URL: u, TechName: css, Category: "CSS Framework"})
	}
}

//nolint:gocyclo // WAF detection requires checking numerous distinct header and body patterns
func detectWAF(statusCode int, headers http.Header, body []byte) string {
	lowerHeaders := strings.ToLower(fmt.Sprintf("%v", headers))
	lowerBody := strings.ToLower(string(body))

	if strings.Contains(lowerHeaders, "cloudflare") || headers.Get("Cf-Ray") != "" || strings.Contains(lowerBody, "cloudflare") {
		if statusCode == 403 || statusCode == 503 || strings.Contains(lowerBody, "attention required! | cloudflare") || strings.Contains(lowerBody, "just a moment...") || strings.Contains(lowerBody, "cf-browser-verification") {
			return "Cloudflare"
		}
	}
	if strings.Contains(lowerHeaders, "akamai") || headers.Get("X-Akamai-Transformed") != "" || strings.Contains(lowerBody, "akamai") {
		if statusCode == 403 || strings.Contains(lowerBody, "access denied") {
			return "Akamai"
		}
	}
	if strings.Contains(lowerHeaders, "sucuri") || strings.Contains(lowerBody, "sucuri website firewall") {
		return "Sucuri"
	}
	if strings.Contains(lowerHeaders, "imperva") || strings.Contains(lowerHeaders, "incapsula") || strings.Contains(lowerBody, "incapsula incident id") {
		return "Imperva"
	}
	if headers.Get("X-Amzn-Waf-Action") != "" || strings.Contains(lowerBody, "awswaf") {
		return "AWS WAF"
	}
	if statusCode == 403 && (strings.Contains(lowerBody, "waf") || strings.Contains(lowerBody, "firewall") || strings.Contains(lowerBody, "blocked") || strings.Contains(lowerBody, "access denied")) {
		return "Generic WAF"
	}
	return ""
}

func checkHTMLSyntax(body []byte) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	s := string(body)
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}

		if next, raw, err := skipRawTextElement(s, i); raw {
			if err != nil {
				return htmlSnippet(s[i:]), err
			}
			i = next
			continue
		}

		j := strings.IndexByte(s[i:], '>')
		k := strings.IndexByte(s[i+1:], '<')
		if j == -1 {
			return htmlSnippet(s[i:]), fmt.Errorf("unclosed tag at byte offset %d", i)
		}
		if k != -1 && (i+1+k) < (i+j) {
			return htmlSnippet(s[i : i+j+1]), fmt.Errorf("malformed tag (nested <) at byte offset %d", i)
		}
	}
	return "", nil
}

func skipRawTextElement(s string, offset int) (next int, raw bool, err error) {
	lower := strings.ToLower(s[offset:])
	var tag string
	switch {
	case strings.HasPrefix(lower, "<script"):
		tag = "script"
	case strings.HasPrefix(lower, "<style"):
		tag = "style"
	default:
		return offset, false, nil
	}
	openEnd := strings.IndexByte(s[offset:], '>')
	if openEnd == -1 {
		return offset, true, fmt.Errorf("unclosed tag at byte offset %d", offset)
	}
	searchFrom := offset + openEnd + 1
	closeStart := strings.Index(strings.ToLower(s[searchFrom:]), "</"+tag)
	if closeStart == -1 {
		return len(s) - 1, true, nil
	}
	closeEnd := strings.IndexByte(s[searchFrom+closeStart:], '>')
	if closeEnd == -1 {
		return len(s) - 1, true, nil
	}
	return searchFrom + closeStart + closeEnd, true, nil
}

func htmlSnippet(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.ToValidUTF8(s, "")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func recordFetchError(stats *probeStats, err error) {
	if stats == nil {
		return
	}
	if isPolicyRejection(err) {
		stats.policyRejections++
		return
	}
	stats.failedFetches++
	if isTimeoutError(err) {
		stats.timeouts++
	}
}
