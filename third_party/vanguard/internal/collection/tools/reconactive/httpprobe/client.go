package httpprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// Config holds configuration for the Client.
type Config struct {
	// Timeout is the overall per-probe timeout.
	Timeout time.Duration
	// MaxRedirects caps redirect hops followed by each probe. Zero uses 10.
	MaxRedirects int
	// MaxBodyBytes caps the response body read to bound memory and fingerprinting.
	MaxBodyBytes int64
	// UserAgent is sent with each request. A default is used when empty.
	UserAgent string
	// Allow authorizes every normalized HTTP request host before traffic is sent.
	// Nil permits valid HTTP(S) targets for standalone use.
	Allow scopecheck.Allow
	// Exclusions is the hard traffic boundary enforced at dial time: the transport
	// resolves a hostname once, drops every excluded resolved address, and connects
	// only to an allowed literal, so no request or redirect can reach an excluded
	// address even after a domain-level check passes. Nil excludes nothing (standalone
	// use); production injects the engagement exclusions.
	Exclusions *scopecheck.Exclusions
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

const (
	defaultMaxRedirects = 10
	defaultMaxBodyBytes = 512 * 1024
	defaultUserAgent    = "vanguard-recon/1.0"
)

var errRedirectLimit = errors.New("redirect limit reached")

// Response holds the outcome of a single HTTP probe.
type Response struct {
	// URL is the probed URL.
	URL string
	// FinalURL is the URL after following redirects.
	FinalURL string
	// StatusCode is the HTTP status returned.
	StatusCode int
	// Title is the <title> contents, if present in the body.
	Title string
	// Header holds the response headers.
	Header http.Header
	// Body is the response body, capped at MaxBodyBytes.
	Body []byte
	// ContentLength is the response content length.
	ContentLength int64
	// RedirectTrail is the shared result contract for followed and rejected
	// decisions in request order.
	RedirectTrail []scopecheck.RedirectObservation
}

// Client performs HTTP GET probes.
type Client struct {
	cfg Config
	// dialer is the shared resolver-aware policy dialer both transports use. It
	// resolves once, drops excluded addresses, and dials an allowed literal. Tests
	// may override its Resolver to control resolution.
	dialer *scopecheck.PolicyDialer
	// client verifies TLS certificates (the default for named targets).
	client *http.Client
	// insecureClient skips TLS certificate verification, used by [Client.ProbeInsecure]
	// for bare-IP HTTPS where a public cert legitimately has no matching IP SAN.
	insecureClient *http.Client
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("httpprobe: Config.Timeout must be positive")
	}
	if cfg.MaxRedirects < 0 {
		return nil, fmt.Errorf("httpprobe: Config.MaxRedirects must not be negative")
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = defaultMaxRedirects
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}

	// Both transports dial through the shared policy dialer so every connection - the
	// initial request and each redirect, secure or insecure - is resolved once and
	// filtered against the exclusion policy before a socket opens. Ambient proxy
	// discovery is disabled: a process proxy must not be able to resolve or connect to
	// a destination the policy rejected.
	dialer := &scopecheck.PolicyDialer{
		Exclusions: cfg.Exclusions,
		Dialer:     &net.Dialer{Timeout: cfg.Timeout},
	}

	secureTransport := http.DefaultTransport.(*http.Transport).Clone()
	secureTransport.Proxy = nil
	secureTransport.DialContext = dialer.DialContext
	client := &http.Client{Timeout: cfg.Timeout, Transport: secureTransport}

	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.Proxy = nil
	insecureTransport.DialContext = dialer.DialContext
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // recon probe against a bare IP, not a trust decision
	insecureClient := &http.Client{Timeout: cfg.Timeout, Transport: insecureTransport}

	return &Client{cfg: cfg, dialer: dialer, client: client, insecureClient: insecureClient}, nil
}

// Probe performs a single GET against url and returns the response, verifying TLS
// certificates. The body is capped at Config.MaxBodyBytes.
func (c *Client) Probe(ctx context.Context, urlStr string) (*Response, error) {
	return c.probe(ctx, urlStr, c.client)
}

// ProbeInsecure is like [Client.Probe] but skips TLS certificate verification. It
// is for HTTPS probes against a bare IP literal, where a valid public certificate
// has no IP SAN and standard verification always fails. This is reconnaissance,
// not a trust decision: the goal is to observe status and headers, not to assert
// the certificate is valid.
func (c *Client) ProbeInsecure(ctx context.Context, urlStr string) (*Response, error) {
	return c.probe(ctx, urlStr, c.insecureClient)
}

// ProbeURLs performs concurrent HTTP GET probes against a batch of URLs for a target,
// summarizing execution metrics in a final ProbeCompleted event.
func (c *Client) ProbeURLs(ctx context.Context, target string, urls []string, concurrency int) ([]*Response, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	if concurrency <= 0 {
		concurrency = 5
	}
	ports := make([]int, 0, len(urls))
	for _, u := range urls {
		_, p := parseTargetAndPort(u)
		ports = append(ports, p)
	}
	c.emit(ctx, ProbeStarted{Target: target, URL: strings.Join(urls, ","), Ports: ports})

	var (
		totalProbes      = len(urls)
		successfulProbes int
		failedProbes     int
		timeouts         int
	)

	results := make([]*Response, len(urls))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, err := c.doProbe(ctx, target, urlStr, c.client)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failedProbes++
				if resp != nil && len(resp.RedirectTrail) > 0 {
					results[idx] = resp
				}
				if isTimeoutErr(err) {
					timeouts++
				}
			} else {
				successfulProbes++
				results[idx] = resp
			}
		}(i, u)
	}
	wg.Wait()

	degraded := failedProbes > 0 && successfulProbes > 0
	c.emit(ctx, ProbeCompleted{
		Target:           target,
		TotalProbes:      totalProbes,
		SuccessfulProbes: successfulProbes,
		FailedProbes:     failedProbes,
		Timeouts:         timeouts,
		Degraded:         degraded,
	})

	validResults := make([]*Response, 0, successfulProbes)
	for _, r := range results {
		if r != nil {
			validResults = append(validResults, r)
		}
	}
	return validResults, nil
}

func (c *Client) probe(ctx context.Context, urlStr string, hc *http.Client) (*Response, error) {
	target, port := parseTargetAndPort(urlStr)
	c.emit(ctx, ProbeStarted{Target: target, URL: urlStr, Ports: []int{port}})

	resp, err := c.doProbe(ctx, target, urlStr, hc)

	var timeouts int
	if err != nil && isTimeoutErr(err) {
		timeouts = 1
	}

	succeeded := 0
	failed := 0
	if err != nil {
		failed = 1
	} else {
		succeeded = 1
	}

	c.emit(ctx, ProbeCompleted{
		Target:           target,
		TotalProbes:      1,
		SuccessfulProbes: succeeded,
		FailedProbes:     failed,
		Timeouts:         timeouts,
		Degraded:         false,
	})
	return resp, err
}

func (c *Client) doProbe(ctx context.Context, target, urlStr string, hc *http.Client) (*Response, error) {
	result := &Response{URL: urlStr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		c.emitErr(ctx, target, urlStr, err)
		return nil, fmt.Errorf("httpprobe: build request for %s: %w", urlStr, err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if err := scopecheck.Check(ctx, c.cfg.Allow, req.URL); err != nil {
		c.emit(ctx, ProbeFailed{URL: urlStr, Err: err})
		return result, fmt.Errorf("httpprobe: authorize request %s: %w", urlStr, err)
	}

	client := *hc
	client.CheckRedirect = c.checkRedirect(target, &result.RedirectTrail)

	resp, err := client.Do(req)
	if err != nil {
		// A resolved-IP exclusion surfaces here as a *scopecheck.RejectedError from the
		// policy dialer. A redirect rejection already emitted RedirectRejected inside
		// checkRedirect, so only surface an initial-dial rejection as ProbeFailed; other
		// errors get the usual DNS/timeout/TLS classification. A rejection is a policy
		// decision and must never be mislabeled as a DNS or connection failure.
		var rejected *scopecheck.RejectedError
		if errors.As(err, &rejected) && !redirectWasRejected(result.RedirectTrail) {
			c.emit(ctx, ProbeFailed{URL: urlStr, Err: err})
		} else {
			c.emitErr(ctx, target, urlStr, err)
		}
		return result, fmt.Errorf("httpprobe: probe %s: %w", urlStr, err)
	}
	body, readErr := readCapped(resp.Body, c.cfg.MaxBodyBytes)
	_ = resp.Body.Close()
	if readErr != nil {
		c.emitErr(ctx, target, urlStr, readErr)
		return result, fmt.Errorf("httpprobe: read body for %s: %w", urlStr, readErr)
	}

	finalURL := urlStr
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		c.emit(ctx, RateLimited{Target: target, URL: urlStr, StatusCode: resp.StatusCode})
	}
	if wafName := detectWAF(resp.StatusCode, resp.Header, body); wafName != "" {
		c.emit(ctx, WAFBlocked{Target: target, URL: urlStr, WAFName: wafName})
	}

	c.emit(ctx, ProbeSucceeded{
		Target:        target,
		URL:           urlStr,
		FinalURL:      finalURL,
		StatusCode:    resp.StatusCode,
		Server:        resp.Header.Get("Server"),
		ContentLength: resp.ContentLength,
	})
	result.FinalURL = finalURL
	result.StatusCode = resp.StatusCode
	result.Title = extractTitle(body)
	result.Header = resp.Header
	result.Body = body
	result.ContentLength = resp.ContentLength
	return result, nil
}

func (c *Client) checkRedirect(target string, trail *[]scopecheck.RedirectObservation) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > c.cfg.MaxRedirects {
			return fmt.Errorf("stopped after %d redirects: %w", c.cfg.MaxRedirects, errRedirectLimit)
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
				*trail = append(*trail, observation)
				c.emit(req.Context(), RedirectRejected{
					Target: target, FromURL: observation.FromURL, ToURL: observation.ToURL,
					Status: status, Hop: hop, Reason: rejected.Reason,
				})
			}
			return fmt.Errorf("authorize redirect to %s: %w", req.URL, err)
		}
		observation.Disposition = scopecheck.DispositionFollowed
		*trail = append(*trail, observation)
		c.emit(req.Context(), RedirectFollowed{
			Target: target, FromURL: observation.FromURL, ToURL: observation.ToURL,
			Status: status, Hop: hop,
		})
		return nil
	}
}

// redirectWasRejected reports whether the last recorded redirect hop was rejected by
// policy, meaning checkRedirect already emitted its RedirectRejected event and the
// resulting client.Do error must not be re-reported as a ProbeFailed.
func redirectWasRejected(trail []scopecheck.RedirectObservation) bool {
	if len(trail) == 0 {
		return false
	}
	return trail[len(trail)-1].Disposition == scopecheck.DispositionRejected
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func (c *Client) emitErr(ctx context.Context, target, urlStr string, err error) {
	var rejected *scopecheck.RejectedError
	if errors.Is(err, errRedirectLimit) || errors.As(err, &rejected) {
		return
	}
	errStr := strings.ToLower(err.Error())
	var dnsErr *net.DNSError
	var certErr *x509.CertificateInvalidError
	var authErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var tlsErr *tls.RecordHeaderError

	if isTimeoutErr(err) {
		c.emit(ctx, ConnectionTimeout{Target: target, URL: urlStr, Timeout: c.cfg.Timeout})
		return
	}
	if errors.As(err, &dnsErr) || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "server misbehaving") || strings.Contains(errStr, "lookup ") {
		c.emit(ctx, DNSResolutionFailed{Target: target, Err: err})
		return
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(errStr, "refused") {
		_, port := parseTargetAndPort(urlStr)
		c.emit(ctx, ConnectionRefused{Target: target, URL: urlStr, Port: port})
		return
	}
	if errors.As(err, &certErr) || errors.As(err, &authErr) || errors.As(err, &hostErr) || errors.As(err, &tlsErr) || strings.Contains(errStr, "tls:") || strings.Contains(errStr, "certificate") || strings.Contains(errStr, "handshake") || strings.Contains(errStr, "remote error: tls:") {
		c.emit(ctx, TLSHandshakeFailed{Target: target, URL: urlStr, Err: err})
		return
	}
	c.emit(ctx, ProbeFailed{URL: urlStr, Err: err})
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	var urlErr *url.Error
	errStr := strings.ToLower(err.Error())
	return errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) ||
		(errors.As(err, &urlErr) && urlErr.Timeout()) ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded")
}

func parseTargetAndPort(urlStr string) (host string, port int) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr, 0
	}
	host = u.Hostname()
	if host == "" {
		host = u.Host
	}
	portStr := u.Port()
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return host, port
}

func detectWAF(status int, h http.Header, body []byte) string {
	switch status {
	case http.StatusForbidden, http.StatusServiceUnavailable, http.StatusNotAcceptable, http.StatusTooManyRequests:
	default:
		return ""
	}
	server := strings.ToLower(h.Get("Server"))
	bodyStr := strings.ToLower(string(body))

	if name := matchCloudflareAkamai(server, bodyStr, h); name != "" {
		return name
	}
	return matchOtherWAFs(server, bodyStr, h)
}

func matchCloudflareAkamai(server, bodyStr string, h http.Header) string {
	if strings.Contains(server, "cloudflare") || h.Get("cf-ray") != "" || strings.Contains(bodyStr, "cloudflare") || strings.Contains(bodyStr, "cf-browser-verification") {
		return "Cloudflare"
	}
	if strings.Contains(server, "akamaighost") || h.Get("Akamai-Reference-ID") != "" || strings.Contains(bodyStr, "akamai") {
		return "Akamai"
	}
	return ""
}

func matchOtherWAFs(server, bodyStr string, h http.Header) string {
	if h.Get("X-AMZN-ErrorType") != "" || strings.Contains(bodyStr, "awswaf") {
		return "AWS WAF"
	}
	if h.Get("X-Iinfo") != "" || h.Get("X-CDN") == "Incapsula" || strings.Contains(bodyStr, "incapsula") {
		return "Imperva/Incapsula"
	}
	if h.Get("X-WA-INFO") != "" || strings.Contains(bodyStr, "the requested url was rejected. please consult with your administrator") {
		return "F5 BIG-IP ASM"
	}
	if h.Get("X-Sucuri-ID") != "" || strings.Contains(server, "sucuri") || strings.Contains(bodyStr, "sucuri website firewall") {
		return "Sucuri"
	}
	return ""
}

func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := io.LimitReader(r, maxBytes+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return b[:maxBytes], nil
	}
	return b, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
