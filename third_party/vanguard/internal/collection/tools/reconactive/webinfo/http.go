package webinfo

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

var errRedirectLimit = errors.New("redirect limit reached")

var priorityHeaders = map[string]int{
	"server":                           0,
	"content-type":                     1,
	"x-powered-by":                     2,
	"strict-transport-security":        3,
	"content-security-policy":          4,
	"x-frame-options":                  5,
	"x-content-type-options":           6,
	"referrer-policy":                  7,
	"permissions-policy":               8,
	"cross-origin-opener-policy":       9,
	"cross-origin-resource-policy":     10,
	"cross-origin-embedder-policy":     11,
	"x-xss-protection":                 12,
	"access-control-allow-origin":      13,
	"access-control-allow-credentials": 14,
}

// lookupHTTP performs a HEAD probe over HTTPS, falling back to HTTP, following
// redirects, and returns the final response metadata.
func (c *Client) lookupHTTP(ctx context.Context, domain string, stats *probeStats) (*HTTPResult, error) {
	result, httpsErr := c.probeHTTP(ctx, "https://"+domain, stats)
	if httpsErr == nil {
		return result, nil
	}
	if isPolicyRejection(httpsErr) {
		return result, httpsErr
	}

	httpResult, httpErr := c.probeHTTP(ctx, "http://"+domain, stats)
	if httpResult != nil {
		httpResult.Redirects = append(resultRedirects(result), httpResult.Redirects...)
	} else {
		httpResult = &HTTPResult{Redirects: resultRedirects(result)}
	}
	if httpErr == nil {
		return httpResult, nil
	}

	return httpResult, fmt.Errorf("http probe for %s failed via https (%w) and http (%w)", domain, httpsErr, httpErr)
}

func (c *Client) probeHTTP(ctx context.Context, rawURL string, stats *probeStats) (*HTTPResult, error) {
	redirects := make([]scopecheck.RedirectObservation, 0, c.cfg.MaxRedirects)
	client := c.newHTTPClient(&redirects)
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if stats != nil {
		stats.totalUrls++
	}
	if err := scopecheck.Check(ctx, c.cfg.Allow, req.URL); err != nil {
		if stats != nil && isPolicyRejection(err) {
			stats.policyRejections++
		}
		return &HTTPResult{Redirects: redirects}, fmt.Errorf("authorize request %s: %w", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		recordFetchError(stats, err)
		if errors.Is(err, errRedirectLimit) {
			c.emit(ctx, RedirectLoopDetected{URL: rawURL, HopsCount: c.cfg.MaxRedirects})
		}
		return &HTTPResult{Redirects: redirects}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if stats != nil {
		stats.successfulFetches++
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		c.emit(ctx, RateLimited{URL: rawURL, StatusCode: resp.StatusCode})
	}
	if wafName := detectWAF(resp.StatusCode, resp.Header, nil); wafName != "" {
		c.emit(ctx, WAFBlocked{URL: rawURL, StatusCode: resp.StatusCode, WAFName: wafName})
	}

	result := &HTTPResult{
		FinalURL:       resp.Request.URL.String(),
		StatusCode:     resp.StatusCode,
		StatusText:     http.StatusText(resp.StatusCode),
		Redirects:      redirects,
		Headers:        sortedHeaders(resp.Header),
		ServerSoftware: resp.Header.Get("Server"),
	}
	if result.StatusText == "" {
		result.StatusText = resp.Status
	}
	if resp.TLS != nil {
		result.TLSVersion = tlsVersionName(resp.TLS.Version)
		result.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	return result, nil
}

func (c *Client) newHTTPClient(redirects *[]scopecheck.RedirectObservation) *http.Client {
	transport := &http.Transport{
		Proxy:           nil,
		DialContext:     c.dialer.DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{
		Timeout:   c.cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
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
					if redirects != nil {
						*redirects = append(*redirects, observation)
					}
					c.emit(req.Context(), RedirectRejected{
						FromURL: observation.FromURL, ToURL: observation.ToURL, Status: status, Hop: hop, Reason: rejected.Reason,
					})
				}
				return fmt.Errorf("authorize redirect to %s: %w", req.URL, err)
			}
			observation.Disposition = scopecheck.DispositionFollowed
			if redirects != nil {
				*redirects = append(*redirects, observation)
			}
			c.emit(req.Context(), RedirectFollowed{
				FromURL: observation.FromURL, ToURL: observation.ToURL, Status: status, Hop: hop,
			})
			return nil
		},
	}
}

func resultRedirects(result *HTTPResult) []scopecheck.RedirectObservation {
	if result == nil {
		return nil
	}
	return append([]scopecheck.RedirectObservation(nil), result.Redirects...)
}

func isPolicyRejection(err error) bool {
	var rejected *scopecheck.RejectedError
	return errors.As(err, &rejected)
}

func sortedHeaders(headers http.Header) []Header {
	result := make([]Header, 0, len(headers))
	for name, values := range headers {
		result = append(result, Header{
			Name:  name,
			Value: strings.Join(values, ", "),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		left := strings.ToLower(result[i].Name)
		right := strings.ToLower(result[j].Name)
		leftPriority, leftOK := priorityHeaders[left]
		rightPriority, rightOK := priorityHeaders[right]

		switch {
		case leftOK && rightOK && leftPriority != rightPriority:
			return leftPriority < rightPriority
		case leftOK != rightOK:
			return leftOK
		default:
			return left < right
		}
	})

	return result
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
