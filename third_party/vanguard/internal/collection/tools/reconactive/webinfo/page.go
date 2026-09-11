package webinfo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// fetchPage fetches a domain home page over HTTPS (falling back to HTTP),
// follows redirects, and returns the response headers, body bytes (capped at
// Config.MaxBodyBytes), and base URL for stack analysis.
func (c *Client) fetchPage(ctx context.Context, domain string, stats *probeStats) (*PageData, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is empty")
	}

	page, httpsErr := c.fetchPageURL(ctx, "https://"+domain, stats)
	if httpsErr == nil {
		return page, nil
	}
	if isPolicyRejection(httpsErr) {
		return page, httpsErr
	}

	httpPage, httpErr := c.fetchPageURL(ctx, "http://"+domain, stats)
	if httpPage != nil {
		httpPage.RedirectTrail = append(pageRedirects(page), httpPage.RedirectTrail...)
	} else {
		httpPage = &PageData{RedirectTrail: pageRedirects(page)}
	}
	if httpErr == nil {
		return httpPage, nil
	}

	return httpPage, fmt.Errorf("fetch page for %s failed via https (%w) and http (%w)", domain, httpsErr, httpErr)
}

func (c *Client) fetchPageURL(ctx context.Context, rawURL string, stats *probeStats) (*PageData, error) {
	redirects := make([]scopecheck.RedirectObservation, 0, c.cfg.MaxRedirects)
	client := c.newHTTPClient(&redirects)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
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
		return &PageData{RedirectTrail: redirects}, fmt.Errorf("authorize request %s: %w", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		recordFetchError(stats, err)
		if errors.Is(err, errRedirectLimit) {
			c.emit(ctx, RedirectLoopDetected{URL: rawURL, HopsCount: c.cfg.MaxRedirects})
		}
		return &PageData{RedirectTrail: redirects}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if stats != nil {
		stats.successfulFetches++
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxBodyBytes))
	if err != nil {
		if stats != nil {
			stats.failedFetches++
			if isTimeoutError(err) {
				stats.timeouts++
			}
		}
		return &PageData{RedirectTrail: redirects}, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		c.emit(ctx, RateLimited{URL: rawURL, StatusCode: resp.StatusCode})
	}
	if wafName := detectWAF(resp.StatusCode, resp.Header, body); wafName != "" {
		c.emit(ctx, WAFBlocked{URL: rawURL, StatusCode: resp.StatusCode, WAFName: wafName})
	}
	if snippet, synErr := checkHTMLSyntax(body); synErr != nil {
		c.emit(ctx, HTMLParseError{URL: rawURL, Snippet: snippet, Err: synErr})
	}

	baseURL := resp.Request.URL.Scheme + "://" + resp.Request.URL.Host
	return &PageData{
		Headers:       resp.Header.Clone(),
		Body:          body,
		BaseURL:       baseURL,
		RedirectTrail: redirects,
	}, nil
}

func pageRedirects(page *PageData) []scopecheck.RedirectObservation {
	if page == nil {
		return nil
	}
	return append([]scopecheck.RedirectObservation(nil), page.RedirectTrail...)
}
