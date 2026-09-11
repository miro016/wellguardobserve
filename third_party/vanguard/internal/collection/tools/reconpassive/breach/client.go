package breach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

// defaultBaseURL is the HaveIBeenPwned API host used when Config.BaseURL is empty.
const defaultBaseURL = "https://haveibeenpwned.com"

// maxErrorBody caps how many bytes of a response body are captured into error
// events, so a large or hostile response cannot bloat the event log.
const maxErrorBody = 8 << 10

// Config holds configuration for the Client.
type Config struct {
	// BaseURL is the HIBP API host. Empty falls back to defaultBaseURL.
	BaseURL string
	// APIKey is the HIBP API key. Required: HIBP rejects unauthenticated calls.
	// The app injects it from the HIBP_API_KEY environment variable rather than
	// the config file, so the secret stays out of the audit configuration.
	APIKey string
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client queries the HaveIBeenPwned API v3 /breachedDomain/{domain} endpoint,
// which returns the email aliases on a domain that appear in known data breaches
// together with the breach names. Usage requires a paid API key and prior domain
// verification on the HIBP dashboard (a 403 means the domain is not verified).
type Client struct {
	cfg    Config
	client *http.Client
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("breach: Config.APIKey is required")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("breach: Config.Timeout must be positive")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	return &Client{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}, nil
}

// Result holds the breach data for a domain.
type Result struct {
	// Aliases are the breached email aliases, sorted by alias for determinism.
	Aliases []BreachedAlias
}

// BreachedAlias records which breaches exposed a single email alias.
type BreachedAlias struct {
	// Alias is the local part of the email address (before the @).
	Alias string
	// Breaches are the names of the breaches that exposed the alias
	// (for example "Adobe", "LinkedIn").
	Breaches []string
}

// Lookup queries HIBP for breached email aliases on domain. It returns a Result
// with an empty Aliases slice when the domain has no breached aliases (HTTP 404).
// Every error path also emits a granular tool event before returning.
func (c *Client) Lookup(ctx context.Context, domain string) (*Result, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("breach: domain is empty")
	}

	endpoint := strings.TrimRight(c.cfg.BaseURL, "/") + "/api/v3/breachedDomain/" + url.PathEscape(domain)
	c.emit(ctx, LookupStarted{Domain: domain, Endpoint: endpoint})

	var (
		queries  int
		failed   int
		degraded bool
		aliases  int
	)
	defer func() {
		c.emit(ctx, LookupCompleted{
			Domain:   domain,
			Aliases:  aliases,
			Queries:  queries,
			Failed:   failed,
			Degraded: degraded,
		})
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		failed++
		c.emit(ctx, NetworkError{Domain: domain, Attempt: 1, Retryable: false, Err: err})
		return nil, fmt.Errorf("breach: create request for %q: %w", domain, err)
	}
	req.Header.Set("hibp-api-key", c.cfg.APIKey)
	req.Header.Set("user-agent", "vanguard-recon")

	queries++
	resp, err := c.client.Do(req)
	if err != nil {
		failed++
		retryable := !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		c.emit(ctx, NetworkError{Domain: domain, Attempt: 1, Retryable: retryable, Err: err})
		return nil, fmt.Errorf("breach: lookup for %q: %w", domain, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Fall through to decode below.
	case http.StatusNotFound:
		return &Result{}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		failed++
		c.emit(ctx, AuthFailed{Domain: domain, Endpoint: endpoint, StatusCode: resp.StatusCode})
		msg := statusMessage(resp.StatusCode, resp.Status)
		return nil, fmt.Errorf("breach: lookup for %q: %s: %w", domain, msg, toolerr.ErrProviderUnavailable)
	case http.StatusTooManyRequests:
		failed++
		c.emit(ctx, RateLimited{Domain: domain, Endpoint: endpoint, Attempt: 1, Err: errors.New("rate limit exceeded")})
		msg := statusMessage(resp.StatusCode, resp.Status)
		return nil, fmt.Errorf("breach: lookup for %q: %s: %w", domain, msg, toolerr.ErrProviderUnavailable)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		failed++
		c.emit(ctx, UpstreamServiceUnavailable{Domain: domain, StatusCode: resp.StatusCode, Retryable: true})
		msg := statusMessage(resp.StatusCode, resp.Status)
		return nil, fmt.Errorf("breach: lookup for %q: %s", domain, msg)
	default:
		failed++
		body := readErrorBody(resp.Body)
		msg := statusMessage(resp.StatusCode, resp.Status)
		c.emit(ctx, HTTPStatusError{Domain: domain, StatusCode: resp.StatusCode, Status: resp.Status, Body: body, Reason: msg})
		if isUnavailableStatus(resp.StatusCode) {
			return nil, fmt.Errorf("breach: lookup for %q: %s: %w", domain, msg, toolerr.ErrProviderUnavailable)
		}
		return nil, fmt.Errorf("breach: lookup for %q: %s", domain, msg)
	}

	result, derr := decodeResult(resp.Body)
	if derr != nil {
		failed++
		c.emit(ctx, JSONParsingError{Domain: domain, RawPayload: derr.body, BodyBytes: derr.bytes, Err: derr.err})
		return nil, fmt.Errorf("breach: decode response for %q: %w", domain, derr.err)
	}

	for _, a := range result.Aliases {
		c.emit(ctx, AliasExposed{Domain: domain, Alias: a.Alias, Breaches: a.Breaches})
	}
	aliases = len(result.Aliases)
	return result, nil
}

// decodeError carries both the decode error and the raw body, so the caller can
// attach the body to a JSONParsingError event for debugging.
type decodeError struct {
	err   error
	body  string
	bytes int
}

// decodeResult parses and sorts the alias map from a successful HIBP response.
// On a decode failure it returns the raw body alongside the error.
func decodeResult(body io.Reader) (*Result, *decodeError) {
	raw, err := io.ReadAll(io.LimitReader(body, maxErrorBody+1))
	if err != nil {
		return nil, &decodeError{err: err, bytes: len(raw)}
	}
	var aliasMap map[string][]string
	if err := json.Unmarshal(raw, &aliasMap); err != nil {
		return nil, &decodeError{err: err, body: truncateSnippet(string(raw), 512), bytes: len(raw)}
	}

	result := &Result{Aliases: make([]BreachedAlias, 0, len(aliasMap))}
	for alias, breaches := range aliasMap {
		result.Aliases = append(result.Aliases, BreachedAlias{
			Alias:    alias,
			Breaches: append([]string(nil), breaches...),
		})
	}
	sort.Slice(result.Aliases, func(i, j int) bool {
		return result.Aliases[i].Alias < result.Aliases[j].Alias
	})
	return result, nil
}

// isUnavailableStatus reports whether an HIBP error status is a key-level wall that
// will persist for the rest of the scan (bad key, unverified domain, or throttle),
// as opposed to a transient per-domain failure.
func isUnavailableStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

// statusMessage maps the known HIBP error statuses to operator-friendly text,
// falling back to the raw status for anything unexpected.
func statusMessage(code int, status string) string {
	switch code {
	case http.StatusUnauthorized:
		return "API key invalid"
	case http.StatusForbidden:
		return "domain not verified on HIBP dashboard"
	case http.StatusTooManyRequests:
		return "rate limit exceeded"
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return "upstream service unavailable (" + status + ")"
	default:
		return "unexpected status " + status
	}
}

func readErrorBody(body io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(body, maxErrorBody+1))
	if err != nil {
		return ""
	}
	return truncate(string(b))
}

func truncate(s string) string {
	return truncateSnippet(s, maxErrorBody)
}

func truncateSnippet(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}
