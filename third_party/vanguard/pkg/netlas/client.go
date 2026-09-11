package netlas

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public Netlas API host.
	DefaultBaseURL = "https://app.netlas.io"
	// PageSize is the fixed number of items Netlas returns per search page; the
	// Start offset advances in multiples of it.
	PageSize = 20

	// apiKeyHeader is the HTTP header Netlas authenticates requests with.
	apiKeyHeader = "X-Api-Key"
	// maxBodyBytes caps a single response body read so a runaway payload cannot
	// exhaust memory.
	maxBodyBytes = 8 << 20 // 8 MiB

	responsesPath = "/api/responses/"

	defaultTimeout = 30 * time.Second
)

// Client is a low-level HTTP wrapper over the Netlas REST API. It carries the API
// key and issues authenticated GET requests against the configured base URL,
// returning decoded envelopes. It is intentionally thin: it owns transport, auth,
// and error mapping, and leaves interpretation of the per-result data document to
// callers. Netlas is a paid service.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client (and thus its timeout). A nil
// value is ignored.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// New validates the API key and returns a Client. The key is required: Netlas
// rejects unauthenticated requests.
func New(apiKey string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("netlas: api key is required")
	}
	c := &Client{
		apiKey:  apiKey,
		baseURL: DefaultBaseURL,
		http:    &http.Client{Timeout: defaultTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// APIError is returned when Netlas responds with a non-2xx status. It carries the
// status code and the (truncated) response body to aid debugging of auth failures
// (401/403), quota exhaustion, and rate limiting (429).
type APIError struct {
	StatusCode int
	Body       string
}

// Error implements error.
func (e *APIError) Error() string {
	return fmt.Sprintf("netlas: http %d: %s", e.StatusCode, e.Body)
}

// SearchRequest describes a query against a Netlas search index.
type SearchRequest struct {
	// Query is the Netlas query-language expression (the q parameter), for example
	// "domain:example.com".
	Query string
	// Start is the pagination offset in items. It should be a multiple of PageSize.
	Start int
	// Fields optionally restricts the returned document fields (comma-separated).
	// When set, source_type=include is sent so only these fields are returned.
	Fields string
	// Indices optionally restricts the data indices searched.
	Indices string
}

// SearchResponse is the envelope the search endpoints return.
type SearchResponse struct {
	Items []SearchItem `json:"items"`
}

// SearchItem is one search hit. Data holds the raw result document; callers decode
// the fields they need from it.
type SearchItem struct {
	Data json.RawMessage `json:"data"`
}

// SearchResponses runs req against the responses (internet scan) index and returns
// one page of hits.
func (c *Client) SearchResponses(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	q := url.Values{}
	q.Set("q", req.Query)
	if req.Start > 0 {
		q.Set("start", strconv.Itoa(req.Start))
	}
	if req.Fields != "" {
		q.Set("fields", req.Fields)
		q.Set("source_type", "include")
	}
	if req.Indices != "" {
		q.Set("indices", req.Indices)
	}
	var out SearchResponse
	if err := c.get(ctx, responsesPath, q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// get issues an authenticated GET to path with query q and decodes the JSON body
// into out. A non-2xx status is returned as an *APIError carrying the body.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := c.baseURL + path
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("netlas: build request: %w", err)
	}
	httpReq.Header.Set(apiKeyHeader, c.apiKey)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("netlas: request %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("netlas: read %s body: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("netlas: decode %s: %w", path, err)
	}
	return nil
}
