package virustotal

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// notFoundCode is the vt-go error Code returned (HTTP 404) when VirusTotal has
// never observed a domain. Treated as a clean empty result, not a failure.
const notFoundCode = "NotFoundError"

// ErrDomainNotFound is returned by [Client.Lookup] when VirusTotal has never
// observed the domain (HTTP 404). It signals a clean empty result, not a tool
// failure: callers should treat it as "no VT data for this domain" and skip it,
// not record it as an error. No [LookupFailed] event is emitted in this case.
var ErrDomainNotFound = errors.New("virustotal: domain not found")

// Default subdomain enumeration bounds, used when Config leaves them unset.
const (
	defaultMaxSubdomains     = 100
	defaultIteratorBatchSize = 40
)

// Config holds configuration for the Client.
type Config struct {
	// APIKey is the VirusTotal API key. Required: the app injects it from the
	// VIRUSTOTAL_API_KEY environment variable rather than the config file, so the
	// secret stays out of the audit configuration.
	APIKey string
	// EnableSubdomains turns on VirusTotal subdomain enumeration. It gates the
	// orchestrator's call to [Client.Subdomains]; the reputation lookup always runs.
	EnableSubdomains bool
	// MaxSubdomains caps the subdomains enumerated per domain. Zero falls back to
	// defaultMaxSubdomains.
	MaxSubdomains int
	// IteratorBatchSize is the page size for the subdomains iterator. Zero falls
	// back to defaultIteratorBatchSize.
	IteratorBatchSize int
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client queries the VirusTotal API v3 for domain intelligence: reputation,
// analysis vote counts, categories, tags, popularity ranks, JARM, and registrar
// via [Client.Lookup], and known subdomains via [Client.Subdomains]. The free
// tier permits 4 requests per minute, so callers should expect rate limiting.
type Client struct {
	cfg Config
	api vtAPI
}

// New validates cfg and returns a Client backed by the real vt-go SDK.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("virustotal: Config.APIKey is required")
	}
	if cfg.MaxSubdomains <= 0 {
		cfg.MaxSubdomains = defaultMaxSubdomains
	}
	if cfg.IteratorBatchSize <= 0 {
		cfg.IteratorBatchSize = defaultIteratorBatchSize
	}
	return &Client{cfg: cfg, api: &sdkClient{c: vt.NewClient(cfg.APIKey)}}, nil
}

// AnalysisStats holds the per-engine scan vote counts for a domain.
type AnalysisStats struct {
	Malicious  int
	Harmless   int
	Suspicious int
	Undetected int
}

// DomainReport holds the VirusTotal intelligence for a domain (excluding
// subdomains, which are fetched separately via [Client.Subdomains]).
type DomainReport struct {
	Reputation      int
	Analysis        AnalysisStats
	Categories      map[string]string
	Tags            []string
	PopularityRanks map[string]int
	JARM            string
	Registrar       string
}

// SubdomainResult holds the name and last observed DNS resolution timestamp of a subdomain.
type SubdomainResult struct {
	Name     string
	LastSeen time.Time
}

// vtAPI abstracts the VirusTotal SDK for testability.
type vtAPI interface {
	getDomain(ctx context.Context, domain string) (*domainInfo, error)
	getSubdomains(ctx context.Context, domain string, limit, batchSize int) ([]SubdomainResult, int, error)
}

// domainInfo holds the extracted domain attributes from a VT API response.
type domainInfo struct {
	Reputation      int
	Malicious       int
	Harmless        int
	Suspicious      int
	Undetected      int
	Categories      map[string]string
	Tags            []string
	PopularityRanks map[string]int
	JARM            string
	Registrar       string
}

// Lookup fetches the VirusTotal intelligence report for domain. A genuine failure
// to fetch the domain object is a hard error (and emits a LookupFailed event). A
// not-found result (VirusTotal never observed the domain) is a clean empty result:
// it emits DomainNotFound and returns a nil report with [ErrDomainNotFound], which
// callers should treat as "no data" rather than a failure.
func (c *Client) Lookup(ctx context.Context, domain string) (*DomainReport, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	endpoint := "domains/" + domain
	c.emit(ctx, LookupStarted{Domain: domain, Endpoint: endpoint})

	info, err := c.api.getDomain(ctx, domain)
	if err != nil {
		if isNotFound(err) {
			c.emit(ctx, DomainNotFound{Domain: domain})
			return nil, ErrDomainNotFound
		}
		c.emitError(ctx, domain, endpoint, 1, err, true, 0)
		return nil, fmt.Errorf("virustotal: domain lookup for %q: %w", domain, err)
	}

	report := &DomainReport{
		Reputation: info.Reputation,
		Analysis: AnalysisStats{
			Malicious:  info.Malicious,
			Harmless:   info.Harmless,
			Suspicious: info.Suspicious,
			Undetected: info.Undetected,
		},
		Categories:      info.Categories,
		Tags:            info.Tags,
		PopularityRanks: info.PopularityRanks,
		JARM:            info.JARM,
		Registrar:       info.Registrar,
	}

	c.emit(ctx, LookupCompleted{
		Domain:     domain,
		Reputation: report.Reputation,
		Malicious:  report.Analysis.Malicious,
		Suspicious: report.Analysis.Suspicious,
		Categories: len(report.Categories),
		Queries:    1,
		Succeeded:  1,
		Failed:     0,
		Degraded:   false,
	})
	return report, nil
}

// Subdomains enumerates the known subdomains of domain, sorted for deterministic
// output. Each result carries its VirusTotal last_seen so the caller can preserve the
// real-world last-observed time downstream. Enumeration errors are reported via a
// SubdomainEnumFailed event and are non-fatal: whatever subdomains were collected before
// the error are returned.
func (c *Client) Subdomains(ctx context.Context, domain string) ([]SubdomainResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.emit(ctx, SubdomainEnumStarted{Domain: domain, Limit: c.cfg.MaxSubdomains})

	subs, queries, err := c.api.getSubdomains(ctx, domain, c.cfg.MaxSubdomains, c.cfg.IteratorBatchSize)
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	if err != nil {
		c.emitError(ctx, domain, "domains/"+domain+"/subdomains", 1, err, false, len(subs))
	}

	for _, sub := range subs {
		c.emit(ctx, SubdomainFound{
			Domain:    domain,
			Subdomain: sub.Name,
			LastSeen:  sub.LastSeen,
			Source:    toolName,
		})
	}

	succeeded := 1
	failed := 0
	degraded := false
	if err != nil {
		succeeded = 0
		failed = 1
		degraded = true
	}

	c.emit(ctx, SubdomainEnumCompleted{
		Domain:    domain,
		Count:     len(subs),
		Queries:   queries,
		Succeeded: succeeded,
		Failed:    failed,
		Truncated: len(subs) >= c.cfg.MaxSubdomains,
		Degraded:  degraded,
	})
	return subs, nil
}

// isNotFound reports whether err is a vt-go NotFoundError (HTTP 404), meaning
// VirusTotal has never observed the domain. It unwraps so the SDK error survives
// the fmt.Errorf wrapping done in getDomain.
func isNotFound(err error) bool {
	var vtErr vt.Error
	return errors.As(err, &vtErr) && vtErr.Code == notFoundCode
}

// sdkClient implements vtAPI using the real vt-go SDK.
type sdkClient struct {
	c *vt.Client
}

func (s *sdkClient) getDomain(_ context.Context, domain string) (*domainInfo, error) {
	obj, err := s.c.GetObject(vt.URL("domains/%s", domain))
	if err != nil {
		return nil, fmt.Errorf("vt domain lookup: %w", err)
	}
	return extractDomainInfo(obj), nil
}

func (s *sdkClient) getSubdomains(_ context.Context, domain string, limit, batchSize int) ([]SubdomainResult, int, error) {
	it, err := s.c.Iterator(vt.URL("domains/%s/subdomains", domain),
		vt.IteratorLimit(limit),
		vt.IteratorBatchSize(batchSize),
	)
	if err != nil {
		return nil, 1, fmt.Errorf("vt subdomains iterator: %w", err)
	}
	defer it.Close()

	var subs []SubdomainResult
	for it.Next() {
		obj := it.Get()
		if id := obj.ID(); id != "" {
			res := SubdomainResult{Name: id}
			if ts, err := obj.GetInt64("last_dns_records_date"); err == nil && ts > 0 {
				res.LastSeen = time.Unix(ts, 0).UTC()
			}
			subs = append(subs, res)
		}
	}
	queries := (len(subs) + batchSize - 1) / batchSize
	if queries == 0 {
		queries = 1
	}
	if err := it.Error(); err != nil {
		return subs, queries, fmt.Errorf("vt subdomains iteration: %w", err)
	}
	return subs, queries, nil
}

// extractDomainInfo pulls the relevant attributes from a VT domain object.
func extractDomainInfo(obj *vt.Object) *domainInfo {
	info := &domainInfo{}

	info.Reputation, _ = getInt(obj, "reputation")
	info.Malicious, _ = getInt(obj, "last_analysis_stats.malicious")
	info.Harmless, _ = getInt(obj, "last_analysis_stats.harmless")
	info.Suspicious, _ = getInt(obj, "last_analysis_stats.suspicious")
	info.Undetected, _ = getInt(obj, "last_analysis_stats.undetected")
	info.JARM, _ = obj.GetString("jarm")
	info.Registrar, _ = obj.GetString("registrar")
	info.Tags, _ = obj.GetStringSlice("tags")

	info.Categories = extractCategories(obj)
	info.PopularityRanks = extractPopularityRanks(obj)

	return info
}

// extractCategories converts the VT "categories" map[vendor]category attribute to
// a map[string]string, returning nil when absent or malformed.
func extractCategories(obj *vt.Object) map[string]string {
	raw, err := obj.Get("categories")
	if err != nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	cats := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			cats[k] = s
		}
	}
	return cats
}

// extractPopularityRanks converts the VT "popularity_ranks" map[vendor]{rank:int}
// attribute to a map[vendor]rank, returning nil when absent or malformed.
func extractPopularityRanks(obj *vt.Object) map[string]int {
	raw, err := obj.Get("popularity_ranks")
	if err != nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	ranks := make(map[string]int, len(m))
	for vendor, v := range m {
		inner, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if r, err := toInt(inner["rank"]); err == nil {
			ranks[vendor] = r
		}
	}
	return ranks
}

// getInt extracts an int64 attribute and converts it to int.
func getInt(obj *vt.Object, attr string) (int, error) {
	v, err := obj.GetInt64(attr)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// toInt converts an interface{} to int, handling float64, int, and int64.
func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func (c *Client) emitError(ctx context.Context, domain, endpoint string, attempt int, err error, isLookup bool, collected int) {
	if err == nil {
		return
	}
	if isRateLimit(err) {
		c.emit(ctx, RateLimited{Domain: domain, Endpoint: endpoint, Attempt: attempt, Err: err})
		return
	}
	if status, ok := isAuthError(err); ok {
		c.emit(ctx, AuthFailed{Domain: domain, Endpoint: endpoint, StatusCode: status, Err: err})
		return
	}
	if snippet, ok := isJSONParseError(err); ok {
		c.emit(ctx, JSONParseError{Domain: domain, Endpoint: endpoint, Snippet: snippet, Err: err})
		return
	}
	if isLookup {
		c.emit(ctx, LookupFailed{Domain: domain, Err: err})
	} else {
		c.emit(ctx, SubdomainEnumFailed{Domain: domain, Collected: collected, Err: err})
	}
}

func isRateLimit(err error) bool {
	if err == nil {
		return false
	}
	var vtErr vt.Error
	if errors.As(err, &vtErr) {
		switch vtErr.Code {
		case "QuotaExceededError", "TooManyRequestsError", "RateLimitError":
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "quota") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "429") || strings.Contains(msg, "rate limit")
}

func isAuthError(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var vtErr vt.Error
	if errors.As(err, &vtErr) {
		switch vtErr.Code {
		case "AuthenticationRequiredError", "WrongCredentialsError":
			return 401, true
		case "ForbiddenError", "UserNotActiveError":
			return 403, true
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "401") || strings.Contains(msg, "wrongcredentials") || strings.Contains(msg, "authentication required") {
		return 401, true
	}
	if strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "user not active") {
		return 403, true
	}
	return 0, false
}

func isJSONParseError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "expecting json response") || strings.Contains(lower, "invalid character") || strings.Contains(lower, "cannot unmarshal") {
		if len(msg) > 100 {
			return msg[:100] + "...", true
		}
		return msg, true
	}
	return "", false
}
