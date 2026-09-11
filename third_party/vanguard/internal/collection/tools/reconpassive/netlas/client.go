package netlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	netlasapi "github.com/velgard-sk/vanguard/pkg/netlas"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

const (
	defaultMaxHosts = 100
	defaultMaxPages = 5
	defaultTimeout  = 30 * time.Second
)

// Config holds configuration for the Client.
type Config struct {
	// APIKey is the Netlas API key. Required: the app injects it from the
	// NETLAS_API_KEY environment variable rather than the config file, so the
	// secret stays out of the audit configuration.
	APIKey string
	// MaxHosts caps the unique hosts returned per domain. Zero falls back to
	// defaultMaxHosts.
	MaxHosts int
	// MaxPages caps how many result pages (PageSize each) a single domain lookup
	// fetches, bounding paid request volume. Zero falls back to defaultMaxPages.
	MaxPages int
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client searches the Netlas internet-scan platform for the hosts Netlas has
// indexed for a domain. It runs a single domain:<domain> responses search, pages
// through the results, deduplicates the scan documents by IP, and aggregates
// ports, routing, software, and known vulnerabilities (CVEs) per host. Netlas is a
// paid API; each request draws down the account's request budget.
type Client struct {
	cfg      Config
	searcher searcher
}

// New validates cfg and returns a Client backed by the real Netlas API.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("netlas: Config.APIKey is required")
	}
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = defaultMaxHosts
	}
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = defaultMaxPages
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	api, err := netlasapi.New(cfg.APIKey, netlasapi.WithHTTPClient(&http.Client{Timeout: cfg.Timeout}))
	if err != nil {
		return nil, fmt.Errorf("netlas: create client: %w", err)
	}
	return &Client{cfg: cfg, searcher: &apiSearcher{client: api}}, nil
}

// Service is one service Netlas observed on a host. Netlas indexes one scan
// document per service, so port, transport, and application protocol are facts
// about that one service and are kept together instead of being spread across
// host-wide lists that cannot be joined back.
type Service struct {
	// Port is the port number the service answered on.
	Port int
	// Transport is the normalized IP transport, "tcp" or "udp". It is empty for
	// every Netlas document today: the responses index this tool reads supplies an
	// application protocol per service but no proven transport field, so transport
	// stays unknown rather than being inferred from ApplicationProtocol or from the
	// port number. If a recorded response is ever seen to carry one, populate it here
	// and add that response as a fixture; do not start inferring it.
	Transport string
	// ApplicationProtocol is the protocol Netlas identified (for example "http",
	// "https", "ssh"), empty when absent. It says what was spoken, not what carried
	// it, and is never read as transport evidence.
	ApplicationProtocol string
}

// HostResult is a single host Netlas indexed for a domain, aggregated from the
// per-service scan documents that matched.
type HostResult struct {
	IP string
	// Services are the services Netlas observed, sorted by port, then transport,
	// then application protocol.
	Services  []Service
	ASN       string
	Org       string
	ISP       string
	Hostnames []string
	Country   string
	City      string
	JARM      string
	Products  []string
	// Vulns are the CVE identifiers Netlas associated with the host's services.
	Vulns []string
	// ObservedAt is the most recent @timestamp across the host's scan documents (when
	// Netlas indexed them, normally close to scan time), zero when Netlas reported none.
	ObservedAt time.Time
}

// DomainHosts holds the hosts Netlas returned for a domain.
type DomainHosts struct {
	Domain    string
	Hosts     []HostResult
	Truncated bool
}

// searcher abstracts the Netlas API for testability.
type searcher interface {
	search(ctx context.Context, req netlasapi.SearchRequest) (*netlasapi.SearchResponse, error)
}

// apiSearcher implements searcher using the real Netlas API wrapper.
type apiSearcher struct {
	client *netlasapi.Client
}

func (s *apiSearcher) search(ctx context.Context, req netlasapi.SearchRequest) (*netlasapi.SearchResponse, error) {
	return s.client.SearchResponses(ctx, req)
}

// responseData is the subset of a Netlas responses document the tool reads. Fields
// Netlas omits decode to their zero value; a document whose shape is incompatible
// is skipped by the caller rather than failing the whole search.
type responseData struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
	Port int    `json:"port"`
	// Protocol is the application protocol Netlas identified for this document (for
	// example "http", "ssh"). Netlas states no transport here, so it is carried as
	// an application protocol and never read as one.
	Protocol  string    `json:"protocol"`
	ISP       string    `json:"isp"`
	JARM      string    `json:"jarm"`
	Timestamp string    `json:"@timestamp"`
	Geo       *geoData  `json:"geo"`
	ASN       *asnData  `json:"asn"`
	HTTP      *httpData `json:"http"`
	CVE       []cveData `json:"cve"`
}

type geoData struct {
	Country string `json:"country"`
	City    string `json:"city"`
}

type asnData struct {
	Number int    `json:"number"`
	Name   string `json:"name"`
}

type httpData struct {
	Server string `json:"server"`
}

type cveData struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ident returns the CVE identifier, preferring the id field and falling back to
// name, since Netlas has used both labels for the vulnerability key.
func (c cveData) ident() string {
	if id := strings.TrimSpace(c.ID); id != "" {
		return id
	}
	return strings.TrimSpace(c.Name)
}

// Search queries Netlas for the hosts indexed under domain:<domain> and returns
// the deduplicated hosts. A search error is reported via a SearchFailed event and
// returned; only an empty domain or a cancelled context short-circuits earlier.
func (c *Client) Search(ctx context.Context, domain string) (*DomainHosts, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("netlas: domain is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	query := "domain:" + domain
	c.emit(ctx, SearchStarted{Domain: domain, Query: query})

	byIP := make(map[string]*hostAccum)
	total, skipped := 0, 0
	queries, succeeded := 0, 0
	for page := 0; page < c.cfg.MaxPages; page++ {
		queries++
		resp, err := c.searcher.search(ctx, netlasapi.SearchRequest{Query: query, Start: page * netlasapi.PageSize})
		if err != nil {
			c.emitSearchError(ctx, domain, query, page+1, err)
			if toolerr.IsUnavailableMessage(err.Error()) {
				// A daily-request-limit (429) or access-denied (403) reply is a key-level
				// wall that will not clear during this scan, not a per-domain miss: flag
				// the provider as unavailable so the orchestrator stops querying Netlas.
				return nil, fmt.Errorf("netlas: search for %q: %w: %w", domain, err, toolerr.ErrProviderUnavailable)
			}
			return nil, fmt.Errorf("netlas: search for %q: %w", domain, err)
		}
		succeeded++
		if len(resp.Items) == 0 {
			break
		}
		total += len(resp.Items)
		for i := range resp.Items {
			var d responseData
			if err := json.Unmarshal(resp.Items[i].Data, &d); err != nil {
				skipped++
				snippet := string(resp.Items[i].Data)
				if len(snippet) > 100 {
					snippet = snippet[:100] + "..."
				}
				c.emit(ctx, JSONParseError{
					Domain:     domain,
					Query:      query,
					Snippet:    snippet,
					RawSnippet: string(resp.Items[i].Data),
					BodyBytes:  len(resp.Items[i].Data),
					Err:        err,
				})
				continue
			}
			ip := strings.TrimSpace(d.IP)
			if ip == "" {
				continue
			}
			acc, ok := byIP[ip]
			if !ok {
				acc = newHostAccum()
				byIP[ip] = acc
			}
			acc.merge(&d)
		}
		if len(resp.Items) < netlasapi.PageSize {
			break
		}
	}

	hosts := finalizeHosts(byIP)
	truncated := false
	if len(hosts) > c.cfg.MaxHosts {
		hosts = hosts[:c.cfg.MaxHosts]
		truncated = true
	}

	for i := range hosts {
		c.emit(ctx, HostDiscovered{
			Domain:   domain,
			IP:       hosts[i].IP,
			Ports:    distinctPorts(hosts[i].Services),
			Vulns:    len(hosts[i].Vulns),
			Services: len(hosts[i].Services),
			Sources:  []string{"netlas"},
		})
	}
	c.emit(ctx, SearchCompleted{
		Domain:            domain,
		Hosts:             len(hosts),
		Truncated:         truncated,
		TotalMatches:      total,
		TotalQueries:      queries,
		SuccessfulQueries: succeeded,
		FailedQueries:     0,
		Degraded:          skipped > 0,
	})
	return &DomainHosts{Domain: domain, Hosts: hosts, Truncated: truncated}, nil
}

// hostAccum gathers the per-document scan data for one IP during deduplication.
type hostAccum struct {
	services   map[Service]struct{}
	hostnames  map[string]struct{}
	products   map[string]struct{}
	vulns      map[string]struct{}
	asn        string
	org        string
	isp        string
	country    string
	city       string
	jarm       string
	observedAt time.Time
}

func newHostAccum() *hostAccum {
	return &hostAccum{
		services:  make(map[Service]struct{}),
		hostnames: make(map[string]struct{}),
		products:  make(map[string]struct{}),
		vulns:     make(map[string]struct{}),
	}
}

func (a *hostAccum) merge(d *responseData) {
	if d.Port != 0 {
		// One document is one service: its application protocol belongs to this port,
		// and its transport stays unknown because the document does not state one.
		a.services[Service{
			Port:                d.Port,
			ApplicationProtocol: strings.ToLower(strings.TrimSpace(d.Protocol)),
		}] = struct{}{}
	}
	if h := strings.TrimSpace(d.Host); h != "" {
		a.hostnames[h] = struct{}{}
	}
	if d.HTTP != nil {
		if s := strings.TrimSpace(d.HTTP.Server); s != "" {
			a.products[s] = struct{}{}
		}
	}
	for i := range d.CVE {
		if id := d.CVE[i].ident(); id != "" {
			a.vulns[id] = struct{}{}
		}
	}
	a.isp = firstNonEmpty(a.isp, strings.TrimSpace(d.ISP))
	a.jarm = firstNonEmpty(a.jarm, strings.TrimSpace(d.JARM))
	if d.ASN != nil {
		a.asn = firstNonEmpty(a.asn, formatASN(d.ASN.Number))
		a.org = firstNonEmpty(a.org, strings.TrimSpace(d.ASN.Name))
	}
	if d.Geo != nil {
		a.country = firstNonEmpty(a.country, strings.TrimSpace(d.Geo.Country))
		a.city = firstNonEmpty(a.city, strings.TrimSpace(d.Geo.City))
	}
	if t := parseNetlasTime(d.Timestamp); !t.IsZero() && t.After(a.observedAt) {
		a.observedAt = t
	}
}

// parseNetlasTime parses a Netlas @timestamp. Netlas reports ISO-8601, with or without
// a zone suffix, so zoneless layouts are tried alongside RFC-3339; an
// unparseable or empty value yields the zero time.
func parseNetlasTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func (a *hostAccum) result(ip string) HostResult {
	return HostResult{
		IP:         ip,
		Services:   sortedServices(a.services),
		ASN:        a.asn,
		Org:        a.org,
		ISP:        a.isp,
		Hostnames:  sortedStrings(a.hostnames),
		Country:    a.country,
		City:       a.city,
		JARM:       a.jarm,
		Products:   sortedStrings(a.products),
		Vulns:      sortedStrings(a.vulns),
		ObservedAt: a.observedAt,
	}
}

// finalizeHosts turns the accumulators into sorted HostResults, ordered by IP for
// deterministic output.
func finalizeHosts(byIP map[string]*hostAccum) []HostResult {
	hosts := make([]HostResult, 0, len(byIP))
	for ip, acc := range byIP {
		hosts = append(hosts, acc.result(ip))
	}
	sort.Slice(hosts, func(i, j int) bool {
		ai, errA := netip.ParseAddr(hosts[i].IP)
		aj, errB := netip.ParseAddr(hosts[j].IP)
		if errA == nil && errB == nil {
			return ai.Less(aj)
		}
		return hosts[i].IP < hosts[j].IP
	})
	return hosts
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

// formatASN renders an AS number as "AS<n>", empty when the number is absent.
func formatASN(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("AS%d", n)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sortedStrings(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// sortedServices renders the accumulated services in a deterministic order: by
// port, then transport, then application protocol, so two services on one port
// keep two stable entries.
func sortedServices(set map[Service]struct{}) []Service {
	out := make([]Service, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Transport != out[j].Transport {
			return out[i].Transport < out[j].Transport
		}
		return out[i].ApplicationProtocol < out[j].ApplicationProtocol
	})
	return out
}

// distinctPorts counts the distinct port numbers across services, which is fewer
// than the service count when one port carried several observed services.
func distinctPorts(services []Service) int {
	seen := make(map[int]struct{}, len(services))
	for _, s := range services {
		seen[s.Port] = struct{}{}
	}
	return len(seen)
}

func (c *Client) emitSearchError(ctx context.Context, domain, query string, attempt int, err error) {
	if err == nil {
		return
	}
	if isRateLimit(err) {
		c.emit(ctx, RateLimited{Domain: domain, Query: query, Attempt: attempt, Err: err})
		return
	}
	if status, ok := isAuthError(err); ok {
		c.emit(ctx, PaidPlanRequired{Domain: domain, Query: query, StatusCode: status})
		return
	}
	if snippet, ok := isJSONParseError(err); ok {
		c.emit(ctx, JSONParseError{Domain: domain, Query: query, Snippet: snippet, RawSnippet: snippet, BodyBytes: len(snippet), Err: err})
		return
	}
	c.emit(ctx, SearchFailed{Domain: domain, Query: query, Err: err})
}

func isRateLimit(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *netlasapi.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 429 {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "429") || strings.Contains(msg, "rate limit") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "daily_request_limit") || strings.Contains(msg, "request limit") || strings.Contains(msg, "ratelimit") || strings.Contains(msg, "quota")
}

func isAuthError(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var apiErr *netlasapi.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == 401 || apiErr.StatusCode == 403 {
			return apiErr.StatusCode, true
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized") {
		return 401, true
	}
	if strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "access denied") || strings.Contains(msg, "paid plan") || strings.Contains(msg, "payment required") || strings.Contains(msg, "subscription") || strings.Contains(msg, "membership") {
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
	if strings.Contains(lower, "invalid character") || strings.Contains(lower, "cannot unmarshal") || strings.Contains(lower, "syntax error") || strings.Contains(lower, "decode") || strings.Contains(lower, "json") {
		if len(msg) > 100 {
			return msg[:100] + "...", true
		}
		return msg, true
	}
	return "", false
}
