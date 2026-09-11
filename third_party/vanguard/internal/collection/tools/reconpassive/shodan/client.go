package shodan

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	shodansdk "github.com/shadowscatcher/shodan"
	"github.com/shadowscatcher/shodan/models"
	"github.com/shadowscatcher/shodan/search"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

const (
	defaultMaxHosts = 100
	defaultTimeout  = 30 * time.Second
)

// Config holds configuration for the Client.
type Config struct {
	// APIKey is the Shodan API key. Required: the app injects it from the
	// SHODAN_API_KEY environment variable rather than the config file, so the
	// secret stays out of the audit configuration.
	APIKey string
	// MaxHosts caps the hosts returned per domain. Zero falls back to defaultMaxHosts.
	MaxHosts int
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client searches the Shodan host-intelligence platform for the hosts Shodan has
// indexed for a domain. It runs a single hostname:<domain> search per domain,
// deduplicates the resulting service banners by IP, and aggregates ports,
// routing, software, and known vulnerabilities (CVEs) per host. Shodan is a paid
// API; one search consumes one query credit.
type Client struct {
	cfg      Config
	searcher searcher
}

// New validates cfg and returns a Client backed by the real Shodan SDK.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("shodan: Config.APIKey is required")
	}
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = defaultMaxHosts
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	// wait=true makes the SDK respect Shodan's rate limit (about 1 req/sec) rather
	// than returning 429s.
	sdk, err := shodansdk.GetClient(cfg.APIKey, &http.Client{Timeout: cfg.Timeout}, true)
	if err != nil {
		return nil, fmt.Errorf("shodan: create client: %w", err)
	}
	return &Client{cfg: cfg, searcher: &sdkSearcher{client: sdk}}, nil
}

// Service is one service Shodan observed on a host: the port it answered on and
// the transport the banner was collected over. Shodan reports both per banner, so
// the pair is kept together rather than flattened into a port list that cannot say
// whether tcp/53 or udp/53 was seen.
type Service struct {
	// Port is the port number the service answered on.
	Port int
	// Transport is the normalized IP transport, "tcp" or "udp". Empty means Shodan
	// reported none for this banner: unknown transport, never an implied tcp.
	Transport string
}

// HostResult is a single host Shodan indexed for a domain, aggregated from the
// per-service banners that matched.
type HostResult struct {
	IP string
	// Services are the services Shodan observed, sorted by port then transport. Two
	// entries may share a port when Shodan saw it on both transports.
	Services  []Service
	ASN       string
	Org       string
	ISP       string
	OS        string
	Hostnames []string
	Tags      []string
	Country   string
	City      string
	Products  []string
	// Vulns are the CVE identifiers Shodan inferred for the host's services.
	Vulns []string
	// ObservedAt is the most recent banner timestamp across the host's services (when
	// Shodan last observed it), zero when Shodan reported none.
	ObservedAt time.Time
}

// DomainHosts holds the hosts Shodan returned for a domain.
type DomainHosts struct {
	Domain    string
	Hosts     []HostResult
	Truncated bool
}

// searcher abstracts the Shodan SDK for testability.
type searcher interface {
	search(ctx context.Context, query string) (models.SearchResult, error)
}

// sdkSearcher implements searcher using the real Shodan SDK.
type sdkSearcher struct {
	client *shodansdk.Client
}

func (s *sdkSearcher) search(ctx context.Context, query string) (models.SearchResult, error) {
	return s.client.Search(ctx, search.Params{Query: search.Query{Text: query}, Page: 1})
}

// Search queries Shodan for the hosts indexed under hostname:<domain> and returns
// the deduplicated hosts. A search error is reported via a SearchFailed event and
// returned; only an empty domain or a cancelled context short-circuits earlier.
func (c *Client) Search(ctx context.Context, domain string) (*DomainHosts, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("shodan: domain is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	query := "hostname:" + domain
	c.emit(ctx, SearchStarted{Domain: domain, Query: query})

	result, err := c.searcher.search(ctx, query)
	if err != nil {
		c.emitSearchError(ctx, domain, query, 1, err)
		if toolerr.IsUnavailableMessage(err.Error()) {
			// "Requires membership or higher" and the like are key-level walls, not a
			// per-domain miss: flag the provider as unavailable so the orchestrator
			// stops querying Shodan for the rest of the scan.
			return nil, fmt.Errorf("shodan: search for %q: %w: %w", domain, err, toolerr.ErrProviderUnavailable)
		}
		return nil, fmt.Errorf("shodan: search for %q: %w", domain, err)
	}

	hosts := buildHosts(result.Matches)
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
			Sources:  []string{"shodan"},
		})
	}
	c.emit(ctx, SearchCompleted{
		Domain:            domain,
		Hosts:             len(hosts),
		Truncated:         truncated,
		TotalMatches:      result.Total,
		TotalQueries:      1,
		SuccessfulQueries: 1,
		FailedQueries:     0,
		Degraded:          false,
	})
	return &DomainHosts{Domain: domain, Hosts: hosts, Truncated: truncated}, nil
}

// hostAccum gathers the per-service banner data for one IP during deduplication.
type hostAccum struct {
	services   map[Service]struct{}
	hostnames  map[string]struct{}
	tags       map[string]struct{}
	products   map[string]struct{}
	vulns      map[string]struct{}
	asn        string
	org        string
	isp        string
	os         string
	country    string
	city       string
	observedAt time.Time
}

// buildHosts groups the service banners by IP and aggregates them into sorted
// HostResults, ordered by IP for deterministic output.
func buildHosts(matches []models.Service) []HostResult {
	byIP := make(map[string]*hostAccum)
	for i := range matches {
		m := &matches[i]
		ip := strings.TrimSpace(m.IPstr)
		if ip == "" {
			continue
		}
		acc, ok := byIP[ip]
		if !ok {
			acc = newHostAccum()
			byIP[ip] = acc
		}
		acc.merge(m)
	}

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

func newHostAccum() *hostAccum {
	return &hostAccum{
		services:  make(map[Service]struct{}),
		hostnames: make(map[string]struct{}),
		tags:      make(map[string]struct{}),
		products:  make(map[string]struct{}),
		vulns:     make(map[string]struct{}),
	}
}

func (a *hostAccum) merge(m *models.Service) {
	if m.Port != 0 {
		// Shodan states the transport per banner; an absent one stays unknown rather
		// than being guessed from the port number or the application protocol.
		a.services[Service{Port: m.Port, Transport: normalizeTransport(m.Transport)}] = struct{}{}
	}
	addAll(a.hostnames, m.Hostnames)
	addAll(a.tags, m.Tags)
	if p := strings.TrimSpace(m.ProductString()); p != "" {
		a.products[p] = struct{}{}
	}
	for cve := range m.Vulns {
		a.vulns[strings.TrimSpace(cve)] = struct{}{}
	}
	a.asn = firstNonEmpty(a.asn, deref(m.ASN))
	a.org = firstNonEmpty(a.org, deref(m.Org))
	a.isp = firstNonEmpty(a.isp, deref(m.ISP))
	a.os = firstNonEmpty(a.os, deref(m.OS))
	a.country = firstNonEmpty(a.country, deref(m.Location.CountryName))
	a.city = firstNonEmpty(a.city, deref(m.Location.City))
	if t := parseShodanTime(m.Timestamp); !t.IsZero() && t.After(a.observedAt) {
		a.observedAt = t
	}
}

// parseShodanTime parses a Shodan banner timestamp. Shodan reports UTC without a zone
// suffix (for example "2014-01-15T05:49:56.283713"), so a zoneless layout is tried
// alongside RFC-3339; an unparseable or empty value yields the zero time.
func parseShodanTime(s string) time.Time {
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
		OS:         a.os,
		Hostnames:  sortedStrings(a.hostnames),
		Tags:       sortedStrings(a.tags),
		Country:    a.country,
		City:       a.city,
		Products:   sortedStrings(a.products),
		Vulns:      sortedStrings(a.vulns),
		ObservedAt: a.observedAt,
	}
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func addAll(set map[string]struct{}, values []string) {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			set[v] = struct{}{}
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
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
// port, then by transport, so a host with both transports on one port keeps two
// stable entries.
func sortedServices(set map[Service]struct{}) []Service {
	out := make([]Service, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Transport < out[j].Transport
	})
	return out
}

// distinctPorts counts the distinct port numbers across services. It differs from
// the service count when Shodan saw one port on both transports, which are two
// services on one port.
func distinctPorts(services []Service) int {
	seen := make(map[int]struct{}, len(services))
	for _, s := range services {
		seen[s.Port] = struct{}{}
	}
	return len(seen)
}

// normalizeTransport lower-cases an explicit tcp or udp transport and discards
// anything else, including an empty value: an unrecognised transport is unknown,
// and unknown is never turned into tcp.
func normalizeTransport(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	default:
		return ""
	}
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
		c.emit(ctx, JSONParseError{Domain: domain, Query: query, Snippet: snippet, Err: err})
		return
	}
	c.emit(ctx, SearchFailed{Domain: domain, Query: query, Err: err})
}

func isRateLimit(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "429") || strings.Contains(msg, "rate limit") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "quota") || strings.Contains(msg, "credits")
}

func isAuthError(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "invalid api key") {
		return 401, true
	}
	if strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "access denied") || strings.Contains(msg, "membership") || strings.Contains(msg, "upgrade") || strings.Contains(msg, "paid plan") || strings.Contains(msg, "payment required") || strings.Contains(msg, "subscription") || strings.Contains(msg, "filter") {
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
