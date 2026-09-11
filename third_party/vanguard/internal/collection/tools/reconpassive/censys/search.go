package censys

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

// ServiceInfo describes a single network service on a host.
type ServiceInfo struct {
	// Port is the port number the service answered on.
	Port int
	// Protocol is the application protocol Censys identified (for example "HTTP").
	// It is never read as transport evidence.
	Protocol string
	// Transport is the normalized IP transport, "tcp" or "udp". Empty means Censys
	// reported none for this service: unknown transport, never an implied tcp. Two
	// services may share a port when Censys observed both transports on it.
	Transport string
	// ObservedAt is Censys's scan_time for the service (when Censys last scanned it),
	// zero when Censys reported none.
	ObservedAt time.Time
}

// ASNInfo holds autonomous system information for a host.
type ASNInfo struct {
	Number      int
	Name        string
	Description string
}

// LocationInfo holds the geographic location of a host.
type LocationInfo struct {
	Country string
	City    string
}

// HostResult represents a single host found by Censys.
type HostResult struct {
	IP       string
	Services []ServiceInfo
	ASN      *ASNInfo
	Location *LocationInfo
	OS       string
	// Products are the software product names Censys fingerprinted across the host's
	// services (deduplicated, sorted), empty when none.
	Products []string
	// Vulns are the CVE identifiers Censys attributes to the host's services (from
	// the exposures and compromises risk lists, deduplicated and sorted), empty when
	// none. They feed the cross-provider CVE merge and the Censys vulnerability rule.
	Vulns []string
	// Reputation is the host-level threat verdict Censys reports (its reputation
	// score level: "malicious", "high_risk", "medium_risk", "low_risk", "benign"),
	// empty when Censys reports none. It rides along in the search hit at no extra
	// cost and feeds the Censys reputation rule.
	Reputation string
	// Labels are the surface descriptors Censys assigned to the host (for example
	// "login-page", "remote-access"), deduplicated and sorted, empty when none. Like
	// Reputation they are already present in the search hit.
	Labels []string
	// Sources records which queries matched this host: "dns", "tls_cert", or both.
	Sources []string
	// NetworkAllocatedAt is Censys whois.network.created for the host's network (its
	// allocation/registration date), zero when absent.
	NetworkAllocatedAt time.Time
	// NetworkCIDRs are Censys whois.network.cidrs for the host's network, empty when absent.
	NetworkCIDRs []string
}

// DomainHosts holds all hosts found for a domain.
type DomainHosts struct {
	Domain    string
	Hosts     []HostResult
	Truncated bool
	// RetrievalSource states where this result came from: "service" for a Censys API
	// answer, "cache_embedded" for the compiled-in fixture. It is carried onto the
	// domain event so an operator can tell the two apart without changing the
	// provider attribution, which stays "censys" either way.
	RetrievalSource string
}

// hostEntry groups a raw hit with its matched sources during deduplication.
type hostEntry struct {
	hit     rawHit
	sources map[string]bool
}

// Search queries Censys for the hosts associated with domain. Individual query
// failures are reported as events and skipped, so partial results are still
// returned. A 403 (paid-plan requirement) on one query type does not stop the
// other: each query type is tried independently, and Search only reports the
// tool as unavailable when every query type attempted this call came back 403 -
// a key missing one entitlement can still serve the other. An "insufficient balance"
// response (an empty query wallet, HTTP 422) is an account-level wall like a 403, so the
// first one short-circuits the search and reports the provider unavailable rather than
// retrying the depleted wallet for the other query and every remaining domain. Only an
// empty domain or a cancelled context is a hard error.
func (c *Client) Search(ctx context.Context, domain string) (*DomainHosts, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("censys: domain is empty")
	}
	c.emit(ctx, SearchStarted{Domain: domain})

	if c.cache != nil {
		return c.cachedSearch(ctx, domain), nil
	}
	return c.serviceSearch(ctx, domain)
}

// serviceSearch is the ModeEnabled path of Search: it runs the two CenQL queries
// against the Censys API, merges their hits, and emits the per-host and completion
// events. It is split out so Search reads as the mode decision it is.
func (c *Client) serviceSearch(ctx context.Context, domain string) (*DomainHosts, error) {
	type queryDef struct {
		label string
		query string
		tag   string // source tag recorded on matched hosts
	}
	// Certificate names runs first: cert-based discovery finds hosts serving the
	// domain's certificate even without a matching DNS name, and running it first
	// means a key entitled to only one query type is not starved by an early wall
	// on the other. The field is host.services.cert.names - the leaf certificate on
	// a service (components.Service.Cert.Names), not host.services.tls, which
	// carries the handshake rather than the certificate SANs.
	queries := []queryDef{
		{label: "TLS certificate names", query: fmt.Sprintf("host.services.cert.names: %q", domain), tag: "tls_cert"},
		{label: "DNS names", query: fmt.Sprintf("host.dns.names: %q", domain), tag: "dns"},
	}

	byIP := make(map[netip.Addr]*hostEntry)
	var totalHits, total, succeeded, failed, paidPlanBlocked int
	var lastPaidPlanLabel string
	var queryTruncated bool

	for _, q := range queries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		total++

		hits, capped, err := c.searchAll(ctx, q.query)
		if err != nil {
			failed++
			if isInsufficientBalanceError(err) {
				// The account wallet is empty: an account-level wall, not a per-domain miss.
				// Stop now and report the tool unavailable so the orchestrator trips its
				// breaker instead of retrying the depleted wallet for every remaining query
				// and domain.
				c.emit(ctx, SearchInsufficientBalance{Domain: domain, Label: q.label})
				c.emit(ctx, SearchCompleted{Domain: domain, Truncated: queryTruncated, TotalQueries: total, Succeeded: succeeded, Failed: failed, RetrievalSource: retrievalService})
				return nil, fmt.Errorf("censys: account has insufficient balance: %w", toolerr.ErrProviderUnavailable)
			}
			if isPaidPlanError(err) {
				paidPlanBlocked++
				lastPaidPlanLabel = q.label
				c.emit(ctx, SearchPaidPlanRequired{Domain: domain, Label: q.label})
				continue
			}
			if isRateLimitError(err) {
				// A 429 that survived the SDK's retries: report it as a rate-limit hit
				// (not a generic failure) so the operational rollup counts it truthfully.
				c.emit(ctx, SearchRateLimited{Domain: domain, Label: q.label, Query: q.query, Err: err})
				continue
			}
			c.emit(ctx, SearchQueryFailed{Domain: domain, Label: q.label, Query: q.query, Err: err})
			continue
		}
		succeeded++
		queryTruncated = queryTruncated || capped
		c.emit(ctx, SearchQuerySucceeded{Domain: domain, Label: q.label, Query: q.query, Hits: len(hits)})

		for _, h := range hits {
			addr, err := netip.ParseAddr(h.IP)
			if err != nil {
				continue
			}
			canonical := addr.Unmap()
			if entry, ok := byIP[canonical]; ok {
				entry.sources[q.tag] = true
				mergeServices(entry, h.Services)
				entry.hit.Products = unionStrings(entry.hit.Products, h.Products)
				entry.hit.Vulns = unionStrings(entry.hit.Vulns, h.Vulns)
				entry.hit.Labels = unionStrings(entry.hit.Labels, h.Labels)
				if entry.hit.Reputation == "" {
					entry.hit.Reputation = h.Reputation
				}
				if entry.hit.NetworkAllocatedAt.IsZero() && !h.NetworkAllocatedAt.IsZero() {
					entry.hit.NetworkAllocatedAt = h.NetworkAllocatedAt
				}
				if len(entry.hit.NetworkCIDRs) == 0 {
					entry.hit.NetworkCIDRs = h.NetworkCIDRs
				}
			} else {
				e := &hostEntry{hit: h, sources: map[string]bool{q.tag: true}}
				e.hit.IP = canonical.String()
				byIP[canonical] = e
			}
		}
		totalHits += len(hits)
	}

	hosts := buildHosts(byIP)
	truncated := queryTruncated
	if len(hosts) > c.cfg.MaxHosts {
		hosts = hosts[:c.cfg.MaxHosts]
		truncated = true
	}
	if totalHits > c.cfg.MaxHosts {
		truncated = true
	}

	for _, h := range hosts {
		c.emit(ctx, SearchHostDiscovered{Domain: domain, IP: h.IP, Services: len(h.Services), Sources: h.Sources})
	}
	c.emit(ctx, SearchCompleted{
		Domain:          domain,
		Hosts:           len(hosts),
		Truncated:       truncated,
		TotalQueries:    total,
		Succeeded:       succeeded,
		Failed:          failed,
		RetrievalSource: retrievalService,
	})

	if paidPlanBlocked == total {
		// Every query type attempted this call came back 403: a key-level wall, not
		// a per-domain miss. Report it as provider-unavailable so the orchestrator
		// stops querying Censys for the remaining domains instead of hitting the
		// same wall each time.
		return nil, fmt.Errorf("censys: %s requires a paid plan: %w", lastPaidPlanLabel, toolerr.ErrProviderUnavailable)
	}

	return &DomainHosts{Domain: domain, Hosts: hosts, Truncated: truncated, RetrievalSource: retrievalService}, nil
}

// cachedSearch answers a host search from the embedded fixture in
// ModeEmbeddedCacheOnly. A hit reports the same host-discovered and completed events
// a served query would, so the tool stream reads the same way; the only difference is
// that no query ran. A miss returns nil - no result at all, which the caller turns
// into no domain event. It is deliberately not an empty result (that would record an
// authoritative "Censys knows no hosts" observation that was never made) and not an
// error (nothing failed), and it never falls through to the API.
func (c *Client) cachedSearch(ctx context.Context, domain string) *DomainHosts {
	result, ok := c.cache.hostsFor(domain, c.cfg.MaxHosts)
	if !ok {
		c.emit(ctx, SearchCacheMiss{Domain: domain})
		c.emit(ctx, SearchCompleted{Domain: domain, RetrievalSource: retrievalCacheEmbedded})
		return nil
	}
	result.RetrievalSource = retrievalCacheEmbedded
	c.emit(ctx, SearchCacheHit{Domain: domain, Hosts: len(result.Hosts), Truncated: result.Truncated})
	for _, h := range result.Hosts {
		c.emit(ctx, SearchHostDiscovered{Domain: domain, IP: h.IP, Services: len(h.Services), Sources: h.Sources})
	}
	c.emit(ctx, SearchCompleted{
		Domain:          domain,
		Hosts:           len(result.Hosts),
		Truncated:       result.Truncated,
		RetrievalSource: retrievalCacheEmbedded,
	})
	return result
}

// searchAll pages one CenQL query, accumulating hits up to MaxHosts. The Platform
// caps page_size at 100, so an estate with more than 100 matches (or more than
// MaxHosts when that is smaller) is bounded here by following the next-page token
// until the cap is reached or the results are exhausted. The bool reports whether
// the cap cut the results short (more pages remained), so the caller can flag the
// result truncated even when the deduplicated union fits under MaxHosts.
func (c *Client) searchAll(ctx context.Context, query string) ([]rawHit, bool, error) {
	limit := c.cfg.MaxHosts
	pageSize := int64(100)
	if limit < 100 {
		pageSize = int64(limit)
	}

	var (
		out   []rawHit
		token string
	)
	for {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		hits, next, err := c.searcher.searchPage(ctx, query, pageSize, token)
		if err != nil {
			return nil, false, err
		}
		out = append(out, hits...)
		if len(out) >= limit {
			return out[:limit], len(out) > limit || next != "", nil
		}
		if next == "" {
			return out, false, nil
		}
		token = next
	}
}

// buildHosts converts the deduplicated entries to sorted HostResults, ordered by
// IP for deterministic output.
func buildHosts(byIP map[netip.Addr]*hostEntry) []HostResult {
	hosts := make([]HostResult, 0, len(byIP))
	for _, entry := range byIP {
		sources := make([]string, 0, len(entry.sources))
		for s := range entry.sources {
			sources = append(sources, s)
		}
		sort.Strings(sources)
		sortServices(entry.hit.Services)
		hosts = append(hosts, HostResult{
			IP:                 entry.hit.IP,
			Services:           entry.hit.Services,
			ASN:                entry.hit.ASN,
			Location:           entry.hit.Location,
			OS:                 entry.hit.OS,
			Products:           entry.hit.Products,
			Vulns:              entry.hit.Vulns,
			Reputation:         entry.hit.Reputation,
			Labels:             entry.hit.Labels,
			Sources:            sources,
			NetworkAllocatedAt: entry.hit.NetworkAllocatedAt,
			NetworkCIDRs:       entry.hit.NetworkCIDRs,
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		ai, _ := netip.ParseAddr(hosts[i].IP)
		aj, _ := netip.ParseAddr(hosts[j].IP)
		return ai.Less(aj)
	})
	return hosts
}

// mergeServices adds services from src to entry, deduplicating by port+protocol+transport.
func mergeServices(entry *hostEntry, src []ServiceInfo) {
	seen := make(map[string]int, len(entry.hit.Services))
	for i, s := range entry.hit.Services {
		seen[serviceKey(s)] = i
	}
	for _, s := range src {
		key := serviceKey(s)
		if i, ok := seen[key]; ok {
			if s.ObservedAt.After(entry.hit.Services[i].ObservedAt) {
				entry.hit.Services[i].ObservedAt = s.ObservedAt
			}
		} else {
			entry.hit.Services = append(entry.hit.Services, s)
			seen[key] = len(entry.hit.Services) - 1
		}
	}
}

// serviceKey builds a stable dedup key for a service.
func serviceKey(s ServiceInfo) string {
	return fmt.Sprintf("%d/%s/%s", s.Port, s.Protocol, s.Transport)
}

// sortServices sorts services by port, then transport, then protocol, so a port
// observed on both transports keeps two stable, separately ordered entries.
func sortServices(svcs []ServiceInfo) {
	sort.Slice(svcs, func(i, j int) bool {
		if svcs[i].Port != svcs[j].Port {
			return svcs[i].Port < svcs[j].Port
		}
		if svcs[i].Transport != svcs[j].Transport {
			return svcs[i].Transport < svcs[j].Transport
		}
		return svcs[i].Protocol < svcs[j].Protocol
	})
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
