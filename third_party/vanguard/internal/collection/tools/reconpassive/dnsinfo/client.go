package dnsinfo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// errNXDomain marks a clean negative DNS answer (NXDOMAIN): the resolver
// authoritatively reports no such name. It is not a transport or operational
// failure, so callers log it at debug rather than warn.
var errNXDomain = errors.New("NXDOMAIN")

// Config holds configuration for the Client.
type Config struct {
	// Resolver is the DNS server address (e.g. "8.8.8.8:53").
	Resolver string
	// Timeout is the per-query DNS timeout.
	Timeout time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client performs DNS lookups and zone transfers.
type Client struct {
	cfg Config
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Resolver == "" {
		return nil, fmt.Errorf("dnsinfo: Config.Resolver is required")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("dnsinfo: Config.Timeout must be positive")
	}
	return &Client{cfg: cfg}, nil
}

// Lookup queries common DNS record types for domain and returns collected
// records. Individual query failures are logged and skipped so partial
// results are still returned.
func (c *Client) Lookup(ctx context.Context, domain string) (*Records, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("dnsinfo: domain is empty")
	}
	fqdn := toFQDN(domain)
	c.emit(ctx, LookupStarted{Domain: fqdn})

	records := &Records{
		Domain:   trimDot(fqdn),
		Resolver: c.cfg.Resolver,
	}

	var totalQueries, failedQueries int

	runQuery := func(qtype uint16) []dns.RR {
		totalQueries++
		answers, err := c.query(ctx, fqdn, qtype)
		if err != nil {
			if errors.Is(err, errNXDomain) {
				c.emit(ctx, QueryNoRecords{Domain: fqdn, Type: dnsutil.TypeToString(qtype)})
			} else {
				failedQueries++
				c.emitErr(ctx, fqdn, dnsutil.TypeToString(qtype), false, err)
			}
		} else {
			for _, rr := range answers {
				c.emit(ctx, RecordDiscovered{
					Domain: fqdn,
					Type:   dnsutil.TypeToString(dns.RRToType(rr)),
					Value:  zoneRecordValue(rr),
					TTL:    rr.Header().TTL,
				})
			}
		}
		return answers
	}

	c.collectBasicRecords(records, runQuery)
	c.collectPTRRecords(ctx, records, &totalQueries, &failedQueries)
	c.collectSOAAndSec(records, runQuery)

	c.emit(ctx, LookupCompleted{
		Domain:   fqdn,
		A:        len(records.A),
		AAAA:     len(records.AAAA),
		NS:       len(records.NS),
		MX:       len(records.MX),
		TXT:      len(records.TXT),
		SOA:      records.SOA != nil,
		DNSSEC:   records.DNSSEC,
		Queries:  totalQueries,
		Failed:   failedQueries,
		Degraded: failedQueries > 0 && failedQueries < totalQueries,
	})
	return records, nil
}

// LookupPTR resolves the reverse-DNS names for one IP address. It is the bounded
// single-address form used when a passive provider reports an address that did not
// appear in the queried domain's A or AAAA records. NXDOMAIN is a clean empty
// result; operational failures are returned after their typed tool event is emitted.
func (c *Client) LookupPTR(ctx context.Context, ip string) ([]PTRRecord, error) {
	ip = strings.TrimSpace(ip)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		err = fmt.Errorf("dnsinfo: invalid PTR address %q: %w", ip, err)
		c.emit(ctx, PTRQueryFailed{IP: ip, Err: err})
		return nil, err
	}

	answers, err := c.query(ctx, dnsutil.ReverseAddr(addr), dns.TypePTR)
	if err != nil {
		if errors.Is(err, errNXDomain) {
			c.emit(ctx, PTRNoRecords{IP: ip})
			return nil, nil
		}
		c.emitErr(ctx, ip, ptrRecordType, true, err)
		return nil, err
	}

	records := make([]PTRRecord, 0, len(answers))
	for _, rr := range answers {
		ptr, ok := rr.(*dns.PTR)
		if !ok {
			continue
		}
		hostname := trimDot(ptr.Ptr)
		records = append(records, PTRRecord{IP: ip, Hostname: hostname})
		c.emit(ctx, RecordDiscovered{
			Domain: ip,
			Type:   ptrRecordType,
			Value:  hostname,
			TTL:    rr.Header().TTL,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Hostname < records[j].Hostname })
	return records, nil
}

func (c *Client) collectBasicRecords(records *Records, runQuery func(uint16) []dns.RR) {
	for _, rr := range runQuery(dns.TypeA) {
		if a, ok := rr.(*dns.A); ok {
			records.A = append(records.A, a.Addr.String())
		}
	}
	sort.Strings(records.A)

	for _, rr := range runQuery(dns.TypeAAAA) {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			records.AAAA = append(records.AAAA, aaaa.Addr.String())
		}
	}
	sort.Strings(records.AAAA)

	for _, rr := range runQuery(dns.TypeCNAME) {
		if cname, ok := rr.(*dns.CNAME); ok {
			records.CNAME = append(records.CNAME, trimDot(cname.Target))
		}
	}
	sort.Strings(records.CNAME)

	records.MX = collectMX(runQuery(dns.TypeMX))

	for _, rr := range runQuery(dns.TypeNS) {
		if ns, ok := rr.(*dns.NS); ok {
			records.NS = append(records.NS, trimDot(ns.Ns))
		}
	}
	sort.Strings(records.NS)

	for _, rr := range runQuery(dns.TypeTXT) {
		if txt, ok := rr.(*dns.TXT); ok {
			records.TXT = append(records.TXT, strings.Join(txt.Txt, ""))
		}
	}
	sort.Strings(records.TXT)
}

func collectMX(answers []dns.RR) []MXRecord {
	mx := make([]MXRecord, 0, len(answers))
	for _, rr := range answers {
		if m, ok := rr.(*dns.MX); ok {
			mx = append(mx, MXRecord{Host: trimDot(m.Mx), Priority: m.Preference})
		}
	}
	sort.Slice(mx, func(i, j int) bool {
		if mx[i].Priority != mx[j].Priority {
			return mx[i].Priority < mx[j].Priority
		}
		return mx[i].Host < mx[j].Host
	})
	return mx
}

func (c *Client) collectPTRRecords(ctx context.Context, records *Records, totalQueries, failedQueries *int) {
	ptrIPs := append(append([]string(nil), records.A...), records.AAAA...)
	sort.Strings(ptrIPs)
	for _, ip := range ptrIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		*totalQueries++
		answers, err := c.query(ctx, dnsutil.ReverseAddr(addr), dns.TypePTR)
		if err != nil {
			if errors.Is(err, errNXDomain) {
				c.emit(ctx, PTRNoRecords{IP: ip})
			} else {
				*failedQueries++
				c.emitErr(ctx, ip, ptrRecordType, true, err)
			}
			continue
		}
		for _, rr := range answers {
			if ptr, ok := rr.(*dns.PTR); ok {
				records.PTR = append(records.PTR, PTRRecord{IP: ip, Hostname: trimDot(ptr.Ptr)})
			}
			c.emit(ctx, RecordDiscovered{
				Domain: ip,
				Type:   ptrRecordType,
				Value:  zoneRecordValue(rr),
				TTL:    rr.Header().TTL,
			})
		}
	}
	sort.Slice(records.PTR, func(i, j int) bool {
		if records.PTR[i].IP != records.PTR[j].IP {
			return records.PTR[i].IP < records.PTR[j].IP
		}
		return records.PTR[i].Hostname < records.PTR[j].Hostname
	})
}

func (c *Client) collectSOAAndSec(records *Records, runQuery func(uint16) []dns.RR) {
	for _, rr := range runQuery(dns.TypeSOA) {
		if soa, ok := rr.(*dns.SOA); ok {
			records.SOA = &SOARecord{
				PrimaryNS:  trimDot(soa.Ns),
				AdminEmail: decodeSOARName(soa.Mbox),
				Serial:     soa.Serial,
				Refresh:    soa.Refresh,
				Retry:      soa.Retry,
				Expire:     soa.Expire,
				MinTTL:     soa.Minttl,
			}
			break
		}
	}

	for _, rr := range runQuery(dns.TypeDNSKEY) {
		if _, ok := rr.(*dns.DNSKEY); ok {
			records.DNSSEC = true
			break
		}
	}
}

// ZoneTransfer attempts AXFR then IXFR against each nameserver for domain, returning
// the nameserver hostname that succeeded and the records, or empty string and nil if
// all fail. Failures are logged and expected (most servers refuse zone transfers).
//
// It is the tool's one active capability, so it is the only dnsinfo path that takes a
// hard exclusion policy. When policy is non-nil, an excluded zone or a nameserver
// whose hostname (or literal address) matches a hard exclusion is rejected before
// any traffic, and a nameserver hostname is resolved once through the configured
// resolver, its answers
// are filtered against the IP/CIDR policy, and only an allowed literal address is
// dialed - so a second resolution cannot reintroduce an excluded address, and a
// nameserver whose every answer is excluded is refused rather than transferred. The
// engagement scope's root/include boundary is deliberately not applied to a
// nameserver: an allowed customer zone may use an authoritative server under another
// provider's domain, while an explicit exclusion still wins. A nil policy keeps the
// standalone behavior (dial the nameserver name and let the transfer client resolve),
// for library callers and unit tests; production always injects a policy.
func (c *Client) ZoneTransfer(ctx context.Context, domain string, nameservers []string, policy *scopecheck.Exclusions) (string, []ZoneRecord) {
	if len(nameservers) == 0 {
		return "", nil
	}
	fqdn := toFQDN(domain)
	// Orchestration checks the zone before calling the tool, but the policy-bearing
	// tool API must also fail closed for direct callers.
	if policy != nil {
		if excluded, reason := policy.HostExcluded(domain); excluded {
			scopecheck.ReportRejection(ctx, scopecheck.Rejection{Host: trimDot(fqdn), Reason: reason})
			c.emit(ctx, ZoneTransferTargetRejected{Domain: fqdn, Reason: reason})
			return "", nil
		}
	}
	c.emit(ctx, ZoneTransferStarted{Domain: fqdn, Nameservers: len(nameservers)})

	for _, raw := range nameservers {
		host, port := splitNameserver(raw)
		if host == "" {
			continue
		}
		// Explicit exclusion of the nameserver identity: a domain rule for a hostname,
		// a CIDR rule for a literal address. Checked before resolution or any dial.
		if policy != nil {
			if excluded, reason := policy.HostExcluded(host); excluded {
				scopecheck.ReportRejection(ctx, scopecheck.Rejection{Host: host, Reason: reason})
				c.emit(ctx, ZoneTransferTargetRejected{Domain: fqdn, Nameserver: host, Reason: reason})
				continue
			}
		}

		dials, ok := c.zoneTransferDials(ctx, fqdn, host, port, policy)
		if !ok {
			continue
		}

		for _, dial := range dials {
			records, err := c.axfr(ctx, fqdn, dial)
			if err != nil {
				c.emit(ctx, AXFRFailed{Domain: fqdn, Nameserver: host, Err: err})
				records, err = c.ixfr(ctx, fqdn, dial)
			}
			if err != nil {
				c.emit(ctx, ZoneTransferFailed{Domain: fqdn, Nameserver: host, Err: err})
				continue
			}
			if len(records) > 0 {
				c.emit(ctx, ZoneTransferSucceeded{Domain: fqdn, Nameserver: host, Records: len(records)})
				return host, records
			}
		}
	}

	return "", nil
}

// zoneTransferDials returns the ordered host:port dial strings for one nameserver,
// and false when there is nothing allowed to dial. A literal address (already
// exclusion-checked by the caller) and the nil-policy path dial the given host
// directly. Under an active policy, a hostname is resolved once, every excluded
// answer is dropped (each emitting a rejection carrying the resolved IP), and the
// remaining allowed literals are dialed; if resolution yields answers but all are
// excluded, the nameserver is refused.
func (c *Client) zoneTransferDials(ctx context.Context, zone, host, port string, policy *scopecheck.Exclusions) ([]string, bool) {
	if policy == nil || net.ParseIP(host) != nil {
		return []string{net.JoinHostPort(host, port)}, true
	}

	addrs := c.resolveHostAddrs(ctx, host)
	if len(addrs) == 0 {
		c.emit(ctx, ZoneTransferFailed{Domain: zone, Nameserver: host, Err: fmt.Errorf("nameserver %s resolved to no address", host)})
		return nil, false
	}

	dials := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if excluded, reason := policy.AddrExcluded(addr); excluded {
			scopecheck.ReportRejection(ctx, scopecheck.Rejection{Host: host, ResolvedIP: addr.String(), Reason: reason})
			c.emit(ctx, ZoneTransferTargetRejected{Domain: zone, Nameserver: host, ResolvedIP: addr.String(), Reason: reason})
			continue
		}
		dials = append(dials, net.JoinHostPort(addr.String(), port))
	}
	return dials, len(dials) > 0
}

// resolveHostAddrs resolves host to its A and AAAA addresses through the configured
// resolver, unmapped and in deterministic (IPv4-then-IPv6, sorted) order. It reuses
// the passive query path and, like it, treats a failed lookup as no answer.
func (c *Client) resolveHostAddrs(ctx context.Context, host string) []netip.Addr {
	fqdn := toFQDN(host)
	var addrs []netip.Addr
	if rrs, err := c.query(ctx, fqdn, dns.TypeA); err == nil {
		for _, rr := range rrs {
			if a, ok := rr.(*dns.A); ok {
				addrs = append(addrs, a.Addr.Unmap())
			}
		}
	}
	if rrs, err := c.query(ctx, fqdn, dns.TypeAAAA); err == nil {
		for _, rr := range rrs {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				addrs = append(addrs, aaaa.Addr.Unmap())
			}
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].String() < addrs[j].String() })
	return addrs
}

// splitNameserver separates a nameserver entry into its host and port, defaulting to
// port 53. It accepts a bare name or address, a bracketed IPv6 literal, and an entry
// that already carries a port.
func splitNameserver(ns string) (host, port string) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(ns); err == nil {
		return h, p
	}
	if strings.HasPrefix(ns, "[") && strings.HasSuffix(ns, "]") {
		ns = strings.TrimPrefix(strings.TrimSuffix(ns, "]"), "[")
	}
	return ns, "53"
}

func (c *Client) axfr(ctx context.Context, domain, nameserver string) ([]ZoneRecord, error) {
	return c.transferIn(ctx, dns.NewMsg(domain, dns.TypeAXFR), nameserver)
}

func (c *Client) ixfr(ctx context.Context, domain, nameserver string) ([]ZoneRecord, error) {
	msg := dns.NewMsg(domain, dns.TypeIXFR)
	// Authority SOA with serial 0 tells the server to send the full zone.
	// Ns and Mbox must be valid FQDNs; their values are ignored by the server.
	soa := &dns.SOA{}
	soa.Hdr = dns.Header{Name: domain, Class: dns.ClassINET, TTL: 3600}
	soa.Ns = domain
	soa.Mbox = "."
	soa.Serial = 0
	msg.Ns = []dns.RR{soa}
	return c.transferIn(ctx, msg, nameserver)
}

const maxZoneRecords = 10000

func (c *Client) transferIn(ctx context.Context, msg *dns.Msg, nameserver string) ([]ZoneRecord, error) {
	tCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	envelopes, err := (&dns.Client{}).TransferIn(tCtx, msg, "tcp", nameserver)
	if err != nil {
		return nil, err
	}

	records := make([]ZoneRecord, 0, 16)
	for envelope := range envelopes {
		if envelope == nil {
			continue
		}
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		for _, rr := range envelope.Answer {
			if len(records) >= maxZoneRecords {
				return nil, fmt.Errorf("zone transfer exceeded %d records", maxZoneRecords)
			}
			records = append(records, zoneRecordFromRR(rr))
		}
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("zone transfer returned no records")
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		if records[i].Value != records[j].Value {
			return records[i].Value < records[j].Value
		}
		return records[i].TTL < records[j].TTL
	})

	return records, nil
}

func (c *Client) query(ctx context.Context, domain string, qtype uint16) ([]dns.RR, error) {
	msg := dns.NewMsg(domain, qtype)
	msg.RecursionDesired = true

	response, err := c.exchange(ctx, msg, "udp")
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		response, err = c.exchange(ctx, msg, "tcp")
		if err != nil {
			return nil, err
		}
	}
	if response.Rcode != dns.RcodeSuccess {
		if response.Rcode == dns.RcodeNameError {
			return nil, errNXDomain
		}
		return nil, fmt.Errorf("rcode %s", dnsutil.RcodeToString(response.Rcode))
	}
	return response.Answer, nil
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func (c *Client) emitErr(ctx context.Context, target, qtype string, isPTR bool, err error) {
	errStr := strings.ToLower(err.Error())
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) || strings.Contains(errStr, "timeout") {
		c.emit(ctx, DNSTimeout{Domain: target, Type: qtype, Attempt: 1, Err: err})
		return
	}
	if strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "throttled") || strings.Contains(errStr, "too many") {
		c.emit(ctx, DNSRateLimited{Domain: target, Type: qtype, Err: err})
		return
	}
	if strings.Contains(errStr, "servfail") {
		c.emit(ctx, DNSServerError{Domain: target, Type: qtype, Rcode: dns.RcodeServerFailure, Err: err})
		return
	}
	if strings.Contains(errStr, "refused") {
		c.emit(ctx, DNSServerError{Domain: target, Type: qtype, Rcode: dns.RcodeRefused, Err: err})
		return
	}
	if isPTR {
		c.emit(ctx, PTRQueryFailed{IP: target, Err: err})
	} else {
		c.emit(ctx, QueryFailed{Domain: target, Type: qtype, Err: err})
	}
}

func (c *Client) exchange(ctx context.Context, msg *dns.Msg, network string) (*dns.Msg, error) {
	qCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	response, _, err := (&dns.Client{}).Exchange(qCtx, msg, network, c.cfg.Resolver)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("dns returned no response")
	}
	return response, nil
}

func zoneRecordFromRR(rr dns.RR) ZoneRecord {
	hdr := rr.Header()
	return ZoneRecord{
		Name:  trimDot(hdr.Name),
		Type:  dnsutil.TypeToString(dns.RRToType(rr)),
		Value: zoneRecordValue(rr),
		TTL:   hdr.TTL,
	}
}

func zoneRecordValue(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.Addr.String()
	case *dns.AAAA:
		return r.Addr.String()
	case *dns.CNAME:
		return trimDot(r.Target)
	case *dns.MX:
		return fmt.Sprintf("%d %s", r.Preference, trimDot(r.Mx))
	case *dns.NS:
		return trimDot(r.Ns)
	case *dns.TXT:
		return strings.Join(r.Txt, "")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			trimDot(r.Ns), trimDot(r.Mbox),
			r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl,
		)
	case *dns.PTR:
		return trimDot(r.Ptr)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, trimDot(r.Target))
	default:
		return rr.String()
	}
}

func toFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func trimDot(name string) string {
	return strings.TrimSuffix(name, ".")
}

func decodeSOARName(rname string) string {
	rname = strings.TrimSuffix(strings.TrimSpace(rname), ".")
	if rname == "" {
		return ""
	}

	var b strings.Builder
	separatorSeen := false
	escaped := false

	for i := 0; i < len(rname); i++ {
		ch := rname[i]
		if escaped {
			b.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '.' && !separatorSeen {
			b.WriteByte('@')
			separatorSeen = true
			continue
		}
		b.WriteByte(ch)
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}
