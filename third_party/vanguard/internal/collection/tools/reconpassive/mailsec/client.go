package mailsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

type lookupStats struct {
	mu         sync.Mutex
	total      int
	successful int
	failed     int
	degraded   bool
}

// SPF lookup limits per RFC 7208: at most 10 DNS-generating mechanisms and 2
// void lookups, with a bound on include/redirect recursion depth.
const (
	spfLookupLimit  = 10
	spfVoidLimit    = 2
	maxSPFRecursion = 10
	strictnessNone  = "None"
)

// dkimSelectors are the common DKIM selector labels probed for each domain.
var dkimSelectors = []string{
	"default", "google", "selector1", "selector2",
	"k1", "mandrill", "s1", "s2", "mail", "dkim",
	"sm1", "sm2", "sig1",
}

// Config holds configuration for the Client.
type Config struct {
	// Resolver is the DNS server address (e.g. "8.8.8.8:53").
	Resolver string
	// Timeout is the per-query DNS timeout.
	Timeout time.Duration
	// MaxRetries is the number of extra attempts after the first for a transient
	// failure (UDP timeout, SERVFAIL). 0 disables retrying. A definitive negative
	// (NXDOMAIN, a successful answer) is never retried. A transient timeout on the
	// MX query otherwise reports MX 0 for a live mail domain.
	MaxRetries int
	// BackoffMin is the wait before the first retry; the wait doubles each retry up
	// to BackoffMax. Each attempt is still bounded by Timeout.
	BackoffMin time.Duration
	BackoffMax time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client probes a domain's email-security DNS records (MX, SPF, DMARC, DKIM,
// BIMI) and performs static SPF analysis.
type Client struct {
	cfg Config
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Resolver == "" {
		return nil, fmt.Errorf("mailsec: Config.Resolver is required")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("mailsec: Config.Timeout must be positive")
	}
	if cfg.MaxRetries < -1 {
		return nil, fmt.Errorf("mailsec: Config.MaxRetries must be >= -1")
	}
	// Backoff is only consulted between retries, so it is required only when
	// retrying is enabled (the config layer mandates it explicitly regardless).
	if cfg.MaxRetries != 0 {
		if cfg.BackoffMin <= 0 {
			return nil, fmt.Errorf("mailsec: Config.BackoffMin must be positive when MaxRetries > 0")
		}
		if cfg.BackoffMax <= 0 {
			return nil, fmt.Errorf("mailsec: Config.BackoffMax must be positive when MaxRetries > 0")
		}
	}
	return &Client{cfg: cfg}, nil
}

// Lookup gathers the mail-security records for domain. Individual record
// failures are reported as events and skipped, so partial results are still
// returned; only an empty domain is a hard error.
func (c *Client) Lookup(ctx context.Context, domain string) (*MailRecords, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("mailsec: domain is empty")
	}
	c.emit(ctx, LookupStarted{Domain: domain})

	stats := &lookupStats{}
	qf := func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
		stats.mu.Lock()
		stats.total++
		stats.mu.Unlock()
		rrs, err := c.query(ctx, name, qtype)
		if err != nil {
			stats.mu.Lock()
			stats.failed++
			stats.degraded = true
			stats.mu.Unlock()
			c.emitDNSError(ctx, name, qtype, err)
			return nil, err
		}
		stats.mu.Lock()
		stats.successful++
		stats.mu.Unlock()
		return rrs, nil
	}

	records := &MailRecords{}

	if rrs := c.runQueryWith(ctx, domain, dns.TypeMX, qf); rrs != nil {
		records.MX = collectMX(rrs)
	}

	spfAnalysis := analyzeSPFWith(ctx, domain, qf)
	c.processSPF(ctx, domain, spfAnalysis, records, stats)

	dmarc := c.runQueryWith(ctx, "_dmarc."+domain, dns.TypeTXT, qf)
	records.DMARC = firstTXTWithPrefix(dmarc, "v=dmarc1")
	if records.DMARC != "" {
		if !strings.Contains(strings.ToLower(records.DMARC), "p=") {
			c.emit(ctx, RecordParseError{Domain: domain, Type: "DMARC", RawTXT: records.DMARC, Err: errors.New("missing required p= policy tag in DMARC record")})
			stats.degraded = true
		} else {
			c.emit(ctx, PolicyDiscovered{Domain: domain, Type: "DMARC", Strictness: classifyDMARCStrictness(records.DMARC), Raw: records.DMARC})
		}
	}
	records.DMARCSeverity = classifyDMARC(records.DMARC)

	records.DKIM = c.lookupDKIMWith(ctx, domain, qf)

	bimi := c.runQueryWith(ctx, "default._bimi."+domain, dns.TypeTXT, qf)
	if raw := firstTXTWithPrefix(bimi, "v=bimi1"); raw != "" {
		records.BIMI = parseBIMI(raw)
		if records.BIMI.LogoURL == "" {
			c.emit(ctx, RecordParseError{Domain: domain, Type: "BIMI", RawTXT: raw, Err: errors.New("missing required l= logo URL tag in BIMI record")})
			stats.degraded = true
		} else {
			c.emit(ctx, PolicyDiscovered{Domain: domain, Type: "BIMI", Strictness: strictnessNone, Raw: raw})
		}
	}

	mtasts := c.runQueryWith(ctx, "_mta-sts."+domain, dns.TypeTXT, qf)
	if raw := firstTXTWithPrefix(mtasts, "v=stsv1"); raw != "" {
		records.MTASTS = raw
		if !strings.Contains(strings.ToLower(raw), "id=") {
			c.emit(ctx, RecordParseError{Domain: domain, Type: "MTA-STS", RawTXT: raw, Err: errors.New("missing required id= tag in MTA-STS record")})
			stats.degraded = true
		} else {
			c.emit(ctx, PolicyDiscovered{Domain: domain, Type: "MTA-STS", Strictness: strictnessNone, Raw: raw})
		}
	}

	c.emit(ctx, LookupCompleted{
		Domain:            domain,
		MX:                len(records.MX),
		HasSPF:            records.SPF != "",
		DMARCSeverity:     records.DMARCSeverity,
		DKIM:              len(records.DKIM),
		HasBIMI:           records.BIMI != nil,
		HasMTASTS:         records.MTASTS != "",
		TotalQueries:      stats.total,
		SuccessfulQueries: stats.successful,
		FailedQueries:     stats.failed,
		Degraded:          stats.degraded,
	})
	return records, nil
}

func (c *Client) processSPF(ctx context.Context, domain string, spfAnalysis *SPFAnalysis, records *MailRecords, stats *lookupStats) {
	if spfAnalysis == nil || (len(spfAnalysis.Records) == 0 && len(spfAnalysis.Errors) == 0) {
		return
	}
	records.SPFAnalysis = spfAnalysis
	if len(spfAnalysis.Records) == 0 {
		if len(spfAnalysis.Errors) > 0 {
			stats.degraded = true
		}
		return
	}
	records.SPF = spfAnalysis.Records[0]
	if spfAnalysis.Multiple || len(spfAnalysis.Errors) > 0 {
		for _, errStr := range spfAnalysis.Errors {
			c.emit(ctx, RecordParseError{Domain: domain, Type: "SPF", RawTXT: strings.Join(spfAnalysis.Records, "; "), Err: errors.New(errStr)})
		}
		stats.degraded = true
		return
	}
	c.emit(ctx, PolicyDiscovered{Domain: domain, Type: "SPF", Strictness: classifySPFStrictness(records.SPF), Raw: records.SPF})
}

func (c *Client) runQueryWith(ctx context.Context, name string, qtype uint16, qf queryFunc) []dns.RR {
	rrs, err := qf(ctx, name, qtype)
	if err != nil {
		return nil
	}
	return rrs
}

func (c *Client) emitDNSError(ctx context.Context, name string, qtype uint16, err error) {
	if isDNSTimeout(err) {
		c.emit(ctx, DNSTimeout{Domain: name, Type: dnsutil.TypeToString(qtype), Attempt: c.cfg.MaxRetries + 1, Err: err})
	} else if rcode, ok := isDNSServerError(err); ok {
		c.emit(ctx, DNSServerError{Domain: name, Type: dnsutil.TypeToString(qtype), Rcode: rcode, Err: err})
	} else {
		c.emit(ctx, QueryFailed{Name: name, Type: dnsutil.TypeToString(qtype), Err: err})
	}
}

func isDNSTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "timeout")
}

func isDNSServerError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "rcode ") {
		return strings.TrimPrefix(msg, "rcode "), true
	}
	return "", false
}

func classifySPFStrictness(record string) string {
	lower := strings.ToLower(strings.TrimSpace(record))
	if strings.HasSuffix(lower, "-all") || strings.Contains(lower, " -all") {
		return "Reject"
	}
	if strings.HasSuffix(lower, "~all") || strings.Contains(lower, " ~all") {
		return "Quarantine"
	}
	return strictnessNone
}

func classifyDMARCStrictness(record string) string {
	lower := strings.ToLower(record)
	for _, part := range strings.Split(lower, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			val := strings.TrimSpace(part[2:])
			switch val {
			case "reject":
				return "Reject"
			case "quarantine":
				return "Quarantine"
			}
		}
	}
	return strictnessNone
}

// classifyDMARC returns severity based on the DMARC policy tag: "critical" when
// missing, "warning" for p=none, "info" for p=quarantine, and "ok" for p=reject.
func classifyDMARC(record string) string {
	record = strings.TrimSpace(record)
	if record == "" {
		return "critical"
	}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "p=") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(part[2:])) {
		case "reject":
			return "ok"
		case "quarantine":
			return "info"
		case "none":
			return "warning"
		}
	}
	return "warning"
}

func (c *Client) lookupDKIMWith(ctx context.Context, domain string, qf queryFunc) []DKIMRecord {
	selectorOrder := make(map[string]int, len(dkimSelectors))
	for i, selector := range dkimSelectors {
		selectorOrder[selector] = i
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make([]DKIMRecord, 0)
	)
	for _, selector := range dkimSelectors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rrs := c.runQueryWith(ctx, selector+"._domainkey."+domain, dns.TypeTXT, qf)
			for _, value := range txtValues(rrs) {
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "v=dkim1") {
					continue
				}
				mu.Lock()
				results = append(results, DKIMRecord{Selector: selector, Value: value})
				mu.Unlock()
				return
			}
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return selectorOrder[results[i].Selector] < selectorOrder[results[j].Selector]
	})
	return results
}

func collectMX(rrs []dns.RR) []MXRecord {
	mx := make([]MXRecord, 0, len(rrs))
	for _, rr := range rrs {
		if m, ok := rr.(*dns.MX); ok {
			mx = append(mx, MXRecord{Host: strings.TrimSuffix(m.Mx, "."), Priority: m.Preference})
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

func firstTXTWithPrefix(rrs []dns.RR, prefix string) string {
	prefix = strings.ToLower(prefix)
	for _, value := range txtValues(rrs) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), prefix) {
			return value
		}
	}
	return ""
}

func txtValues(rrs []dns.RR) []string {
	values := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if txt, ok := rr.(*dns.TXT); ok {
			values = append(values, strings.Join(txt.Txt, ""))
		}
	}
	return values
}

func parseBIMI(raw string) *BIMIRecord {
	record := &BIMIRecord{Raw: raw}
	for _, part := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "l":
			record.LogoURL = strings.TrimSpace(value)
		case "a":
			record.VMCURL = strings.TrimSpace(value)
		}
	}
	return record
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// query performs a DNS query against the configured resolver, retrying a
// transient failure up to MaxRetries times with an exponential backoff. A single
// UDP query against a busy resolver can time out, which for the MX query would
// report MX 0 for a live mail domain; the retry recovers it. A definitive negative
// (NXDOMAIN, or a successful answer) is never retried - absent mail records are
// normal and return no records and no error.
func (c *Client) query(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	for attempt := 0; ; attempt++ {
		rrs, transient, err := c.queryOnce(ctx, name, qtype)
		if err == nil {
			return rrs, nil
		}
		if !transient || (c.cfg.MaxRetries >= 0 && attempt >= c.cfg.MaxRetries) || ctx.Err() != nil {
			return nil, err
		}
		c.emit(ctx, QueryRetried{Name: name, Type: dnsutil.TypeToString(qtype), Attempt: attempt + 1, Err: err})
		if berr := c.backoff(ctx, attempt); berr != nil {
			return nil, berr
		}
	}
}

// queryOnce performs a single DNS query. The transient return reports whether a
// failure is worth retrying (a network/timeout error or a server-side
// SERVFAIL/REFUSED) versus a definitive result (NXDOMAIN, or a success).
func (c *Client) queryOnce(ctx context.Context, name string, qtype uint16) (rrs []dns.RR, transient bool, err error) {
	msg := dns.NewMsg(toFQDN(name), qtype)
	msg.RecursionDesired = true

	response, err := c.exchange(ctx, msg, "udp")
	if err != nil {
		return nil, true, err
	}
	if response.Truncated {
		if response, err = c.exchange(ctx, msg, "tcp"); err != nil {
			return nil, true, err
		}
	}
	switch response.Rcode {
	case dns.RcodeSuccess:
		return response.Answer, false, nil
	case dns.RcodeNameError:
		return nil, false, nil
	default:
		return nil, true, fmt.Errorf("rcode %s", dnsutil.RcodeToString(response.Rcode))
	}
}

// backoff waits before the next retry: BackoffMin doubled per attempt, capped at
// BackoffMax. It honours ctx so a cancelled scan stops retrying promptly.
func (c *Client) backoff(ctx context.Context, attempt int) error {
	d := c.cfg.BackoffMin << attempt
	if d <= 0 || d > c.cfg.BackoffMax {
		d = c.cfg.BackoffMax
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
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

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func toFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
