package asn

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// Config holds configuration for the Client.
type Config struct {
	// Resolver is the DNS server address (e.g. "8.8.8.8:53").
	Resolver string
	// Timeout is the per-query DNS timeout.
	Timeout time.Duration
	// MaxRetries is the number of extra attempts after the first for a transient
	// failure (UDP timeout, SERVFAIL). 0 disables retrying. A definitive negative
	// (NXDOMAIN, a successful empty answer) is never retried.
	MaxRetries int
	// BackoffMin is the wait before the first retry; the wait doubles each retry up
	// to BackoffMax. Each attempt is still bounded by Timeout, so the total stays
	// predictable.
	BackoffMin time.Duration
	BackoffMax time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Record holds ASN information for a single IP address.
type Record struct {
	// IP is the queried address in canonical form.
	IP string
	// ASN is the autonomous system number.
	ASN int
	// Prefix is the announced BGP prefix (e.g. "8.8.8.0/24").
	Prefix string
	// Country is the two-letter country code.
	Country string
	// Registry is the regional registry (arin, ripe, apnic, etc.).
	Registry string
	// Name is the AS name/description.
	Name string
}

// Client performs ASN lookups via Team Cymru's DNS service.
type Client struct {
	cfg Config
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Resolver == "" {
		return nil, fmt.Errorf("asn: Config.Resolver is required")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("asn: Config.Timeout must be positive")
	}
	if cfg.MaxRetries < -1 {
		return nil, fmt.Errorf("asn: Config.MaxRetries must be >= -1")
	}
	// Backoff is only consulted between retries, so it is required only when
	// retrying is enabled (the config layer mandates it explicitly regardless).
	if cfg.MaxRetries != 0 {
		if cfg.BackoffMin <= 0 {
			return nil, fmt.Errorf("asn: Config.BackoffMin must be positive when MaxRetries > 0")
		}
		if cfg.BackoffMax <= 0 {
			return nil, fmt.Errorf("asn: Config.BackoffMax must be positive when MaxRetries > 0")
		}
	}
	return &Client{cfg: cfg}, nil
}

// Lookup resolves an IP address to its ASN information.
func (c *Client) Lookup(ctx context.Context, ip string) (*Record, error) {
	ip = strings.TrimSpace(ip)
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("asn: invalid IP address %q", ip)
	}
	canonical := parsedIP.String()
	c.emit(ctx, LookupStarted{
		IP:        canonical,
		QueryType: "TXT",
		Resolver:  c.cfg.Resolver,
	})

	var (
		queries   int
		retries   int
		successes int
		failures  int
		degraded  bool
		finalASN  int
	)
	defer func() {
		c.emit(ctx, LookupCompleted{
			IP:        canonical,
			ASN:       finalASN,
			Queries:   queries,
			Retries:   retries,
			Successes: successes,
			Failures:  failures,
			Degraded:  degraded,
		})
	}()

	var originName string
	if parsedIP.To4() != nil {
		originName = reverseIPv4(parsedIP) + ".origin.asn.cymru.com."
	} else {
		originName = reverseIPv6(parsedIP) + ".origin6.asn.cymru.com."
	}

	originTXT, originAttempts, err := c.queryTXT(ctx, canonical, "TXT", originName, &queries, &retries)
	if err != nil {
		failures++
		return nil, fmt.Errorf("asn: origin lookup for %s: %w", canonical, err)
	}
	successes++

	asn, prefix, country, registry, err := parseOriginTXT(originTXT)
	if err != nil {
		failures++
		c.emit(ctx, OriginParseFailed{
			IP:      canonical,
			TXT:     originTXT,
			RawTXT:  originTXT,
			Attempt: originAttempts,
			Err:     err,
		})
		return nil, fmt.Errorf("asn: parse origin for %s: %w", canonical, err)
	}
	finalASN = asn

	nameTXT, nameAttempts, err := c.queryTXT(ctx, canonical, "TXT", fmt.Sprintf("AS%d.asn.cymru.com.", asn), &queries, &retries)
	if err != nil {
		failures++
		degraded = true
		return nil, fmt.Errorf("asn: name lookup for AS%d: %w", asn, err)
	}
	successes++

	name, err := parseNameTXT(nameTXT)
	if err != nil {
		failures++
		degraded = true
		c.emit(ctx, NameParseFailed{
			IP:      canonical,
			ASN:     asn,
			TXT:     nameTXT,
			RawTXT:  nameTXT,
			Attempt: nameAttempts,
			Err:     err,
		})
		return nil, fmt.Errorf("asn: parse AS name for %s: %w", canonical, err)
	}

	c.emit(ctx, LookupSucceeded{
		IP:      canonical,
		ASN:     asn,
		Prefix:  prefix,
		ASName:  name,
		Country: country,
	})

	return &Record{
		IP:       canonical,
		ASN:      asn,
		Prefix:   prefix,
		Country:  country,
		Registry: registry,
		Name:     name,
	}, nil
}

// queryTXT performs the TXT lookup, retrying a transient failure up to MaxRetries
// times with an exponential backoff. A single UDP query against a busy resolver
// can time out for one IP while every other lookup in the run succeeds; without a
// retry that IP's ASN/netblock data is silently lost. A definitive negative
// (NXDOMAIN, or a successful response carrying no TXT answer) is a real "no data"
// and is returned immediately rather than retried.
func (c *Client) queryTXT(ctx context.Context, ip, queryType, name string, queries, retries *int) (txt string, attempt int, err error) {
	for attempt := 0; ; attempt++ {
		*queries++
		if attempt > 0 {
			*retries++
		}
		txt, rcode, transient, err := c.queryTXTOnce(ctx, name)
		if err == nil {
			return txt, attempt + 1, nil
		}
		if !transient || (c.cfg.MaxRetries >= 0 && attempt >= c.cfg.MaxRetries) || ctx.Err() != nil {
			c.emitDNSError(ctx, ip, queryType, rcode, attempt+1, err)
			return "", attempt + 1, err
		}
		c.emit(ctx, LookupRetried{Name: name, Attempt: attempt + 1, Err: err})
		if berr := c.backoff(ctx, attempt); berr != nil {
			c.emitDNSError(ctx, ip, queryType, rcode, attempt+1, berr)
			return "", attempt + 1, berr
		}
	}
}

// queryTXTOnce performs a single UDP TXT query. The transient return reports
// whether a failure is worth retrying (a network/timeout error or a server-side
// SERVFAIL/REFUSED) versus a definitive negative (NXDOMAIN, or a successful but
// empty answer) that must not be retried.
func (c *Client) queryTXTOnce(ctx context.Context, name string) (txt, rcode string, transient bool, err error) {
	msg := dns.NewMsg(name, dns.TypeTXT)
	msg.RecursionDesired = true

	qCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	tr := dns.NewTransport()
	tr.ReadTimeout = c.cfg.Timeout
	tr.WriteTimeout = c.cfg.Timeout
	if tr.Dialer != nil {
		tr.Dialer.Timeout = c.cfg.Timeout
	}
	client := &dns.Client{Transport: tr}
	response, _, err := client.Exchange(qCtx, msg, "udp", c.cfg.Resolver)
	if err != nil {
		// A network/timeout error is transient: the same query may succeed on retry.
		return "", "", true, err
	}
	if response == nil {
		return "", "", true, fmt.Errorf("dns returned no response for %s", name)
	}
	rcodeStr := dnsutil.RcodeToString(response.Rcode)
	if response.Rcode != dns.RcodeSuccess {
		// NXDOMAIN is a definitive negative; SERVFAIL/REFUSED are server-side
		// transients worth a retry.
		retryable := response.Rcode != dns.RcodeNameError
		return "", rcodeStr, retryable, fmt.Errorf("dns rcode %s for %s", rcodeStr, name)
	}

	for _, rr := range response.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			return strings.Join(t.Txt, ""), rcodeStr, false, nil
		}
	}

	return "", rcodeStr, false, fmt.Errorf("no TXT records for %s", name)
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

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func (c *Client) emitDNSError(ctx context.Context, ip, queryType, rcode string, attempts int, err error) {
	if isTimeout(err) {
		c.emit(ctx, DNSTimeout{
			IP:        ip,
			QueryType: queryType,
			Attempt:   attempts,
			Err:       err,
		})
		return
	}
	c.emit(ctx, DNSResolutionFailed{
		IP:        ip,
		QueryType: queryType,
		RCode:     rcode,
		Err:       err,
	})
}

func isTimeout(err error) bool {
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
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded")
}

func parseOriginTXT(value string) (asn int, prefix, country, registry string, err error) {
	fields := splitFields(value)
	if len(fields) < 5 {
		return 0, "", "", "", fmt.Errorf("unexpected origin response %q", value)
	}

	asn, err = parseASN(fields[0])
	if err != nil {
		return 0, "", "", "", err
	}

	prefix = fields[len(fields)-4]
	country = fields[len(fields)-3]
	registry = fields[len(fields)-2]
	if prefix == "" || country == "" || registry == "" {
		return 0, "", "", "", fmt.Errorf("unexpected origin response %q", value)
	}

	return asn, prefix, country, registry, nil
}

func parseNameTXT(value string) (string, error) {
	fields := splitFields(value)
	if len(fields) < 5 {
		return "", fmt.Errorf("unexpected AS name response %q", value)
	}

	name := fields[len(fields)-1]
	if name == "" {
		return "", fmt.Errorf("unexpected AS name response %q", value)
	}
	return name, nil
}

func splitFields(value string) []string {
	parts := strings.Split(value, "|")
	fields := make([]string, 0, len(parts))
	for _, p := range parts {
		fields = append(fields, strings.TrimSpace(p))
	}
	return fields
}

func parseASN(value string) (int, error) {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return 0, fmt.Errorf("missing ASN")
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("parse ASN %q: %w", parts[0], err)
	}
	return n, nil
}

func reverseIPv4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

func reverseIPv6(ip net.IP) string {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return ""
	}
	expanded := hex.EncodeToString(v6)
	nibbles := make([]string, 0, len(expanded))
	for i := len(expanded) - 1; i >= 0; i-- {
		nibbles = append(nibbles, string(expanded[i]))
	}
	return strings.Join(nibbles, ".")
}
