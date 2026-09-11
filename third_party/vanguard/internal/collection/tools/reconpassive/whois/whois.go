package whois

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	likexianwhois "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// Data source labels recording which leg answered a lookup. They are carried on
// Registration.Source so the data from different tools can be compared later.
const (
	// SourceWHOIS marks data gathered over traditional port-43 WHOIS.
	SourceWHOIS = "whois"
	// SourceRDAP marks data gathered over the RDAP HTTPS/JSON fallback.
	SourceRDAP = "rdap"
)

// Config holds configuration for the Client.
type Config struct {
	// Timeout bounds each RDAP HTTP request and the bootstrap fetch.
	Timeout time.Duration
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// errWhoisServerDown marks the synthetic WHOIS error used when the port-43 leg
// is skipped because the TLD's WHOIS server was already found unreachable.
var errWhoisServerDown = errors.New("whois: TLD WHOIS server known unreachable this run, skipped")

// Client performs domain registration lookups via WHOIS with RDAP fallback.
type Client struct {
	cfg Config

	// mu guards downTLDs, which is read and written by concurrent lookups.
	mu sync.Mutex
	// downTLDs records TLDs whose port-43 WHOIS server was unreachable earlier in
	// the run. Later lookups for the same TLD skip straight to RDAP instead of
	// paying the dial timeout again (every .no/.tech lookup hit a blocked
	// Cloudflare port-43 endpoint before falling back).
	downTLDs map[string]struct{}
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("whois: Config.Timeout must be positive")
	}
	return &Client{cfg: cfg, downTLDs: map[string]struct{}{}}, nil
}

// whoisServerDown reports whether tld's port-43 WHOIS server was already marked
// unreachable this run.
func (c *Client) whoisServerDown(tld string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.downTLDs[tld]
	return ok
}

// markWhoisServerDown records that tld's port-43 WHOIS server is unreachable.
func (c *Client) markWhoisServerDown(tld string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.downTLDs[tld] = struct{}{}
}

// emit forwards e to the configured sink when one is set.
func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func truncateSnippet(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

func isWhoisThrottled(errStr, raw string) bool {
	lower := strings.ToLower(errStr + " " + raw)
	keywords := []string{
		"rate limit",
		"quota exceeded",
		"too many requests",
		"query limit",
		"limit exceeded",
		"throttled",
		"connection refused",
		"connection reset",
		"closed by the remote host",
		"try again later",
		"maximum number of requests",
		"ban",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (c *Client) checkWhoisDate(ctx context.Context, domain, server, field, val string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	if _, ok := parseDate(val); !ok {
		c.emit(ctx, WhoisParseError{
			Domain:  domain,
			Server:  firstNonEmpty(server, domainTLD(domain)),
			Snippet: truncateSnippet(val),
			Err:     fmt.Errorf("unparseable %s date format: %q", field, val),
		})
	}
}

var dateFormats = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05-07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"January 2, 2006",
	"2006/01/02",
	"02/01/2006",
	"2006.01.02",
}

// queryWHOISFn performs raw WHOIS lookups.
// Tests can replace it to avoid live network calls.
var queryWHOISFn = func(domain string) (string, error) {
	return likexianwhois.Whois(domain)
}

// Registration holds domain registration data gathered from WHOIS or RDAP.
type Registration struct {
	// Source records which leg produced the data (SourceWHOIS or SourceRDAP),
	// so the same field set can be compared across tools and data sources.
	Source      string
	DomainName  string
	Registrar   string
	Server      string
	Status      []string
	CreatedDate time.Time
	UpdatedDate time.Time
	ExpiryDate  time.Time
	Nameservers []string
	DNSSEC      bool
	Contacts    []Contact
	Extensions  map[string]string
}

// Contact holds one WHOIS contact record.
type Contact struct {
	Role         string
	Name         string
	Organization string
	Email        string
	Phone        string
	Address      string
}

// Lookup queries registration data for domain and maps it into a Registration.
// It tries port-43 WHOIS first and falls back to RDAP when WHOIS fails. Typed
// events are emitted to the configured sink for every notable outcome.
func (c *Client) Lookup(ctx context.Context, domain string) (*Registration, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("whois lookup: domain is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("whois lookup %s: %w", domain, err)
	}
	c.emit(ctx, LookupStarted{Domain: domain})

	var (
		whoisAttempted bool
		rdapAttempted  bool
		succeeded      bool
		degraded       bool
	)
	defer func() {
		c.emit(ctx, LookupCompleted{
			Domain:         domain,
			WhoisAttempted: whoisAttempted,
			RdapAttempted:  rdapAttempted,
			Succeeded:      succeeded,
			Degraded:       degraded,
		})
	}()

	tld := domainTLD(domain)
	var whoisErr error
	//nolint:nestif // WHOIS lookup fallback logic requires nested error checking
	if c.whoisServerDown(tld) {
		// The TLD's WHOIS server already timed out this run; skip straight to RDAP
		// rather than pay the dial timeout again.
		c.emit(ctx, QuerySkipped{Domain: domain, TLD: tld})
		whoisErr = errWhoisServerDown
		degraded = true
	} else {
		whoisAttempted = true
		info, err := c.lookupWHOIS(ctx, domain)
		if err == nil {
			succeeded = true
			if info.CreatedDate.IsZero() || info.ExpiryDate.IsZero() {
				degraded = true
			}
			c.emit(ctx, LookupSucceeded{
				Domain:          domain,
				Source:          info.Source,
				Registrar:       info.Registrar,
				CreatedDate:     info.CreatedDate,
				ExpiryDate:      info.ExpiryDate,
				NameserverCount: len(info.Nameservers),
			})
			return info, nil
		}
		whoisErr = err
		degraded = true
		c.emit(ctx, QueryFailed{Domain: domain, Err: whoisErr})
		if isWhoisServerUnreachable(whoisErr) {
			c.markWhoisServerDown(tld)
		}
	}

	rdapAttempted = true
	info, rdapErr := c.lookupRDAP(ctx, domain)
	if rdapErr == nil {
		succeeded = true
		if info.CreatedDate.IsZero() || info.ExpiryDate.IsZero() {
			degraded = true
		}
		c.emit(ctx, LookupSucceeded{
			Domain:          domain,
			Source:          info.Source,
			Registrar:       info.Registrar,
			CreatedDate:     info.CreatedDate,
			ExpiryDate:      info.ExpiryDate,
			NameserverCount: len(info.Nameservers),
		})
		return info, nil
	}
	degraded = true
	c.emit(ctx, RdapFailed{Domain: domain, Err: rdapErr})

	c.emit(ctx, LookupFailed{Domain: domain, WhoisErr: whoisErr, RdapErr: rdapErr})
	return nil, fmt.Errorf("whois lookup %s: whois: %w; rdap: %w", domain, whoisErr, rdapErr)
}

// lookupWHOIS performs traditional port-43 WHOIS lookup.
func (c *Client) lookupWHOIS(ctx context.Context, domain string) (*Registration, error) {
	raw, err := queryWHOIS(ctx, domain)
	if err != nil {
		if isWhoisThrottled(err.Error(), raw) {
			c.emit(ctx, WhoisServerThrottled{
				Domain:  domain,
				Server:  domainTLD(domain),
				Message: err.Error(),
			})
		}
		return nil, err
	}
	server := extractWHOISServer(raw)
	if isWhoisThrottled("", raw) {
		msg := "whois server response indicates rate limit or quota exceeded"
		c.emit(ctx, WhoisServerThrottled{
			Domain:  domain,
			Server:  firstNonEmpty(server, domainTLD(domain)),
			Message: msg,
		})
		return nil, errors.New(msg)
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		c.emit(ctx, WhoisParseError{
			Domain:  domain,
			Server:  firstNonEmpty(server, domainTLD(domain)),
			Snippet: truncateSnippet(raw),
			Err:     err,
		})
		return nil, fmt.Errorf("parse whois for %s: %w", domain, err)
	}
	if parsed.Domain == nil {
		err := fmt.Errorf("parse whois for %s: missing domain data", domain)
		c.emit(ctx, WhoisParseError{
			Domain:  domain,
			Server:  firstNonEmpty(server, domainTLD(domain)),
			Snippet: truncateSnippet(raw),
			Err:     err,
		})
		return nil, err
	}

	c.checkWhoisDate(ctx, domain, server, "created", parsed.Domain.CreatedDate)
	c.checkWhoisDate(ctx, domain, server, "updated", parsed.Domain.UpdatedDate)
	c.checkWhoisDate(ctx, domain, server, "expiration", parsed.Domain.ExpirationDate)

	info := &Registration{
		Source:      SourceWHOIS,
		DomainName:  firstNonEmpty(parsed.Domain.Domain, domain),
		Registrar:   registrarName(parsed.Registrar),
		Server:      firstNonEmpty(server, parsed.Domain.WhoisServer),
		Status:      cleanStrings(parsed.Domain.Status),
		CreatedDate: parseDomainDate(parsed.Domain.CreatedDate, parsed.Domain.CreatedDateInTime),
		UpdatedDate: parseDomainDate(parsed.Domain.UpdatedDate, parsed.Domain.UpdatedDateInTime),
		ExpiryDate:  parseDomainDate(parsed.Domain.ExpirationDate, parsed.Domain.ExpirationDateInTime),
		Nameservers: cleanStrings(parsed.Domain.NameServers),
		DNSSEC:      parsed.Domain.DNSSec,
		Contacts:    buildContacts(parsed),
		Extensions:  buildExtensions(parsed),
	}

	return info, nil
}

type whoisResult struct {
	raw string
	err error
}

// queryWHOIS runs blocking whois query in goroutine so ctx can stop waiting.
func queryWHOIS(ctx context.Context, domain string) (string, error) {
	results := make(chan whoisResult, 1)
	go func() {
		raw, err := queryWHOISFn(domain)
		results <- whoisResult{raw: raw, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("query whois for %s: %w", domain, ctx.Err())
	case result := <-results:
		if result.err != nil {
			return "", fmt.Errorf("query whois for %s: %w", domain, result.err)
		}
		if strings.TrimSpace(result.raw) == "" {
			return "", fmt.Errorf("query whois for %s: empty response", domain)
		}
		return result.raw, nil
	}
}

// extractWHOISServer returns the responder advertised in raw WHOIS text.
func extractWHOISServer(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)
		for _, prefix := range []string{"registrar whois server:", "whois server:"} {
			if !strings.HasPrefix(lower, prefix) {
				continue
			}
			return normalizeWHOISServer(line[len(prefix):])
		}
	}
	return ""
}

// normalizeWHOISServer trims transport noise from a WHOIS server value.
func normalizeWHOISServer(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "whois://") {
		value = value[len("whois://"):]
	}
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

// domainTLD returns the last DNS label of domain (its TLD). It keys the per-run
// cache of WHOIS servers found unreachable, since one registry WHOIS server
// answers a whole TLD.
func domainTLD(domain string) string {
	if i := strings.LastIndex(domain, "."); i >= 0 {
		return domain[i+1:]
	}
	return domain
}

// isWhoisServerUnreachable reports whether err is a port-43 connection failure
// (the WHOIS host could not be dialled), as opposed to a parse or data error.
// Such a failure is TLD-wide, so later lookups for that TLD can skip WHOIS.
func isWhoisServerUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "connect to whois server failed") {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// normalizeDomain trims noise around domain before lookup.
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.Trim(domain, ".")
	return strings.ToLower(domain)
}

// registrarName picks best registrar label from parsed data.
func registrarName(contact *whoisparser.Contact) string {
	if contact == nil {
		return ""
	}
	return firstNonEmpty(contact.Name, contact.Organization)
}

// parseDomainDate tries known layouts, then parser fallback time.
func parseDomainDate(value string, fallback *time.Time) time.Time {
	if parsed, ok := parseDate(value); ok {
		return parsed
	}
	if fallback != nil {
		return fallback.UTC()
	}
	return time.Time{}
}

// parseDate tries common WHOIS date formats in order.
func parseDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range dateFormats {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

// buildContacts maps parsed WHOIS contacts into crawler output contacts.
func buildContacts(parsed whoisparser.WhoisInfo) []Contact {
	contacts := make([]Contact, 0, 3)
	if contact, ok := mapContact("registrant", parsed.Registrant); ok {
		contacts = append(contacts, contact)
	}
	if contact, ok := mapContact("administrative", parsed.Administrative); ok {
		contacts = append(contacts, contact)
	}
	if contact, ok := mapContact("technical", parsed.Technical); ok {
		contacts = append(contacts, contact)
	}
	if len(contacts) == 0 {
		return nil
	}
	return contacts
}

// mapContact copies one parser contact into local schema.
func mapContact(role string, src *whoisparser.Contact) (Contact, bool) {
	if src == nil {
		return Contact{}, false
	}
	contact := Contact{
		Role:         role,
		Name:         strings.TrimSpace(src.Name),
		Organization: strings.TrimSpace(src.Organization),
		Email:        strings.TrimSpace(src.Email),
		Phone:        formatPhone(src.Phone, src.PhoneExt),
		Address:      joinNonEmpty(src.Street, src.City, src.Province, src.PostalCode, src.Country),
	}
	if contact.Name == "" && contact.Organization == "" && contact.Email == "" && contact.Phone == "" && contact.Address == "" {
		return Contact{}, false
	}
	return contact, true
}

// buildExtensions keeps extra parsed fields not promoted into main schema.
func buildExtensions(parsed whoisparser.WhoisInfo) map[string]string {
	extensions := map[string]string{}
	if parsed.Domain != nil {
		addExtension(extensions, "domain_id", parsed.Domain.ID)
		addExtension(extensions, "punycode", parsed.Domain.Punycode)
		addExtension(extensions, "extension", parsed.Domain.Extension)
		addExtension(extensions, "whois_server", parsed.Domain.WhoisServer)
	}
	if parsed.Registrar != nil {
		addExtension(extensions, "registrar_id", parsed.Registrar.ID)
		addExtension(extensions, "registrar_referral_url", parsed.Registrar.ReferralURL)
	}
	if len(extensions) == 0 {
		return nil
	}
	return extensions
}

// addExtension stores value under key when value exists.
func addExtension(extensions map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	extensions[key] = value
}

// cleanStrings trims empty values and keeps first copy of each value.
func cleanStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// formatPhone joins phone and extension when both exist.
func formatPhone(phone, extension string) string {
	phone = strings.TrimSpace(phone)
	extension = strings.TrimSpace(extension)
	if phone == "" {
		return ""
	}
	if extension == "" {
		return phone
	}
	return phone + " x" + extension
}

// joinNonEmpty joins trimmed parts with ", " and skips empty values.
func joinNonEmpty(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		clean = append(clean, part)
	}
	return strings.Join(clean, ", ")
}

// firstNonEmpty returns first trimmed non-empty string.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
