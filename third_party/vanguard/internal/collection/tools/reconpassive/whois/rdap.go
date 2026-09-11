package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rdapBootstrapURL is the IANA RDAP bootstrap service for DNS registrations.
// Tests can override this.
var rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

// rdapMaxBody caps response size to avoid OOM on rogue servers.
const rdapMaxBody = 512 * 1024

// bootstrap caches the IANA TLD-to-RDAP-server mapping for the process
// lifetime, loaded lazily on first RDAP request.
var bootstrap struct {
	once    sync.Once
	servers map[string]string // TLD -> base URL
	err     error
}

// rdapBootstrap is the JSON structure from IANA's dns.json.
type rdapBootstrap struct {
	Version     string  `json:"version"`
	Publication string  `json:"publication"`
	Services    [][]any `json:"services"`
}

// rdapDomainResponse is a minimal subset of the RDAP domain response.
type rdapDomainResponse struct {
	Handle      string       `json:"handle"`
	LDHName     string       `json:"ldhName"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Nameservers []rdapNS     `json:"nameservers"`
	Entities    []rdapEntity `json:"entities"`
	SecureDNS   *rdapDNSSec  `json:"secureDNS"`
	Port43      string       `json:"port43"`
	Links       []rdapLink   `json:"links"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapEntity struct {
	Handle string      `json:"handle"`
	Roles  []string    `json:"roles"`
	VCard  any         `json:"vcardArray"`
	Events []rdapEvent `json:"events"`
}

type rdapDNSSec struct {
	DelegationSigned bool `json:"delegationSigned"`
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// lookupRDAP queries RDAP for domain registration data. Returns nil, error
// if RDAP is not available for the TLD or query fails.
func (c *Client) lookupRDAP(ctx context.Context, domain string) (*Registration, error) {
	baseURL, err := c.rdapServerForDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(baseURL, "/") + "/domain/" + domain

	body, err := rdapGet(ctx, url, c.cfg.Timeout)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 429") {
			c.emit(ctx, RateLimited{
				Domain:  domain,
				Server:  baseURL,
				Attempt: 1,
				Err:     err,
			})
		}
		return nil, fmt.Errorf("rdap query %s: %w", domain, err)
	}

	var resp rdapDomainResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		c.emit(ctx, RDAPParseError{
			Domain:  domain,
			Server:  baseURL,
			Snippet: truncateSnippet(string(body)),
			Err:     err,
		})
		return nil, fmt.Errorf("rdap parse %s: %w", domain, err)
	}

	info := c.mapRDAPToWHOISWithEvents(ctx, domain, baseURL, &resp)
	return info, nil
}

// rdapServerForDomain finds the RDAP base URL for the given domain's TLD.
func (c *Client) rdapServerForDomain(ctx context.Context, domain string) (string, error) {
	bootstrap.once.Do(func() {
		bootstrap.servers, bootstrap.err = loadBootstrap(ctx, c.cfg.Timeout)
	})
	if bootstrap.err != nil {
		return "", fmt.Errorf("rdap bootstrap: %w", bootstrap.err)
	}

	tld := extractTLD(domain)
	if tld == "" {
		return "", fmt.Errorf("rdap: cannot extract TLD from %q", domain)
	}

	base, ok := bootstrap.servers[tld]
	if !ok {
		return "", fmt.Errorf("rdap: no server for TLD %q", tld)
	}
	return base, nil
}

// loadBootstrap fetches and parses the IANA RDAP bootstrap file.
func loadBootstrap(ctx context.Context, timeout time.Duration) (map[string]string, error) {
	body, err := rdapGet(ctx, rdapBootstrapURL, timeout)
	if err != nil {
		return nil, fmt.Errorf("fetch bootstrap: %w", err)
	}

	var bs rdapBootstrap
	if err := json.Unmarshal(body, &bs); err != nil {
		return nil, fmt.Errorf("parse bootstrap: %w", err)
	}

	servers := make(map[string]string)
	for _, svc := range bs.Services {
		if len(svc) < 2 {
			continue
		}
		tlds, ok1 := toStringSlice(svc[0])
		urls, ok2 := toStringSlice(svc[1])
		if !ok1 || !ok2 || len(urls) == 0 {
			continue
		}
		for _, tld := range tlds {
			servers[strings.ToLower(strings.Trim(tld, "."))] = urls[0]
		}
	}

	return servers, nil
}

// toStringSlice converts an any (expected []any of strings) to []string.
func toStringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// rdapGet performs a GET with timeout and size limit.
func rdapGet(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, rdapMaxBody))
}

// extractTLD returns the last label of a domain name.
func extractTLD(domain string) string {
	parts := strings.Split(strings.Trim(domain, "."), ".")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

func (c *Client) mapRDAPToWHOISWithEvents(ctx context.Context, domain, server string, resp *rdapDomainResponse) *Registration {
	info := mapRDAPToWHOIS(domain, resp)
	for _, event := range resp.Events {
		val := strings.TrimSpace(event.Date)
		if val == "" {
			continue
		}
		if _, ok := parseDate(val); !ok {
			c.emit(ctx, RDAPParseError{
				Domain:  domain,
				Server:  server,
				Snippet: truncateSnippet(val),
				Err:     fmt.Errorf("unparseable RDAP date format: %q", val),
			})
		}
	}
	return info
}

// mapRDAPToWHOIS converts an RDAP response into a Registration.
func mapRDAPToWHOIS(domain string, resp *rdapDomainResponse) *Registration {
	info := &Registration{
		Source:     SourceRDAP,
		DomainName: firstNonEmpty(resp.LDHName, domain),
		Status:     resp.Status,
		Server:     resp.Port43,
	}

	for _, event := range resp.Events {
		t, ok := parseDate(event.Date)
		if !ok {
			continue
		}
		switch event.Action {
		case "registration":
			info.CreatedDate = t
		case "last changed":
			info.UpdatedDate = t
		case "expiration":
			info.ExpiryDate = t
		}
	}

	for _, ns := range resp.Nameservers {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ns.LDHName)), ".")
		if name != "" {
			info.Nameservers = append(info.Nameservers, name)
		}
	}

	if resp.SecureDNS != nil {
		info.DNSSEC = resp.SecureDNS.DelegationSigned
	}

	info.Contacts = mapRDAPEntities(resp.Entities)

	// Find registrar from entities. entity.Handle is the registry's numeric
	// registrar ID, not a name, so the vCard's "fn"/"org" are tried first and the
	// handle is only a last-resort fallback for a missing or malformed vCard.
	for _, entity := range resp.Entities {
		fn, org := vcardNameOrg(entity.VCard)
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrar") {
				info.Registrar = firstNonEmpty(fn, org, entity.Handle, info.Registrar)
			}
		}
	}

	if resp.Handle != "" {
		info.Extensions = map[string]string{"domain_id": resp.Handle}
	}

	return info
}

// mapRDAPEntities extracts contacts from RDAP entities.
func mapRDAPEntities(entities []rdapEntity) []Contact {
	var contacts []Contact
	for _, entity := range entities {
		fn, org := vcardNameOrg(entity.VCard)
		for _, role := range entity.Roles {
			contacts = append(contacts, Contact{
				Role:         strings.ToLower(role),
				Name:         fn,
				Organization: firstNonEmpty(org, entity.Handle),
			})
		}
	}
	if len(contacts) == 0 {
		return nil
	}
	return contacts
}

// vcardNameOrg extracts the formatted name ("fn") and organization ("org")
// properties from a jCard vcardArray
// (["vcard", [["fn",{},"text","Example Registrar, Inc."], ...]]) - the RDAP
// entity's actual display name. entity.Handle is only the registry's numeric
// ID, not a name, so callers use it solely as a last-resort fallback. Tolerates
// a missing or malformed vCard (registries vary widely in how strictly they
// follow the jCard shape): any unexpected structure yields empty results
// rather than a panic.
func vcardNameOrg(raw any) (fn, org string) {
	arr, ok := raw.([]any)
	if !ok || len(arr) != 2 {
		return "", ""
	}
	props, ok := arr[1].([]any)
	if !ok {
		return "", ""
	}

	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		name, ok := prop[0].(string)
		if !ok {
			continue
		}
		switch strings.ToLower(name) {
		case "fn":
			if fn == "" {
				fn = vcardTextValue(prop[3])
			}
		case "org":
			if org == "" {
				org = vcardTextValue(prop[3])
			}
		}
	}
	return fn, org
}

// vcardTextValue extracts a display string from a jCard property value. Most
// properties carry a plain string, but some registries encode "org" as a
// structured array (e.g. ["Example Registrar, Inc."]) instead of a bare
// string; the first non-empty string element covers both shapes.
func vcardTextValue(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case []any:
		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if s = strings.TrimSpace(s); s != "" {
				return s
			}
		}
	}
	return ""
}
