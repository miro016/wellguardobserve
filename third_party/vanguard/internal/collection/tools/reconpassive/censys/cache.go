package censys

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// cacheDataJSON is the compiled-in Censys result fixture. It is package data, not a
// runtime file: the collector reads no cache directory, so adding results means
// editing cache_data.json and recompiling.
//
//go:embed cache_data.json
var cacheDataJSON []byte

// cacheData is the decoded shape of cache_data.json. Both maps are keyed by the
// normalized domain (trimmed, lowercased) exactly as Client.Search and
// Client.Certificates normalize their argument; there is no partial matching, so an
// absent key is a miss. The nested objects decode straight into the result types, so
// their JSON keys are those types' Go field names.
type cacheData struct {
	// HostSearches holds one host-search result per cached domain.
	HostSearches map[string]DomainHosts `json:"host_searches"`
	// CertificateSearches holds one certificate-history result per cached domain. It
	// is empty until certificate-history data is collected: crt.sh answered for the
	// staged domains, so Censys certificate history was never queried and a
	// cache-only history lookup is an observable miss.
	CertificateSearches map[string]DomainCertificates `json:"certificate_searches"`
}

// cache is the validated, read-only lookup built from cacheDataJSON. It is never
// mutated after loadCache returns, so it needs no lock, refresh, or persistence, and
// every lookup hands back a deep copy so a caller cannot write through to the fixture.
type cache struct {
	hosts map[string]DomainHosts
	certs map[string]DomainCertificates
}

// loadCache decodes and validates the embedded fixture. A cache-using Client calls it
// during construction so malformed data fails fast instead of mid-scan.
func loadCache() (*cache, error) {
	var data cacheData
	dec := json.NewDecoder(bytes.NewReader(cacheDataJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("censys: decode embedded cache: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("censys: decode embedded cache: multiple JSON values")
		}
		return nil, fmt.Errorf("censys: decode embedded cache trailing data: %w", err)
	}
	for domain, entry := range data.HostSearches {
		if err := validateHostEntry(domain, entry); err != nil {
			return nil, err
		}
	}
	for domain, entry := range data.CertificateSearches {
		if err := validateCertEntry(domain, entry); err != nil {
			return nil, err
		}
	}
	return &cache{hosts: data.HostSearches, certs: data.CertificateSearches}, nil
}

// validateHostEntry rejects a host-search entry that could not have come from a real
// Search call: an empty or unnormalized key, a key that disagrees with the stored
// domain, an unparseable IP, or the same host listed twice.
func validateHostEntry(domain string, entry DomainHosts) error {
	if err := validateCacheKey("host_searches", domain); err != nil {
		return err
	}
	if entry.Domain != domain {
		return fmt.Errorf("censys: embedded cache host_searches[%q] holds domain %q", domain, entry.Domain)
	}
	seen := make(map[netip.Addr]bool, len(entry.Hosts))
	for _, h := range entry.Hosts {
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			return fmt.Errorf("censys: embedded cache host_searches[%q] has invalid IP %q: %w", domain, h.IP, err)
		}
		canonical := addr.Unmap()
		if seen[canonical] {
			return fmt.Errorf("censys: embedded cache host_searches[%q] lists host %s twice", domain, canonical)
		}
		seen[canonical] = true
	}
	return nil
}

// validateCertEntry applies the same key rules to a certificate-history entry and
// rejects a certificate listed twice under one domain (the SHA-256 fingerprint is the
// CT index identity, so a repeat means the fixture was built wrong) or a validity
// window that ends before it starts.
func validateCertEntry(domain string, entry DomainCertificates) error {
	if err := validateCacheKey("certificate_searches", domain); err != nil {
		return err
	}
	if entry.Domain != domain {
		return fmt.Errorf("censys: embedded cache certificate_searches[%q] holds domain %q", domain, entry.Domain)
	}
	seen := make(map[string]bool, len(entry.Certs))
	for _, cert := range entry.Certs {
		if cert.FingerprintSHA256 == "" {
			return fmt.Errorf("censys: embedded cache certificate_searches[%q] has a certificate without a fingerprint", domain)
		}
		if seen[cert.FingerprintSHA256] {
			return fmt.Errorf("censys: embedded cache certificate_searches[%q] lists certificate %s twice", domain, cert.FingerprintSHA256)
		}
		seen[cert.FingerprintSHA256] = true
		if !cert.NotBefore.IsZero() && !cert.NotAfter.IsZero() && !cert.NotAfter.After(cert.NotBefore) {
			return fmt.Errorf("censys: embedded cache certificate_searches[%q] certificate %s expires before it starts", domain, cert.FingerprintSHA256)
		}
	}
	return nil
}

// validateCacheKey rejects an empty or unnormalized map key. Lookups normalize the
// domain the same way, so an unnormalized key could never be hit.
func validateCacheKey(section, domain string) error {
	if domain == "" {
		return fmt.Errorf("censys: embedded cache %s has an empty key", section)
	}
	if domain != normalizeDomain(domain) {
		return fmt.Errorf("censys: embedded cache %s key %q is not normalized", section, domain)
	}
	return nil
}

// normalizeDomain is the single normalization used by both the API calls and the
// cache lookups, so a cached key matches exactly the domain a caller would query.
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// hostsFor returns a deep copy of the cached host search for domain, capped to
// maxHosts exactly as the service path caps a live search: dropping hosts marks the
// returned result truncated. The bool is false when the domain is not cached.
func (c *cache) hostsFor(domain string, maxHosts int) (*DomainHosts, bool) {
	entry, ok := c.hosts[normalizeDomain(domain)]
	if !ok {
		return nil, false
	}
	out := DomainHosts{Domain: entry.Domain, Hosts: copyHosts(entry.Hosts), Truncated: entry.Truncated}
	if maxHosts > 0 && len(out.Hosts) > maxHosts {
		out.Hosts = out.Hosts[:maxHosts]
		out.Truncated = true
	}
	return &out, true
}

// certificatesFor returns a deep copy of the cached certificate history for domain.
// The bool is false when the domain is not cached; no certificate history is staged
// yet, so this misses for every domain until such data is collected.
func (c *cache) certificatesFor(domain string) (*DomainCertificates, bool) {
	entry, ok := c.certs[normalizeDomain(domain)]
	if !ok {
		return nil, false
	}
	out := DomainCertificates{
		Domain:    entry.Domain,
		Certs:     copyCerts(entry.Certs),
		Names:     copyStrings(entry.Names),
		Present:   entry.Present,
		Truncated: entry.Truncated,
	}
	return &out, true
}

// copyHosts deep-copies host results, including the slices and pointers nested in
// each host, so a mutated result cannot reach back into the fixture.
func copyHosts(in []HostResult) []HostResult {
	if in == nil {
		return nil
	}
	out := make([]HostResult, len(in))
	for i, h := range in {
		out[i] = h
		out[i].Services = copyServices(h.Services)
		out[i].Products = copyStrings(h.Products)
		out[i].Vulns = copyStrings(h.Vulns)
		out[i].Labels = copyStrings(h.Labels)
		out[i].Sources = copyStrings(h.Sources)
		out[i].NetworkCIDRs = copyStrings(h.NetworkCIDRs)
		if h.ASN != nil {
			asn := *h.ASN
			out[i].ASN = &asn
		}
		if h.Location != nil {
			loc := *h.Location
			out[i].Location = &loc
		}
	}
	return out
}

// copyCerts deep-copies certificate results, including each certificate's SAN slice.
func copyCerts(in []CertResult) []CertResult {
	if in == nil {
		return nil
	}
	out := make([]CertResult, len(in))
	for i, cert := range in {
		out[i] = cert
		out[i].Names = copyStrings(cert.Names)
	}
	return out
}

// copyServices copies a host's services; ServiceInfo holds no reference fields.
func copyServices(in []ServiceInfo) []ServiceInfo {
	if in == nil {
		return nil
	}
	out := make([]ServiceInfo, len(in))
	copy(out, in)
	return out
}

// copyStrings copies a string slice, preserving nil so a copy compares equal to its
// original.
func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
