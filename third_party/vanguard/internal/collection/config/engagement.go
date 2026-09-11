package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// EngagementConfig is the customer-specific half of a scan's audit-grade
// configuration. It says who and where Vanguard may scan: the customer identity,
// the scan roots, the in/out-of-scope domains, the engagement-wide work limits, and
// the exceptional authorization (out-of-scope GoScans HTTP).
//
// It is disjoint from [ScanProfile], which says how Vanguard performs the scan.
// Neither file overrides the other and no field exists in both: they are composed
// as complementary inputs (see [Scan]), never merged. Like the profile, every
// safety-relevant value is mandatory - the file alone determines the engagement, so
// an omitted decision is an error rather than a silent default. The file carries no
// API keys, credentials, or other secrets; those stay in the environment.
type EngagementConfig struct {
	Customer      Customer        `yaml:"customer"`
	Scope         EngagementScope `yaml:"scope"`
	Limits        Limits          `yaml:"limits"`
	Authorization EngagementAuthz `yaml:"authorization"`
}

// Customer identifies the engagement's customer. Name is the human-readable display
// name.
type Customer struct {
	// Name is the customer's display name. Required and non-empty.
	Name string `yaml:"name"`
}

// EngagementScope groups the customer scope: which domains are in play and the
// engagement-wide focus policy. The domain and IP exclusion lists are hard traffic
// boundaries; the IP allow list is reserved future shape and carries no admission
// behavior yet.
type EngagementScope struct {
	Domains DomainScope `yaml:"domains"`
	// IPRanges carries the network scope. Its exclude list is a hard traffic
	// boundary (every address in an excluded CIDR is out of bounds for active
	// tools); its allow list is reserved future work and must stay empty.
	IPRanges IPRangeScope `yaml:"ip_ranges"`
	// DepthCap is the maximum crawl depth that is deeply probed; -1 means no limit.
	// It bounds how deeply the engagement permits paid and active work.
	DepthCap *int `yaml:"depth_cap"`
	// ProbeProviderHosts controls active probing of IPs that only a passive
	// host-intel provider (Censys/Shodan/Netlas) attributed to an in-scope domain.
	// "never"/"corroborated"/"always"; see ProviderHostProbePolicy.
	ProbeProviderHosts ProviderHostProbePolicy `yaml:"probe_provider_hosts"`
}

// DomainScope is the domain half of the engagement scope. Roots are scan entry
// points; include names extra in-scope apexes that are not entry points; exclude
// names out-of-scope names and their subdomains.
type DomainScope struct {
	// Roots lists the scan entry points. Exactly one root is accepted initially; the
	// list shape is retained so multi-root engagements need no schema change.
	Roots []string `yaml:"roots"`
	// Include lists extra in-scope apex domains the customer owns (suffix match).
	// An included domain does not itself become a scan entry point.
	Include []string `yaml:"include"`
	// Exclude lists names (and their subdomains) to treat as out of scope. Each
	// entry is a hard traffic boundary: the exact normalized name and every
	// subdomain of it are denied all active, target-facing contact, and the deny
	// wins over root or include membership. Matching is exact-name-plus-subdomains,
	// never substring, glob, or registrable-domain.
	Exclude []string `yaml:"exclude"`
	// RestrictDiscoveryToRoots keeps discovery inside the engagement's roots. It is
	// the customer-boundary policy formerly named discovery.restrict_to_root.
	RestrictDiscoveryToRoots *bool `yaml:"restrict_discovery_to_roots"`
}

// IPRangeScope is the CIDR-shaped network scope. CIDR is the file format for both
// lists; a single address is written as /32 (IPv4) or /128 (IPv6).
type IPRangeScope struct {
	// Allow is reserved future work and must be empty. A non-empty value fails
	// validation until include semantics for network scope are specified.
	Allow []string `yaml:"allow"`
	// Exclude lists CIDR prefixes to deny all active traffic. Every address in an
	// excluded prefix is out of bounds; the deny wins over any domain that resolves
	// to it. Entries must be canonical (no host bits set) and unique.
	Exclude []string `yaml:"exclude"`
}

// Limits holds the engagement-wide caps on expensive work. Both use the shared
// count encoding: 0 = none, -1 = unlimited, positive = finite.
type Limits struct {
	// MaxPaidLookupsPerTool caps calls to each paid tool (breach/censys/virustotal/
	// shodan/netlas); -1 means unlimited and 0 permits no calls.
	MaxPaidLookupsPerTool *int `yaml:"max_paid_lookups_per_tool"`
	// MaxActiveHosts caps the per-domain active sweep (https/smtp/webinfo); -1
	// means unlimited and 0 permits no hosts.
	MaxActiveHosts *int `yaml:"max_active_hosts"`
}

// EngagementAuthz holds the engagement's exceptional authorizations: the
// out-of-scope GoScans HTTP grant. It expresses a positive customer mandate
// rather than a tool-local bypass.
type EngagementAuthz struct {
	GoScans GoScansAuthorization `yaml:"goscans"`
}

// GoScansAuthorization is the engagement's grant for the GoScans webcrawler and
// webenum modules, whose upstream requester dials redirects and links before
// Vanguard's request authorizer can judge them. Absent/false clears those modules
// before the scan starts; true readmits them and moves the scope check to each result.
type GoScansAuthorization struct {
	// AllowOutOfScopeHTTPRequests permits the crawl-following HTTP modules. It needs
	// an engagement mandate that tolerates a request to wherever a crawl leads.
	AllowOutOfScopeHTTPRequests *bool `yaml:"allow_out_of_scope_http_requests"`
}

// Root returns the single scan root. It must be called only after Validate has
// succeeded, which guarantees exactly one root.
func (e *EngagementConfig) Root() string {
	return e.Scope.Domains.Roots[0]
}

// LoadEngagement reads and validates an engagement configuration file. Unknown
// fields are rejected so a typo cannot silently fall back to a default.
func LoadEngagement(path string) (EngagementConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return EngagementConfig{}, fmt.Errorf("read engagement %s: %w", path, err)
	}
	return ParseEngagement(b, path)
}

// ParseEngagement validates an engagement held as bytes, exactly as
// [LoadEngagement] validates one held as a file. source names where the bytes came
// from and appears in every message, so a caller that never had a file still gets an
// error an operator can place.
func ParseEngagement(b []byte, source string) (EngagementConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)

	var e EngagementConfig
	if err := dec.Decode(&e); err != nil {
		return EngagementConfig{}, fmt.Errorf("parse engagement %s: %w", source, err)
	}
	if err := e.Validate(); err != nil {
		return EngagementConfig{}, fmt.Errorf("invalid engagement %s:\n%w", source, err)
	}
	return e, nil
}

// Validate enforces that every required engagement value is present and sane,
// reporting all problems at once so the operator can fix the file in one pass.
func (e *EngagementConfig) Validate() error {
	var problems []string
	req := func(cond bool, msg string) {
		if !cond {
			problems = append(problems, msg)
		}
	}

	req(strings.TrimSpace(e.Customer.Name) != "", "customer.name is required")

	d := &e.Scope.Domains
	req(len(d.Roots) == 1, "scope.domains.roots must list exactly one root initially")
	for _, r := range d.Roots {
		req(strings.TrimSpace(r) != "", "scope.domains.roots must not contain an empty root")
	}
	req(d.RestrictDiscoveryToRoots != nil, "scope.domains.restrict_discovery_to_roots is required")

	req(len(e.Scope.IPRanges.Allow) == 0,
		"scope.ip_ranges.allow is reserved future work: leave it empty until IP-range allow semantics are defined")
	problems = append(problems, validateExclusionDomains(d.Exclude)...)
	problems = append(problems, validateExclusionPrefixes(e.Scope.IPRanges.Exclude)...)

	req(e.Scope.DepthCap != nil, "scope.depth_cap is required (use -1 for no limit)")
	req(e.Scope.DepthCap == nil || *e.Scope.DepthCap >= -1, "scope.depth_cap must be >= -1")
	req(e.Scope.ProbeProviderHosts != "", "scope.probe_provider_hosts is required (never/corroborated/always)")
	req(e.Scope.ProbeProviderHosts == "" ||
		e.Scope.ProbeProviderHosts == ProviderHostProbeNever ||
		e.Scope.ProbeProviderHosts == ProviderHostProbeCorroborated ||
		e.Scope.ProbeProviderHosts == ProviderHostProbeAlways,
		"scope.probe_provider_hosts must be never, corroborated, or always")

	req(e.Limits.MaxPaidLookupsPerTool != nil, "limits.max_paid_lookups_per_tool is required (use -1 for unlimited)")
	reqLimit(req, "limits.max_paid_lookups_per_tool", e.Limits.MaxPaidLookupsPerTool)
	req(e.Limits.MaxActiveHosts != nil, "limits.max_active_hosts is required (use -1 for unlimited)")
	reqLimit(req, "limits.max_active_hosts", e.Limits.MaxActiveHosts)

	req(e.Authorization.GoScans.AllowOutOfScopeHTTPRequests != nil,
		"authorization.goscans.allow_out_of_scope_http_requests is required")

	if len(problems) > 0 {
		return fmt.Errorf("  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// ExcludedDomains returns the normalized, de-duplicated out-of-scope domain names.
// Call only after Validate has succeeded, which guarantees each entry is a valid,
// unique DNS name.
func (e *EngagementConfig) ExcludedDomains() []string {
	seen := make(map[string]bool, len(e.Scope.Domains.Exclude))
	out := make([]string, 0, len(e.Scope.Domains.Exclude))
	for _, raw := range e.Scope.Domains.Exclude {
		name := normalizeExclusionDomain(raw)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// ExcludedIPPrefixes returns the canonical (masked) excluded CIDR prefixes. Call
// only after Validate has succeeded, which guarantees each entry parses and is
// canonical. An unparseable entry is skipped rather than panicking, so a caller that
// ignores the Validate contract would fail open (fewer exclusions), so production
// callers must honor Validate before using this accessor.
func (e *EngagementConfig) ExcludedIPPrefixes() []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(e.Scope.IPRanges.Exclude))
	out := make([]netip.Prefix, 0, len(e.Scope.IPRanges.Exclude))
	for _, raw := range e.Scope.IPRanges.Exclude {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		canonical := p.Masked()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	return out
}

// normalizeExclusionDomain lowercases and strips surrounding whitespace and a
// trailing dot, matching the exact-name-plus-subdomains comparison used at admission
// and dial time. It performs no validity check; use validateExclusionDomains for that.
func normalizeExclusionDomain(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// validateExclusionDomains reports one problem per malformed or duplicate domain
// exclusion. A valid entry normalizes to a non-empty DNS name that is not an IP
// literal and carries no scheme, port, path, or illegal character.
func validateExclusionDomains(entries []string) []string {
	var problems []string
	seen := make(map[string]bool, len(entries))
	for i, raw := range entries {
		name := normalizeExclusionDomain(raw)
		if name == "" {
			problems = append(problems, fmt.Sprintf("scope.domains.exclude[%d] must not be empty", i))
			continue
		}
		if _, err := netip.ParseAddr(name); err == nil {
			problems = append(problems, fmt.Sprintf("scope.domains.exclude[%d] %q is an IP literal; put addresses in scope.ip_ranges.exclude", i, raw))
			continue
		}
		if !isPlausibleDNSName(name) {
			problems = append(problems, fmt.Sprintf("scope.domains.exclude[%d] %q is not a valid domain name", i, raw))
			continue
		}
		if seen[name] {
			problems = append(problems, fmt.Sprintf("scope.domains.exclude[%d] %q duplicates an earlier entry (normalized %q)", i, raw, name))
			continue
		}
		seen[name] = true
	}
	return problems
}

// validateExclusionPrefixes reports one problem per malformed, non-canonical, or
// duplicate IP-range exclusion. A valid entry is a CIDR whose host bits are all
// zero (canonical) and whose masked form has not appeared before.
func validateExclusionPrefixes(entries []string) []string {
	var problems []string
	seen := make(map[netip.Prefix]bool, len(entries))
	for i, raw := range entries {
		trimmed := strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(trimmed)
		if err != nil {
			problems = append(problems, fmt.Sprintf("scope.ip_ranges.exclude[%d] %q is not a valid CIDR (use /32 or /128 for a single address): %v", i, raw, err))
			continue
		}
		if p.Masked() != p {
			problems = append(problems, fmt.Sprintf("scope.ip_ranges.exclude[%d] %q has host bits set; write the network address (e.g. %s)", i, raw, p.Masked()))
			continue
		}
		if seen[p] {
			problems = append(problems, fmt.Sprintf("scope.ip_ranges.exclude[%d] %q duplicates an earlier entry", i, raw))
			continue
		}
		seen[p] = true
	}
	return problems
}

// isPlausibleDNSName reports whether a normalized name is a syntactically plausible
// DNS name: at least one dot-separated label, labels of 1-63 characters drawn from
// letters, digits, and hyphens, no leading or trailing hyphen, and no empty label.
// It is a syntax gate, not a registry check.
func isPlausibleDNSName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if l := len(label); l == 0 || l > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			isLetter := r >= 'a' && r <= 'z'
			isDigit := r >= '0' && r <= '9'
			if !isLetter && !isDigit && r != '-' {
				return false
			}
		}
	}
	return true
}
