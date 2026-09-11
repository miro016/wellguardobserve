package scopecheck

import (
	"fmt"
	"net/netip"
	"strings"
)

// Exclusions is a compiled, immutable set of hard traffic-boundary rules that a
// target-facing dial must never cross: a list of out-of-scope domain names, each
// matching itself and every subdomain, and a list of canonical CIDR prefixes, each
// matching every contained address.
//
// It is policy-neutral. scopecheck owns no engagement policy: the caller decides
// which names and prefixes are excluded (the orchestrator derives them from the
// engagement config) and passes them here; Exclusions only normalizes, stores, and
// matches them. A nil *Exclusions excludes nothing, so a standalone tool or a unit
// test may leave it unset and keep its existing behavior.
//
// Domain matching is exact name plus subdomains, never substring, glob, or
// registrable-domain matching. Address matching canonicalizes both sides: a stored
// prefix is masked to its network address, and a queried address is unmapped so an
// IPv4-mapped IPv6 input is treated as its IPv4 address.
type Exclusions struct {
	// domains holds normalized (lowercased, trailing-dot-stripped) exclusion names.
	domains []string
	// prefixes holds canonical (masked) exclusion prefixes.
	prefixes []netip.Prefix
}

// NewExclusions compiles domain names and CIDR prefixes into an Exclusions set. It
// normalizes and de-duplicates both lists, masks each prefix to its network
// address, and rejects an IP literal supplied as a domain (those belong in the
// prefix list). An empty input returns a non-nil, empty set.
func NewExclusions(domains []string, prefixes []netip.Prefix) (*Exclusions, error) {
	seenDomain := make(map[string]bool, len(domains))
	norm := make([]string, 0, len(domains))
	for _, d := range domains {
		name, err := NormalizeHost(d)
		if err != nil {
			return nil, fmt.Errorf("exclusion domain %q: %w", d, err)
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return nil, fmt.Errorf("exclusion domain %q is an IP literal; use an IP-range exclusion", d)
		}
		if seenDomain[name] {
			continue
		}
		seenDomain[name] = true
		norm = append(norm, name)
	}

	seenPrefix := make(map[netip.Prefix]bool, len(prefixes))
	pref := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			return nil, fmt.Errorf("exclusion prefix %q is invalid", p.String())
		}
		canonical := p.Masked()
		if seenPrefix[canonical] {
			continue
		}
		seenPrefix[canonical] = true
		pref = append(pref, canonical)
	}

	return &Exclusions{domains: norm, prefixes: pref}, nil
}

// Empty reports whether the set carries no rules. A nil receiver is empty.
func (e *Exclusions) Empty() bool {
	return e == nil || (len(e.domains) == 0 && len(e.prefixes) == 0)
}

// HostExcluded reports whether host, a DNS name or IP literal, is excluded and, if
// so, a human-readable audit reason. A name is matched against the domain rules; an
// IP literal against the prefixes. It never resolves a name: an excluded IP behind
// an allowed name is caught at dial time by PolicyDialer, not here. A host that
// cannot be normalized is not excluded by this check (the caller's own normalization
// governs whether it is dialed at all).
func (e *Exclusions) HostExcluded(host string) (excluded bool, reason string) {
	if e == nil {
		return false, ""
	}
	name, err := NormalizeHost(host)
	if err != nil {
		return false, ""
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		return e.AddrExcluded(addr)
	}
	if rule, ok := e.matchDomain(name); ok {
		return true, fmt.Sprintf("host %s is excluded by domain rule %s", name, rule)
	}
	return false, ""
}

// AddrExcluded reports whether addr matches an exclusion prefix and, if so, an audit
// reason. The address is unmapped first, so an IPv4-mapped IPv6 input is judged as
// its IPv4 address. An invalid address is not excluded.
func (e *Exclusions) AddrExcluded(addr netip.Addr) (excluded bool, reason string) {
	if e == nil || !addr.IsValid() {
		return false, ""
	}
	a := addr.Unmap()
	for _, p := range e.prefixes {
		if p.Contains(a) {
			return true, fmt.Sprintf("address %s is excluded by CIDR %s", a, p)
		}
	}
	return false, ""
}

// matchDomain returns the matching exclusion rule for a normalized name.
func (e *Exclusions) matchDomain(name string) (string, bool) {
	for _, d := range e.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return d, true
		}
	}
	return "", false
}
