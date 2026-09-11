package netaudit

import (
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// matchDomain reports whether name is excluded by one of rules, using the exact
// runtime semantics: exact name or a subdomain of it, never substring or glob. It
// returns the matched rule for audit.
func matchDomain(name string, rules []string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" {
		return "", false
	}
	for _, r := range rules {
		if n == r || strings.HasSuffix(n, "."+r) {
			return r, true
		}
	}
	return "", false
}

// addrInPrefix reports whether the target string parses to an address contained in
// prefix. A non-address target (a hostname) never matches a CIDR rule here.
func addrInPrefix(target string, prefix netip.Prefix) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		return false
	}
	return prefix.Contains(addr.Unmap())
}

// excludedEndpoint returns the endpoint of a flow that falls in the excluded
// prefix, when either does. Both endpoints are checked because the capture is the
// scanner host's own traffic and the excluded target may be on either side.
func excludedEndpoint(f flow, prefix netip.Prefix) (netip.Addr, bool) {
	if prefix.Contains(f.a.Unmap()) {
		return f.a.Unmap(), true
	}
	if prefix.Contains(f.b.Unmap()) {
		return f.b.Unmap(), true
	}
	return netip.Addr{}, false
}

// sharedExcludedNames returns the excluded names that resolved to an address in the
// flow, for the given rule. It is the DNS-correlation path for a possible domain
// violation without SNI/Host proof.
func sharedExcludedNames(f flow, dnsExcluded map[netip.Addr][]string, rule string) []string {
	var out []string
	for _, addr := range []netip.Addr{f.a.Unmap(), f.b.Unmap()} {
		for _, name := range dnsExcluded[addr] {
			if name == rule {
				out = appendUnique(out, name)
			}
		}
	}
	return out
}

// correlatedActive reports whether an active or exploit tool span overlaps a flow's
// time window and names one of its endpoints, so an ambiguous shared-IP conversation
// can be tied to a deliberate active attempt.
func correlatedActive(f flow, spans []ToolSpan) bool {
	for _, s := range spans {
		if s.Rejected || !isActivePhase(s.Phase) {
			continue
		}
		if s.At.Before(f.first.Add(-spanSlack)) || s.At.After(f.last.Add(spanSlack)) {
			continue
		}
		if spanTargetsEndpoint(s.Target, f) {
			return true
		}
	}
	return false
}

// spanTargetsEndpoint reports whether a tool span's target names one of the flow's
// endpoints (by IP literal).
func spanTargetsEndpoint(target string, f flow) bool {
	host := target
	if h, err := scopecheck.NormalizeHost(target); err == nil {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		a := addr.Unmap()
		return a == f.a.Unmap() || a == f.b.Unmap()
	}
	return false
}

// spanAttribution returns the tool name whose active span best matches the flow,
// for violation attribution when packet-level process identity is unavailable.
func spanAttribution(f flow, spans []ToolSpan) string {
	for _, s := range spans {
		if s.Rejected || !isActivePhase(s.Phase) {
			continue
		}
		if s.At.Before(f.first.Add(-spanSlack)) || s.At.After(f.last.Add(spanSlack)) {
			continue
		}
		if spanTargetsEndpoint(s.Target, f) {
			return "tool:" + s.Tool
		}
	}
	return ""
}

// spanSlack is how far outside a flow's observed window a correlated tool span may
// sit and still be considered the same attempt, absorbing capture/clock skew.
const spanSlack = 5 * 1_000_000_000 // 5s in nanoseconds (time.Duration)

func isActivePhase(phase string) bool {
	return phase == "active" || phase == "exploit"
}

func countIssues(issues []ExclusionIssue, match func(target string) bool) int {
	n := 0
	for _, i := range issues {
		if match(i.Target) {
			n++
		}
	}
	return n
}

// countRejections counts the typed rejection spans whose denied destination is
// covered by a rule. A rejection is matched on the destinations derived from its
// own event attributes, not on the invocation target the envelope carries: the
// latter is the correlation target of the whole call (normally the root domain)
// and almost never the destination the policy denied.
func countRejections(spans []ToolSpan, match func(target string) bool) int {
	n := 0
	for _, s := range spans {
		if !s.Rejected {
			continue
		}
		for _, d := range rejectionTargets(s) {
			if match(d) {
				n++
				break
			}
		}
	}
	return n
}

// rejectionTargets returns the destinations a rejection span is matched on: its
// derived destinations, or the invocation target when the event carried none.
func rejectionTargets(s ToolSpan) []string {
	if len(s.Destinations) > 0 {
		return s.Destinations
	}
	if s.Target != "" {
		return []string{s.Target}
	}
	return nil
}

// domainViolation builds a Violation row for a domain rule from a flow.
func domainViolation(rule string, f flow, destination string, verdict Verdict, spans []ToolSpan) Violation {
	v := Violation{
		Rule:        rule,
		Kind:        RuleDomain,
		Verdict:     verdict,
		Destination: destination,
		Protocol:    f.protocol,
		Port:        remotePort(f),
		Attribution: attribution(f, spans),
		First:       f.first,
		Last:        f.last,
		Packets:     f.packets,
		Confidence:  confidence(verdict),
	}
	return v
}

// cidrViolation builds a Violation row for a CIDR rule from a flow.
func cidrViolation(rule netip.Prefix, f flow, peer netip.Addr, spans []ToolSpan) Violation {
	return Violation{
		Rule:        rule.String(),
		Kind:        RuleCIDR,
		Verdict:     VerdictViolationConfirmed,
		Destination: peer.String(),
		Protocol:    f.protocol,
		Port:        remotePort(f),
		Attribution: attribution(f, spans),
		First:       f.first,
		Last:        f.last,
		Packets:     f.packets,
		Confidence:  confidence(VerdictViolationConfirmed),
	}
}

// remotePort returns the non-ephemeral endpoint port of a flow when it is
// identifiable (the lower well-known port), else the b-side port.
func remotePort(f flow) int {
	if f.portA == 0 && f.portB == 0 {
		return 0
	}
	if f.portA != 0 && (f.portB == 0 || f.portA < f.portB) {
		return f.portA
	}
	return f.portB
}

func attribution(f flow, spans []ToolSpan) string {
	if f.process != "" {
		return "proc:" + f.process
	}
	return spanAttribution(f, spans)
}

func confidence(v Verdict) string {
	if v == VerdictViolationConfirmed {
		return "confirmed"
	}
	return "possible"
}

func appendUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// sortViolations orders violations most severe first (confirmed before possible),
// then by rule, destination, and first-seen time, for stable rendering.
func sortViolations(v []Violation) {
	sort.SliceStable(v, func(i, j int) bool {
		if v[i].Verdict != v[j].Verdict {
			return v[i].Verdict == VerdictViolationConfirmed
		}
		if v[i].Rule != v[j].Rule {
			return v[i].Rule < v[j].Rule
		}
		if v[i].Destination != v[j].Destination {
			return v[i].Destination < v[j].Destination
		}
		return v[i].First.Before(v[j].First)
	})
}
