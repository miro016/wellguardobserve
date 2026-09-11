package orchestration

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// Scope decides which discovered names are in scope for the customer, so expensive
// (paid API) and active work is limited to them. Out-of-scope names are still
// discovered and recorded for coverage; they are only skipped by the gated work.
// It generalises the ad-hoc websearch host filter into one predicate used wherever
// the scan fans out.
type Scope struct {
	// Root is the scanned root domain; it and its subdomains are always in scope.
	Root string
	// Include are extra in-scope apex domains the customer owns (suffix match).
	Include []string
	// Exclude are names (and their subdomains) to treat as out of scope, even when
	// they match the root or an include entry (for example third-party CDNs). They
	// are also a hard traffic boundary: an excluded name and its subdomains receive
	// no active, target-facing contact (see Exclusions).
	Exclude []string
	// ExcludeIP are canonical (masked) CIDR prefixes that are a hard traffic
	// boundary: every contained address is denied active contact, even when an
	// in-scope domain resolves to it (see Exclusions).
	ExcludeIP []netip.Prefix
	// DepthCap is the maximum crawl depth that is deeply probed; a negative value
	// means no depth limit. Names beyond it stay discovered but are not probed.
	DepthCap int
}

// Exclusions compiles the domain and IP exclusion lists into the policy-neutral
// matcher every active tool shares. It is the single hard-deny boundary: a matched
// destination is denied active contact regardless of root or include membership,
// prior approval, budget, or any override. An empty Scope yields an empty, non-nil
// set. The compile can only fail on inputs FromConfig already validated, so the
// error path is a fail-closed guard for direct programmatic construction.
func (s Scope) Exclusions() (*scopecheck.Exclusions, error) {
	return scopecheck.NewExclusions(s.Exclude, s.ExcludeIP)
}

// InScope reports whether name at the given crawl depth is in scope, and when it is
// not, a short human-readable reason for the audit trail.
func (s Scope) InScope(name string, depth int) (inScope bool, reason string) {
	n := normalizeName(name)
	for _, e := range s.Exclude {
		if matchesSuffix(n, e) {
			return false, "excluded by scope config"
		}
	}
	matched := matchesSuffix(n, s.Root)
	for _, inc := range s.Include {
		if matched {
			break
		}
		matched = matchesSuffix(n, inc)
	}
	if !matched {
		return false, "out of scope (not under root or include list)"
	}
	if s.DepthCap >= 0 && depth > s.DepthCap {
		return false, fmt.Sprintf("beyond scope depth cap %d", s.DepthCap)
	}
	return true, ""
}

// matchesSuffix reports whether name equals root or is a subdomain of it, both
// normalised. An empty root never matches.
func matchesSuffix(name, root string) bool {
	r := normalizeName(root)
	if r == "" {
		return false
	}
	return name == r || strings.HasSuffix(name, "."+r)
}

// normalizeName lowercases and strips the trailing dot for suffix comparison.
func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// reasonIPNotApproved is the single wording for a destination address that never
// entered the approved-target registry. The request policy and the goscans
// post-hoc web check state it identically, so an operator filtering the stream reads
// one reason rather than two phrasings of it.
const reasonIPNotApproved = "IP address was not approved for active traffic"

// ipOriginDerivedDepth is the DNS discovery depth given to a name that is first
// referenced from an approved IP target, typically by a redirect from a literal-IP
// request to a virtual host. An approved IP carries no DNS discovery depth of its
// own (its approval depth is negative), but the referenced name is one referral edge
// away from the approved active surface, so it is judged at the same depth a name
// referred by the scan root would get. Root, include, and exclude rules still apply:
// only the depth is derived here.
const ipOriginDerivedDepth = 1

// allowRequest implements the shared target-facing request policy. The caller
// supplies a normalized host through scopecheck.Check; this method normalizes again
// so direct programmatic use fails closed rather than relying on that convention.
func (o *Orchestrator) allowRequest(ctx context.Context, host string) (allowed bool, reason string) {
	normalized, err := scopecheck.NormalizeHost(host)
	if err != nil {
		return false, fmt.Sprintf("invalid request host: %v", err)
	}

	// A hard exclusion is checked before the approval registries so an approval
	// already granted cannot re-authorize a destination the engagement excludes. The
	// exclusion list is the boundary; an approval is only ever permission within it.
	if excluded, reason := o.gate.excludedHost(normalized); excluded {
		rejection := scopecheck.Rejection{Host: normalized, Reason: reason}
		if ip, err := netip.ParseAddr(normalized); err == nil {
			rejection.ResolvedIP = ip.Unmap().String()
		}
		scopecheck.ReportRejection(ctx, rejection)
		return false, reason
	}

	if ip, err := netip.ParseAddr(normalized); err == nil {
		if _, approved := o.gate.approvedIP(ip.Unmap().String()); approved {
			return true, ""
		}
		return false, reasonIPNotApproved
	}
	depth, discovered := o.targets.depth(normalized)
	if discovered {
		return o.gate.inScope(normalized, depth)
	}

	origin, hasOrigin := scopecheck.OriginFrom(ctx)
	if !hasOrigin {
		return false, "request host is unknown and no approved origin is available"
	}
	originApproval, approvedOrigin, originIsIP := o.approvedOrigin(origin.Host)
	if !approvedOrigin {
		if originIsIP {
			return false, "request origin IP address was not approved for active traffic"
		}
		return false, "request origin was not approved for active traffic"
	}
	if origin.Depth != originApproval.depth {
		return false, "request origin depth does not match its approval"
	}
	if normalized == origin.Host {
		return o.gate.inScope(normalized, origin.Depth)
	}
	if originIsIP {
		return o.gate.inScope(normalized, ipOriginDerivedDepth)
	}
	if origin.Depth < 0 {
		return false, "request host is unknown and the approved origin has no discovery depth"
	}
	return o.gate.inScope(normalized, origin.Depth+1)
}

// withActiveExclusionAudit projects tool-owned hard-exclusion decisions into the
// active domain issue stream. The tool still owns the network boundary and its typed
// event; this observer gives projections and reports the same exact target and rule.
func (o *Orchestrator) withActiveExclusionAudit(ctx context.Context) context.Context {
	return scopecheck.WithRejectionSink(ctx, func(rejection scopecheck.Rejection) {
		kind := events.ActiveTargetDomain
		target := rejection.Host
		if rejection.ResolvedIP != "" {
			kind = events.ActiveTargetIP
			target = rejection.ResolvedIP
		} else if ip, err := netip.ParseAddr(target); err == nil {
			kind = events.ActiveTargetIP
			target = ip.Unmap().String()
		}
		if target == "" || rejection.Reason == "" {
			return
		}
		o.emitActiveExclusion(ctx, kind, target, rejection.Reason)
	})
}

// approvedOrigin resolves the admission record for a request origin from the
// registry that matches its kind: a canonical IP literal lives in the IP registry,
// a DNS name in the domain registry. Looking an IP origin up as a domain would
// always miss and report an approved source as unapproved.
func (o *Orchestrator) approvedOrigin(host string) (approval targetApproval, approved, isIP bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		approval, approved = o.gate.approvedIP(ip.Unmap().String())
		return approval, approved, true
	}
	approval, approved = o.gate.approvedDomain(host)
	return approval, approved, false
}
