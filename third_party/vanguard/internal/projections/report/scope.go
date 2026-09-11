package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections"
)

// ScopeAccounting is the deterministic scope ledger for one scan. Every count is a
// pure function of the folded inventory and issue stream, never a runtime counter,
// so a replay of the same events reproduces it exactly. None of the counts infers
// "in scope" from a hostname suffix: they reuse the recorded scope/budget decisions
// (the events.IssueClass* control-plane classes) and the inventory's own
// referenced-only marks.
type ScopeAccounting struct {
	// DiscoveredNames is every domain node in the inventory, including the
	// referenced-only redirect destinations counted under ExternalReferencedNames.
	DiscoveredNames int
	// InScopeNames is the domain nodes established by evidence beyond a redirect
	// reference that were not skipped at scheduling scope.
	InScopeNames int
	// ExternalReferencedNames is the domain and IP nodes known only from a redirect
	// Location and never contacted.
	ExternalReferencedNames int
	// ActiveTargetsApproved is the distinct domain/IP targets admitted by the
	// active scheduler over the whole collection.
	ActiveTargetsApproved int
	// ScheduledScopeSkips is the distinct names withheld from the passive/active
	// fan-out by the scheduling scope gate (events.IssueClassScopeSchedule).
	ScheduledScopeSkips int
	// RedirectPairsFollowed is the distinct (source host, destination host) pairs
	// whose redirect policy allowed the hop.
	RedirectPairsFollowed int
	// RedirectPairsRejected is the distinct (source host, destination host) pairs
	// whose redirect policy rejected the destination before any request.
	RedirectPairsRejected int
	// ProviderHostsApproved and ProviderHostsSkipped are the provider-only hosts the
	// ownership policy admitted to, or withheld from, active probing
	// (events.IssueClassProviderApproved / IssueClassProviderSkipped).
	ProviderHostsApproved int
	ProviderHostsSkipped  int
	// BudgetCapsReached is the number of budget exclusion events (one per capped
	// tool or stage). The event stream records a cap hit, not a per-target verdict,
	// so this is the truthful budget count the events permit; it is not a count of
	// individual rejected targets.
	BudgetCapsReached int
	// ActiveTargetsExcluded is the distinct active targets denied by a hard
	// engagement exclusion (events.IssueClassExclusion), counted once per (target
	// kind, normalized target, matched rule). These targets never entered active
	// approval; the count is disjoint from ScheduledScopeSkips.
	ActiveTargetsExcluded int
}

// RedirectEdge is one normalized third-party redirect adjacency, summarizing every
// observation of the same (source URL, destination URL, disposition) triple
// without discarding provenance: the contributing tools and the distinct policy
// reasons are unioned across observations. The complete per-event evidence stays in
// the facts graph and the inventory endpoint adjacencies.
type RedirectEdge struct {
	// FromURL is the normalized endpoint that returned the redirect.
	FromURL string
	// ToURL is the normalized redirect destination.
	ToURL string
	// FromHost is the normalized host of the endpoint that returned the redirect.
	FromHost string
	// ToHost is the normalized destination host.
	ToHost string
	// Disposition is "followed" or "rejected".
	Disposition events.HttpRedirectDisposition
	// Reason is the deduplicated, sorted policy reason(s) for a rejected edge, empty
	// when followed.
	Reason string
	// Sources are the contributing tools, deduplicated and sorted.
	Sources []string
	// Observations is how many redirect events corroborated this edge.
	Observations int
}

// buildScopeAccounting derives the scope ledger and the third-party redirect view
// from the projection. The report's control-decision issue slices (ScopeExclusions,
// BudgetExclusions) are already populated on r; this reads the inventory and the
// full issue stream for the remaining deterministic counts.
func buildScopeAccounting(p *projections.Projection, r *Report) {
	acc := ScopeAccounting{}
	approved := make(map[string]struct{})
	for i := range p.ActiveApprovals {
		a := p.ActiveApprovals[i]
		approved[string(a.Kind)+"\x00"+a.Target] = struct{}{}
	}
	acc.ActiveTargetsApproved = len(approved)

	skipped := make(map[string]struct{})
	for i := range p.Issues {
		iss := p.Issues[i]
		switch iss.Class {
		case events.IssueClassScopeSchedule:
			skipped[iss.Query] = struct{}{}
		case events.IssueClassProviderApproved:
			acc.ProviderHostsApproved++
		case events.IssueClassProviderSkipped:
			acc.ProviderHostsSkipped++
		case events.IssueClassBudget:
			acc.BudgetCapsReached++
		case events.IssueClassExclusion:
			acc.ActiveTargetsExcluded++
		}
	}
	acc.ScheduledScopeSkips = len(skipped)

	acc.DiscoveredNames = len(p.Inventory.Domains)
	for _, node := range p.Inventory.Domains {
		switch {
		case node.ReferencedOnly:
			acc.ExternalReferencedNames++
		default:
			if _, ok := skipped[node.Name]; !ok {
				acc.InScopeNames++
			}
		}
	}
	for _, node := range p.Inventory.IPs {
		if node.ReferencedOnly {
			acc.ExternalReferencedNames++
		}
	}

	edges := collectRedirectEdges(p)
	pairs := make(map[string]struct{})
	for i := range edges {
		pair := edges[i].FromHost + "\x00" + edges[i].ToHost + "\x00" + string(edges[i].Disposition)
		if _, seen := pairs[pair]; seen {
			continue
		}
		pairs[pair] = struct{}{}
		if edges[i].Disposition == events.HttpRedirectRejected {
			acc.RedirectPairsRejected++
		} else {
			acc.RedirectPairsFollowed++
		}
	}

	r.ScopeAccounting = &acc
	r.ThirdPartyRedirects = edges
}

// collectRedirectEdges folds every endpoint redirect adjacency into one row per
// (from URL, to URL, disposition), unioning contributing sources and reasons and
// counting corroborating observations. Rows are sorted for deterministic output:
// rejected before followed, then by source host, destination host.
func collectRedirectEdges(p *projections.Projection) []RedirectEdge {
	type key struct {
		from, to string
		disp     events.HttpRedirectDisposition
	}
	agg := make(map[key]*RedirectEdge)
	srcSets := make(map[key]map[string]struct{})
	reasonSets := make(map[key]map[string]struct{})

	for _, ep := range p.Inventory.Endpoints {
		for i := range ep.Redirects {
			red := ep.Redirects[i]
			k := key{from: red.FromURL, to: red.ToURL, disp: red.Disposition}
			edge := agg[k]
			if edge == nil {
				edge = &RedirectEdge{
					FromURL: red.FromURL, ToURL: red.ToURL,
					FromHost: red.FromHost, ToHost: red.ToHost,
					Disposition: red.Disposition,
				}
				agg[k] = edge
				srcSets[k] = make(map[string]struct{})
				reasonSets[k] = make(map[string]struct{})
			}
			edge.Observations++
			if red.Source != "" {
				srcSets[k][red.Source] = struct{}{}
			}
			if red.Reason != "" {
				reasonSets[k][red.Reason] = struct{}{}
			}
		}
	}

	edges := make([]RedirectEdge, 0, len(agg))
	for k, edge := range agg {
		edge.Sources = sortedKeys(srcSets[k])
		edge.Reason = strings.Join(sortedKeys(reasonSets[k]), "; ")
		edges = append(edges, *edge)
	}
	sort.Slice(edges, func(i, j int) bool {
		// Rejected edges are the operator's priority, so they sort first.
		if edges[i].Disposition != edges[j].Disposition {
			return edges[i].Disposition == events.HttpRedirectRejected
		}
		if edges[i].FromURL != edges[j].FromURL {
			return edges[i].FromURL < edges[j].FromURL
		}
		return edges[i].ToURL < edges[j].ToURL
	})
	return edges
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeScopeAccounting prints the deterministic scope ledger as a compact table. It
// is written inside the Scope & Budget section, before the exclusion lists.
func (r Report) writeScopeAccounting(sb *strings.Builder) {
	if r.ScopeAccounting == nil {
		return
	}
	a := r.ScopeAccounting
	sb.WriteString("**Scope accounting** (derived from events and inventory, not runtime counters):\n\n")
	sb.WriteString("| Measure | Count |\n|---|---|\n")
	fmt.Fprintf(sb, "| Discovered names | %d |\n", a.DiscoveredNames)
	fmt.Fprintf(sb, "| In-scope names | %d |\n", a.InScopeNames)
	fmt.Fprintf(sb, "| External/referenced names | %d |\n", a.ExternalReferencedNames)
	fmt.Fprintf(sb, "| Active targets approved | %d |\n", a.ActiveTargetsApproved)
	fmt.Fprintf(sb, "| Names skipped at scheduling scope | %d |\n", a.ScheduledScopeSkips)
	fmt.Fprintf(sb, "| Redirect host pairs followed | %d |\n", a.RedirectPairsFollowed)
	fmt.Fprintf(sb, "| Redirect host pairs rejected | %d |\n", a.RedirectPairsRejected)
	fmt.Fprintf(sb, "| Provider-only hosts approved | %d |\n", a.ProviderHostsApproved)
	fmt.Fprintf(sb, "| Provider-only hosts skipped | %d |\n", a.ProviderHostsSkipped)
	fmt.Fprintf(sb, "| Active targets excluded | %d |\n", a.ActiveTargetsExcluded)
	fmt.Fprintf(sb, "| Budget caps reached | %d |\n", a.BudgetCapsReached)
	sb.WriteString("\nExternal/referenced and rejected-redirect destinations were referenced but not contacted.\n\n")
}

// writeThirdPartyRedirects prints the third-party redirect dependency view: one row
// per normalized edge, retaining disposition, rejection reason, and contributing
// tools. A destination listed here is not a live endpoint unless it also appears
// under Web Applications from its own successful response.
func (r Report) writeThirdPartyRedirects(sb *strings.Builder) {
	if len(r.ThirdPartyRedirects) == 0 {
		return
	}
	sb.WriteString("## Third-party redirects\n\n")
	sb.WriteString("Redirect destinations are referenced dependencies. A rejected destination received no request.\n\n")
	sb.WriteString("| Source URL | Destination URL | Disposition | Scope reason | Sources | Observations |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for i := range r.ThirdPartyRedirects {
		e := r.ThirdPartyRedirects[i]
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %d |\n",
			markdownCell(e.FromURL), markdownCell(e.ToURL), markdownCell(string(e.Disposition)),
			markdownCell(e.Reason), markdownCell(strings.Join(e.Sources, ", ")), e.Observations)
	}
	sb.WriteString("\n")
}
