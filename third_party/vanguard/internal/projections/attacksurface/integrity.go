package attacksurface

import (
	"fmt"
	"sort"
	"strings"
)

// maxReportedViolations bounds the generation error. A contraction that breaks
// structurally usually breaks for one reason, and printing every consequence of it buries
// the first line that says what to fix.
const maxReportedViolations = 20

// isolationAllowed names the node types that may legitimately stand alone, with the
// reason. Everything else with no edge is a defect: a contracted node that relates to
// nothing is not attack surface a person can reason about, and it almost always means a
// contraction rule dropped the edge that gave the node meaning.
//
// Only names qualify. An enumeration source can report a name and never establish another
// thing about it, and a name that resolves to nothing is still part of the picture. An
// address with no name, service, or surface, a service on no address, and a web origin no
// host serves are each an error in this package rather than a fact about the target.
var isolationAllowed = map[NodeType]string{
	NodeDomain: "a name enumeration or registration source can report a name and nothing else " +
		"about it, and a name that never resolved still belongs on the surface",
}

// validate checks the contracted graph's structure. It runs over the rendered nodes and
// edges rather than the builder's indexes, so it judges exactly the bytes a consumer will
// read, and it is the same check tests and report generation use.
func (b *builder) validate(g *Graph) IntegrityReport {
	rep := IntegrityReport{Violations: append([]IntegrityViolation(nil), b.violations...)}

	all := g.AllNodes()
	ids := make(map[string]struct{}, len(all))
	for _, n := range all {
		if _, dup := ids[n.ID]; dup {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind: ViolationDuplicateNode, Subject: n.ID,
				Detail: "two nodes share one typed id; every edge pointing at it is ambiguous",
			})
			continue
		}
		ids[n.ID] = struct{}{}
	}

	degree := make(map[string]int, len(all))
	seenEdges := make(map[string]struct{}, len(g.Edges))
	for _, e := range g.Edges {
		k := string(e.Type) + "\x00" + e.From + "\x00" + e.To
		if _, dup := seenEdges[k]; dup {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind: ViolationDuplicateEdge, Subject: edgeSubject(e),
				Detail: "two edges share one identity after contraction; the merge policy did not run",
			})
			continue
		}
		seenEdges[k] = struct{}{}
		missing := make([]string, 0, 2)
		if _, ok := ids[e.From]; !ok {
			missing = append(missing, e.From)
		}
		if _, ok := ids[e.To]; !ok {
			missing = append(missing, e.To)
		}
		if len(missing) > 0 {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind: ViolationDanglingEdge, Subject: edgeSubject(e),
				Detail: "no node has id " + strings.Join(missing, " or "),
			})
			continue
		}
		degree[e.From]++
		degree[e.To]++
	}

	isolated := map[NodeType]int{}
	for _, n := range all {
		if degree[n.ID] > 0 {
			continue
		}
		if _, allowed := isolationAllowed[n.Type]; allowed {
			isolated[n.Type]++
			continue
		}
		rep.Violations = append(rep.Violations, IntegrityViolation{
			Kind: ViolationIsolatedNode, Subject: n.ID,
			Detail: "no contracted edge touches this node, and its type has no documented reason to stand alone",
		})
	}
	for t, count := range isolated {
		rep.IsolatedByDesign = append(rep.IsolatedByDesign, TypeCount{Type: string(t), Count: count})
	}
	sort.Slice(rep.IsolatedByDesign, func(i, j int) bool {
		return rep.IsolatedByDesign[i].Type < rep.IsolatedByDesign[j].Type
	})

	if total := g.ContractionSummary.FindingsAttached + g.ContractionSummary.FindingsUnmapped; total != g.ContractionSummary.FindingsTotal {
		rep.Violations = append(rep.Violations, IntegrityViolation{
			Kind:    ViolationLostFinding,
			Subject: fmt.Sprintf("%d of %d findings accounted for", total, g.ContractionSummary.FindingsTotal),
			Detail:  "every finding must either attach to a node or appear in unmapped_findings",
		})
	}

	rep.Violations = append(rep.Violations, b.uncontractedAssets()...)
	sortViolations(rep.Violations)
	if rep.Violations == nil {
		rep.Violations = []IntegrityViolation{}
	}
	return rep
}

// uncontractedAssets reports the facts assets that had a relationship to fold through and
// still landed nowhere. The relationship test is what makes the check precise: an asset
// the facts graph itself documents as legitimately isolated - a technology with no URL to
// attach it to, a certificate covering only wildcard names - has nothing to contract
// through and is not evidence of a bug here.
func (b *builder) uncontractedAssets() []IntegrityViolation {
	connected := b.factsConnected()
	var out []IntegrityViolation
	for _, a := range b.v.Assets {
		k := typedKey(a.Type, a.Key)
		if b.folded[k] || b.nodeOf[k] != "" || !connected[a.Key] {
			continue
		}
		out = append(out, IntegrityViolation{
			Kind: ViolationUncontractedAsset, Subject: string(a.Type) + " " + a.Key,
			Detail: "the facts graph joined this asset to something, but the contraction attached it to no node",
		})
	}
	return out
}

// sortViolations orders the report so the same graph always produces the same text.
func sortViolations(vs []IntegrityViolation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Kind != vs[j].Kind {
			return vs[i].Kind < vs[j].Kind
		}
		if vs[i].Subject != vs[j].Subject {
			return vs[i].Subject < vs[j].Subject
		}
		return vs[i].Detail < vs[j].Detail
	})
}

// edgeSubject names an edge the way a person would look for it.
func edgeSubject(e Edge) string { return string(e.Type) + " " + e.From + " -> " + e.To }

// Err returns an error naming the structural defects, or nil when the graph is sound. A
// writer calls it before creating any file: an artifact whose edges do not resolve renders
// as a picture that disagrees with its own data, and shipping that is worse than failing.
func (g *Graph) Err() error {
	rep := g.Integrity
	if len(rep.Violations) == 0 {
		return nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "attack surface graph has %d violation(s):", len(rep.Violations))
	for i, v := range rep.Violations {
		if i == maxReportedViolations {
			fmt.Fprintf(&sb, "\n  ... and %d more", len(rep.Violations)-maxReportedViolations)
			break
		}
		fmt.Fprintf(&sb, "\n  %s: %s (%s)", v.Kind, v.Subject, v.Detail)
	}
	return fmt.Errorf("%s", sb.String())
}
