package facts

import (
	"fmt"
	"sort"
	"strings"
)

// IntegrityViolationKind names one class of structural defect in a folded graph.
type IntegrityViolationKind string

const (
	// IntegrityDuplicateAsset marks two assets sharing one typed identity, which makes
	// the merge non-deterministic and the key ambiguous for every edge pointing at it.
	IntegrityDuplicateAsset IntegrityViolationKind = "duplicate_asset"
	// IntegrityDuplicateRelationship marks two edges sharing one (type, from, to)
	// identity, which means an upsert path bypassed the merge.
	IntegrityDuplicateRelationship IntegrityViolationKind = "duplicate_relationship"
	// IntegrityDanglingRelationship marks an edge whose endpoint names no node. A
	// renderer can only drop such an edge, so the JSON and the HTML would disagree.
	IntegrityDanglingRelationship IntegrityViolationKind = "dangling_relationship"
	// IntegrityIsolatedAsset marks an asset that no drawn asset relationship touches
	// and whose type carries no documented reason to stand alone.
	IntegrityIsolatedAsset IntegrityViolationKind = "isolated_asset"
)

// IntegrityViolation is one structural defect, named precisely enough to act on: which
// node or edge, and what is wrong with it.
type IntegrityViolation struct {
	Kind    IntegrityViolationKind `json:"kind"`
	Subject string                 `json:"subject"`
	Detail  string                 `json:"detail"`
}

// IntegrityReport is the result of validating a folded graph's structure.
//
// ExcludedRelationships is renderer and degree accounting, nothing more. The HTML view
// does not draw the finding edges, so an asset whose only edge is a finding edge is an
// isolated node on screen even though the JSON says it has a degree; counting those edges
// toward connectivity would let a real display defect hide behind a relationship nobody
// can see. Exclusion from drawing is never permission for a dangling reference: a finding
// edge whose endpoint names no node is an ordinary violation, exactly like a dangling
// asset edge, because every producer of a finding constructs the canonical key of the
// asset kind it declares.
type IntegrityReport struct {
	Violations []IntegrityViolation `json:"violations,omitempty"`
	// ExcludedRelationships counts, per type, the edges the renderer does not draw.
	ExcludedRelationships map[RelationshipType]int `json:"excluded_relationships,omitempty"`
	// AllowlistedIsolation counts, per asset type, the isolated assets a documented
	// reason permits. They are legitimate but still worth seeing in one place.
	AllowlistedIsolation map[AssetType]int `json:"allowlisted_isolation,omitempty"`
}

// rendererExcludedRelationships are the edge types whose endpoints are not both assets:
// they wire a finding candidate to the asset it concerns and to the evidence backing it.
// The HTML graph view skips them for that reason, so this one set decides both which
// edges the asset-endpoint check applies to and which edges count toward connectivity.
var rendererExcludedRelationships = map[RelationshipType]bool{
	RelFindingAffectsAsset:        true,
	RelFindingSupportedByEvidence: true,
}

// isolationAllowlist names the asset types that may legitimately have no drawn edge, with
// the reason that makes it legitimate. Anything not listed here is a connectivity defect:
// a fact the graph asserts exists but cannot relate to anything else is not usable by a
// consumer, and it is almost always a normalizer that materialized a node and forgot the
// edge that gave it meaning.
//
// The list is deliberately short and per-type. A blanket allowance would have let the
// endpoint, DNS-record, and host-technology orphans pass unnoticed.
var isolationAllowlist = map[AssetType]string{
	AssetDomain: "a name enumeration or registration source can report a name and nothing " +
		"else about it, and a root that never resolved still belongs in the graph",
	AssetSubdomain: "same as Domain: an enumeration hit is a real discovery even when no " +
		"record, certificate, or probe ever attached anything to it",
	AssetExternalDomain: "an out-of-scope name can be mentioned by a source whose other " +
		"claims about it were all rejected as out of scope",
	AssetTechnology: "a fingerprint can arrive with neither a URL nor a service to attach " +
		"it to, and the product was still genuinely observed",
	AssetCertificate: "a certificate can cover only wildcard names, which are zone " +
		"directives rather than assets, so there is no concrete name to link it to",
}

// Integrity validates the folded graph's structure. It is pure: it reads the rendered
// snapshot and allocates nothing on the graph, so tests and report generation see exactly
// the same verdict about exactly the same bytes.
func (g *Graph) Integrity() IntegrityReport { return integrity(g.snap()) }

// integrity is the snapshot-level validator behind [Graph.Integrity].
func integrity(s snapshot) IntegrityReport {
	rep := IntegrityReport{
		ExcludedRelationships: map[RelationshipType]int{},
		AllowlistedIsolation:  map[AssetType]int{},
	}

	assetKeys := make(map[string]struct{}, len(s.Assets))
	seenAssets := make(map[string]struct{}, len(s.Assets))
	for _, a := range s.Assets {
		id := string(a.Type) + "\x00" + a.Key
		if _, dup := seenAssets[id]; dup {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind:    IntegrityDuplicateAsset,
				Subject: assetSubject(a.Type, a.Key),
				Detail:  "two assets share one typed identity; the asset index must merge them",
			})
			continue
		}
		seenAssets[id] = struct{}{}
		assetKeys[a.Key] = struct{}{}
	}

	findingIDs := make(map[string]struct{}, len(s.FindingCandidates))
	for _, c := range s.FindingCandidates {
		findingIDs[c.ID] = struct{}{}
	}
	evidenceIDs := make(map[string]struct{}, len(s.Evidence))
	for _, e := range s.Evidence {
		evidenceIDs[e.ID] = struct{}{}
	}

	degree := make(map[string]int, len(assetKeys))
	seenRels := make(map[string]struct{}, len(s.Relationships))
	for _, r := range s.Relationships {
		id := string(r.Type) + "\x00" + r.From + "\x00" + r.To
		if _, dup := seenRels[id]; dup {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind:    IntegrityDuplicateRelationship,
				Subject: relSubject(r),
				Detail:  "two relationships share one identity; the relationship index must merge them",
			})
			continue
		}
		seenRels[id] = struct{}{}

		if rendererExcludedRelationships[r.Type] {
			// Counted for the renderer, validated like any other edge: not drawn is not
			// the same as not required to resolve.
			rep.ExcludedRelationships[r.Type]++
			rep.Violations = append(rep.Violations,
				findingEdgeViolations(r, findingIDs, evidenceIDs, assetKeys)...)
			continue
		}
		_, fromOK := assetKeys[r.From]
		_, toOK := assetKeys[r.To]
		if !fromOK {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind:    IntegrityDanglingRelationship,
				Subject: relSubject(r),
				Detail:  fmt.Sprintf("no asset has key %q, so the edge cannot be drawn from it", r.From),
			})
		}
		if !toOK {
			rep.Violations = append(rep.Violations, IntegrityViolation{
				Kind:    IntegrityDanglingRelationship,
				Subject: relSubject(r),
				Detail:  fmt.Sprintf("no asset has key %q, so the edge cannot be drawn to it", r.To),
			})
		}
		if fromOK && toOK {
			degree[r.From]++
			degree[r.To]++
		}
	}

	for _, a := range s.Assets {
		if degree[a.Key] > 0 {
			continue
		}
		if _, allowed := isolationAllowlist[a.Type]; allowed {
			rep.AllowlistedIsolation[a.Type]++
			continue
		}
		rep.Violations = append(rep.Violations, IntegrityViolation{
			Kind:    IntegrityIsolatedAsset,
			Subject: assetSubject(a.Type, a.Key),
			Detail: fmt.Sprintf("no drawn asset relationship touches it and %s is not allowlisted "+
				"for isolation; the normalizer that created it must also create the edge that "+
				"gives it meaning", a.Type),
		})
	}

	sortViolations(rep.Violations)
	return rep
}

// sortViolations orders a violation list deterministically, so the same graph always
// produces the same error text.
func sortViolations(vs []IntegrityViolation) {
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Kind != vs[j].Kind {
			return vs[i].Kind < vs[j].Kind
		}
		return vs[i].Subject < vs[j].Subject
	})
}

// findingEdgeViolations checks the two renderer-excluded edge types against the node sets
// they actually point into: a candidate id on the from side, and an asset key or an
// evidence id on the to side. Its defects are ordinary violations, so a finding that names
// an asset the graph does not hold stops report generation instead of shipping a graph
// with an unreachable weakness in it.
func findingEdgeViolations(r Relationship, findingIDs, evidenceIDs, assetKeys map[string]struct{}) []IntegrityViolation {
	var out []IntegrityViolation
	if _, ok := findingIDs[r.From]; !ok {
		out = append(out, IntegrityViolation{Kind: IntegrityDanglingRelationship, Subject: relSubject(r),
			Detail: fmt.Sprintf("no finding candidate has id %q", r.From)})
	}
	// Only the two renderer-excluded types reach here; the caller filters on the same set.
	if r.Type == RelFindingAffectsAsset {
		if _, ok := assetKeys[r.To]; !ok {
			out = append(out, IntegrityViolation{Kind: IntegrityDanglingRelationship, Subject: relSubject(r),
				Detail: fmt.Sprintf("no asset has key %q", r.To)})
		}
		return out
	}
	if _, ok := evidenceIDs[r.To]; !ok {
		out = append(out, IntegrityViolation{Kind: IntegrityDanglingRelationship, Subject: relSubject(r),
			Detail: fmt.Sprintf("no evidence has id %q", r.To)})
	}
	return out
}

// Err returns a single actionable error describing every violation, or nil for a sound
// graph. Report generation calls it so a structurally broken graph fails loudly at write
// time instead of silently rendering an HTML view that disagrees with its own JSON.
func (rep IntegrityReport) Err() error {
	if len(rep.Violations) == 0 {
		return nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "facts graph integrity: %d violation(s)", len(rep.Violations))
	const shown = 20
	for i, v := range rep.Violations {
		if i == shown {
			fmt.Fprintf(&sb, "\n  ... and %d more", len(rep.Violations)-shown)
			break
		}
		fmt.Fprintf(&sb, "\n  %s %s: %s", v.Kind, v.Subject, v.Detail)
	}
	return fmt.Errorf("%s", sb.String())
}

// assetSubject and relSubject render a node or edge identity in one readable form, so an
// error message names the exact thing to look at.
func assetSubject(t AssetType, key string) string { return string(t) + " " + key }

func relSubject(r Relationship) string {
	return fmt.Sprintf("%s %s -> %s", r.Type, r.From, r.To)
}
