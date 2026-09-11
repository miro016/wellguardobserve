package attacksurface

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
)

// JSON renders the contracted graph as indented, deterministically ordered JSON. Every
// collection was sorted when the graph was assembled and every map is rendered in sorted
// key order by the encoder, so the same event stream always produces the same bytes.
func (g *Graph) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal attack surface graph: %w", err)
	}
	return b, nil
}

// Markdown renders the analyst summary: what the surface is, how current it is, what is
// listening, what is on the web, what is wrong with it, and what the contraction did.
//
// It deliberately stops short of the operator report. Full provenance, the timeline, and
// scan-health faults live in the facts and issues artifacts, and duplicating them here
// would produce a second document that drifts from the first.
func (g *Graph) Markdown() string {
	var sb strings.Builder
	sb.WriteString("# Attack surface\n\n")
	if g.ScanID != "" {
		fmt.Fprintf(&sb, "Scan `%s`", g.ScanID)
		if g.RootTarget != "" {
			fmt.Fprintf(&sb, ", root target `%s`", g.RootTarget)
		}
		sb.WriteString(".\n\n")
	}
	asOf := events.AnalysisAsOf{At: g.AnalysisAsOf, Partial: g.AnalysisPartial}
	fmt.Fprintf(&sb, "Temporal scope: %s.\nData view: %s.\n\n", asOf.String(), g.DataView)
	g.writeSourceCollection(&sb)
	fmt.Fprintf(&sb, "- In-scope nodes: %d\n- External nodes: %d (of which %d referenced only, never observed directly)\n"+
		"- Edges: %d\n- Findings: %d attached, %d unmapped\n\n",
		g.ContractionSummary.InScopeNodes, g.ContractionSummary.ExternalNodes, g.referencedOnly(),
		len(g.Edges), g.ContractionSummary.FindingsAttached, g.ContractionSummary.FindingsUnmapped)

	writeTypeTable(&sb, "## Nodes by type", "Node type", g.ContractionSummary.NodesByType)
	writeTypeTable(&sb, "## Edges by type", "Edge type", g.ContractionSummary.EdgesByType)
	g.writeCurrentness(&sb)
	g.writeAddresses(&sb)
	g.writeServices(&sb)
	g.writeWebSurfaces(&sb)
	g.writeFindings(&sb)
	g.writeContraction(&sb)
	g.writeIntegrity(&sb)

	sb.WriteString("## Where the rest lives\n\n")
	sb.WriteString("This file is the contracted analyst view. `facts.json` holds the complete " +
		"graph with every observation, evidence item, and temporal assertion behind the facts " +
		"summarized here, and `../reports/issues.md` holds the scan-health faults, which are " +
		"deliberately kept out of the attack topology.\n\n")
	return sb.String()
}

// writeSourceCollection states the collection outcome before the surface totals, so a
// reader never sizes an estate from a scan that did not finish looking. It is compact
// on purpose: the exact problem rows are in the operator report, and repeating them
// here would make two ledgers of one loss.
func (g *Graph) writeSourceCollection(sb *strings.Builder) {
	s := g.SourceCollection
	if s == nil {
		return
	}
	if !s.Incomplete() {
		fmt.Fprintf(sb, "Source collection: %s, no collection problems.\n\n", s.Status)
		return
	}
	fmt.Fprintf(sb, "> **Source collection %s** with %d collection problem event(s). "+
		"The counts below are what this scan managed to collect, not necessarily what exists. "+
		"See `../reports/report.md` for the exact losses.\n\n",
		s.Status, s.HealthTotal)
}

// referencedOnly counts the nodes that exist only because something else pointed at them.
// They are part of the picture and dishonest to count as discovered surface, so the header
// states them separately rather than folding them into the external total.
func (g *Graph) referencedOnly() int {
	n := 0
	for _, node := range g.AllNodes() {
		if node.ReferencedOnly {
			n++
		}
	}
	return n
}

// writeCurrentness breaks the nodes down by how current the evidence behind them is,
// which is the first thing an analyst has to know before acting on any of it.
func (g *Graph) writeCurrentness(sb *strings.Builder) {
	counts := map[string]int{}
	for _, n := range g.AllNodes() {
		counts[string(n.Primary)]++
	}
	sb.WriteString("## Nodes by currentness\n\n")
	writeCounts(sb, "Currentness", counts)
}

// writeAddresses lists the addresses with the infrastructure attribution and host-level
// products folded onto them. A host-level product is marked as such: a passive source that
// mapped a product to a host and to no port has not said which service runs it, and the
// table must not imply otherwise.
func (g *Graph) writeAddresses(sb *strings.Builder) {
	sb.WriteString("## Addresses\n\n")
	rows := make([]string, 0, 16)
	for _, n := range g.IPAddresses {
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s |",
			n.Key, n.Scope, providerOf(n), strings.Join(technologyKeys(n.Technologies), ", "), n.Primary))
	}
	if len(rows) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	sb.WriteString("| Address | Scope | Provider | Technologies | Currentness |\n|---|---|---|---|---|\n")
	sort.Strings(rows)
	sb.WriteString(strings.Join(rows, "\n"))
	sb.WriteString("\n\n")
}

// providerOf renders an address's infrastructure attribution from its folded facets.
func providerOf(n Node) string {
	// The provider reads first and the prefixes after it. The facets are sorted by kind
	// for the machine view, and that order puts the netblock ahead of the operator that
	// announces it, which is backwards for someone scanning the column.
	var providers, prefixes []string
	for _, f := range n.Facets {
		switch f.Kind {
		case "provider_attribution":
			providers = append(providers, fmt.Sprintf("AS%s %s", scalar(f.Values["asn_number"]), scalar(f.Values["name"])))
		case "netblock":
			prefixes = append(prefixes, scalar(f.Values["prefix"]))
		}
	}
	return strings.Join(append(providers, prefixes...), ", ")
}

// writeServices lists what is listening, grouped by transport so the shape of the exposure
// is visible before any individual port is.
func (g *Graph) writeServices(sb *strings.Builder) {
	sb.WriteString("## Exposed services\n\n")
	exposure := g.exposureConfidence()
	rows := make([]string, 0, 16)
	byTransport := map[string]int{}
	byConfidence := map[string]int{}
	for _, n := range g.Services {
		transport, _ := n.Attributes["transport"].(string)
		byTransport[transport]++
		conf := exposure[n.ID]
		byConfidence[confidenceLabel(conf)]++
		rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |",
			n.Label, scalar(n.Attributes["service"]), confidenceLabel(conf), n.Primary,
			strings.Join(technologyKeys(n.Technologies), ", "), strings.Join(n.Sources, ", ")))
	}
	if len(rows) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	writeCounts(sb, "Transport", byTransport)
	writeCounts(sb, "Exposure confidence", byConfidence)
	sb.WriteString("| Service | Protocol | Confidence | Currentness | Technologies | Sources |\n|---|---|---|---|---|---|\n")
	sort.Strings(rows)
	sb.WriteString(strings.Join(rows, "\n"))
	sb.WriteString("\n\n")
}

// exposureConfidence maps each service node to the strongest confidence any edge that
// exposes it carried. Confidence lives on the relationship rather than on the service,
// because "how sure are we that this port is open" is a property of the claim that found
// it, and two sources may have found the same port with different certainty.
func (g *Graph) exposureConfidence() map[string]facts.Confidence {
	out := make(map[string]facts.Confidence, len(g.Services))
	for _, e := range g.Edges {
		if e.Type != EdgeExposesService {
			continue
		}
		if confidenceRank(e.Confidence) > confidenceRank(out[e.To]) {
			out[e.To] = e.Confidence
		}
	}
	return out
}

// confidenceLabel renders a confidence for a table, naming the absent case rather than
// leaving a blank cell that reads like an oversight.
func confidenceLabel(c facts.Confidence) string {
	if c == "" {
		return "unstated"
	}
	return string(c)
}

// writeWebSurfaces lists the web origins with what was observed on them. Paths are counted
// rather than listed in full: an origin with two hundred paths is one line of summary and
// two hundred lines of noise.
func (g *Graph) writeWebSurfaces(sb *strings.Builder) {
	sb.WriteString("## Web surfaces\n\n")
	rows := make([]string, 0, 16)
	for _, n := range g.WebSurfaces {
		rows = append(rows, fmt.Sprintf("| %s | %s | %d | %s | %s | %s |",
			n.Key, n.Scope, len(n.Paths), summarizePaths(n.Paths),
			strings.Join(technologyKeys(n.Technologies), ", "), n.Primary))
	}
	if len(rows) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	sb.WriteString("| Origin | Scope | Paths | Observed | Technologies | Currentness |\n|---|---|---|---|---|---|\n")
	sort.Strings(rows)
	sb.WriteString(strings.Join(rows, "\n"))
	sb.WriteString("\n\n")
	g.writePaths(sb)
}

// writePaths lists every observed path in full. The origin table above summarizes the
// distinct responses, which answers "what is this origin"; the analyst's next question is
// always which URL answered what, and a summary cannot be un-summarized.
func (g *Graph) writePaths(sb *strings.Builder) {
	rows := make([]string, 0, 32)
	for _, n := range g.WebSurfaces {
		for _, p := range n.Paths {
			status := ""
			if p.StatusCode != 0 {
				status = fmt.Sprintf("%d", p.StatusCode)
			}
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |",
				n.Key, p.Path, status, p.Title, p.Server, p.AuthType))
		}
	}
	if len(rows) == 0 {
		return
	}
	sb.WriteString("### Observed paths\n\n")
	sb.WriteString("| Origin | Path | Status | Title | Server | Auth |\n|---|---|---|---|---|---|\n")
	sort.Strings(rows)
	sb.WriteString(strings.Join(rows, "\n"))
	sb.WriteString("\n\n")
}

// summarizePaths renders the response detail an origin's paths carried without letting one
// arbitrary response speak for the origin: the statuses, servers, and authentication
// surfaces are listed as the distinct sets they are.
func summarizePaths(paths []PathObservation) string {
	statuses, servers, auth := map[string]int{}, map[string]int{}, map[string]int{}
	for _, p := range paths {
		if p.StatusCode != 0 {
			statuses[fmt.Sprintf("%d", p.StatusCode)]++
		}
		if p.Server != "" {
			servers[p.Server]++
		}
		if p.AuthType != "" {
			auth[p.AuthType]++
		}
	}
	parts := make([]string, 0, 3)
	if s := joinCounts(statuses); s != "" {
		parts = append(parts, "status "+s)
	}
	if s := joinCounts(servers); s != "" {
		parts = append(parts, "server "+s)
	}
	if s := joinCounts(auth); s != "" {
		parts = append(parts, "auth "+s)
	}
	return strings.Join(parts, "; ")
}

// writeFindings lists the raised weaknesses by severity and affected node.
func (g *Graph) writeFindings(sb *strings.Builder) {
	sb.WriteString("## Findings\n\n")
	bySeverity := map[string]int{}
	rows := make([]string, 0, 16)
	for _, n := range g.AllNodes() {
		for _, f := range n.Findings {
			bySeverity[f.Severity.String()]++
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |",
				f.Severity, n.ID, f.Rule, f.Title))
		}
	}
	if len(rows) == 0 && len(g.UnmappedFindings) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	writeCounts(sb, "Severity", bySeverity)
	if len(rows) > 0 {
		sb.WriteString("| Severity | Node | Rule | Title |\n|---|---|---|---|\n")
		sort.Strings(rows)
		sb.WriteString(strings.Join(rows, "\n"))
		sb.WriteString("\n\n")
	}
	if len(g.UnmappedFindings) > 0 {
		fmt.Fprintf(sb, "%d finding(s) had no defensible retained target and are listed in "+
			"`unmapped_findings` in the JSON rather than attached to a node:\n\n", len(g.UnmappedFindings))
		for _, f := range g.UnmappedFindings {
			fmt.Fprintf(sb, "- `%s` on facts asset `%s` (%s)\n", f.Rule, f.FactsAssetKey, f.Severity)
		}
		sb.WriteString("\n")
	}
}

// writeContraction states what happened to every facts asset type, so a reader can prove
// that a type missing from the node list was folded rather than lost.
func (g *Graph) writeContraction(sb *strings.Builder) {
	sb.WriteString("## Contraction\n\n")
	fmt.Fprintf(sb, "%d facts relationship(s), %d considered by a contraction rule.\n\n",
		g.ContractionSummary.FactsRelationships, g.ContractionSummary.ContractedRelationships)
	sb.WriteString("| Facts asset type | Outcome | Count | Contracted | Standalone | Rule |\n|---|---|---|---|---|---|\n")
	standalone := 0
	for _, a := range g.ContractionSummary.Assets {
		standalone += a.Standalone
		fmt.Fprintf(sb, "| %s | %s | %d | %d | %d | %s |\n",
			a.AssetType, a.Outcome, a.Count, a.Contracted, a.Standalone, a.Reason)
	}
	sb.WriteString("\n")
	if standalone > 0 {
		fmt.Fprintf(sb, "%d asset(s) are counted as standalone: the facts graph joined them to nothing, "+
			"so there was no relationship to fold them through. A certificate covering only wildcard names "+
			"is the usual case, because a wildcard is a zone directive rather than a name that can carry the "+
			"coverage. They are listed in `facts.json` and are not lost; the count is here so "+
			"`count = contracted + standalone` closes for every type.\n\n", standalone)
	}
	fmt.Fprintf(sb, "Scan health is reported separately: %d issue(s) and %d event type(s) without a "+
		"facts normalizer are recorded in the facts and issues artifacts.\n\n",
		g.ContractionSummary.IssueCount, g.ContractionSummary.UnmappedEventTypes)
}

// writeIntegrity states the structural verdict in the document itself, so a reader never
// has to assume the file is sound.
func (g *Graph) writeIntegrity(sb *strings.Builder) {
	sb.WriteString("## Integrity\n\n")
	if len(g.Integrity.Violations) == 0 {
		sb.WriteString("No structural violations: every node has a unique typed id, every edge " +
			"resolves both endpoints, and every node participates in the graph.\n\n")
	} else {
		fmt.Fprintf(sb, "%d structural violation(s):\n\n", len(g.Integrity.Violations))
		for _, v := range g.Integrity.Violations {
			fmt.Fprintf(sb, "- `%s` %s: %s\n", v.Kind, v.Subject, v.Detail)
		}
		sb.WriteString("\n")
	}
	if len(g.Integrity.IsolatedByDesign) > 0 {
		sb.WriteString("Nodes with no edge, permitted by rule:\n\n")
		for _, c := range g.Integrity.IsolatedByDesign {
			fmt.Fprintf(sb, "- %s: %d (%s)\n", c.Type, c.Count, isolationAllowed[NodeType(c.Type)])
		}
		sb.WriteString("\n")
	}
}

// technologyKeys renders a node's products, marking the ones only seen on the host so the
// weaker attribution is never read as a service fingerprint.
func technologyKeys(techs []Technology) []string {
	out := make([]string, 0, len(techs))
	for _, t := range techs {
		if t.Relation == TechHostObserved {
			out = append(out, t.Key+" (host)")
			continue
		}
		out = append(out, t.Key)
	}
	return out
}

// writeTypeTable writes a heading and a sorted count table.
func writeTypeTable(sb *strings.Builder, heading, header string, counts []TypeCount) {
	sb.WriteString(heading + "\n\n")
	if len(counts) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	fmt.Fprintf(sb, "| %s | Count |\n|---|---|\n", header)
	for _, c := range counts {
		fmt.Fprintf(sb, "| %s | %d |\n", c.Type, c.Count)
	}
	sb.WriteString("\n")
}

// writeCounts writes a sorted count table from a map, with no heading of its own.
func writeCounts(sb *strings.Builder, header string, counts map[string]int) {
	rows := typeCounts(counts)
	if len(rows) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	fmt.Fprintf(sb, "| %s | Count |\n|---|---|\n", header)
	for _, c := range rows {
		fmt.Fprintf(sb, "| %s | %d |\n", c.Type, c.Count)
	}
	sb.WriteString("\n")
}

// joinCounts renders a count map as "value (n), value (n)" in sorted order.
func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s (%d)", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// scalar renders an attribute value for a table cell.
func scalar(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
