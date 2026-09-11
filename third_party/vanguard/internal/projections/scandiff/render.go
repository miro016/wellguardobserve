package scandiff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// maxListItems caps how many members a single Markdown list shows; the omitted
// remainder is summarized as "+N more". It is a render-only concern - the JSON
// always carries the complete set - so the Markdown stays readable without losing
// data.
const maxListItems = 20

// JSON renders the report as indented JSON. It is the machine-readable artifact and
// the source of truth: every field is exported and deterministically ordered.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal scan-diff report: %w", err)
	}
	return b, nil
}

// Markdown renders the operator-facing summary. Every list is sorted and capped, so
// the output is deterministic and golden-testable.
func (r *Report) Markdown() string {
	var sb strings.Builder
	sb.WriteString("# Scan Diff\n\n")

	r.writeHeader(&sb)
	if r.Environment.Changed {
		sb.WriteString("Environment changed between these runs; interpret finding deltas in light of the tool, corpus, runtime, or configuration changes.\n\n")
	}
	r.writeEnvironment(&sb)
	r.writeSummary(&sb)
	r.writeCoverage(&sb)
	r.writeFindings(&sb)
	r.writeChanges(&sb)
	r.writeAppearedDisappeared(&sb)
	r.writeOperational(&sb)

	return sb.String()
}

// writeEnvironment names every execution-input difference. An unchanged or absent
// environment section stays out of the Markdown to keep the common report compact;
// the full snapshots remain in JSON.
func (r *Report) writeEnvironment(sb *strings.Builder) {
	if len(r.Environment.Changes) == 0 {
		return
	}
	sb.WriteString("## Environment\n\n")
	sb.WriteString("| Field | Baseline | Candidate |\n")
	sb.WriteString("|-------|----------|-----------|\n")
	for _, change := range r.Environment.Changes {
		fmt.Fprintf(sb, "| %s | %s | %s |\n",
			markdownCell(change.Field), markdownCell(orNone(change.Baseline)), markdownCell(orNone(change.Candidate)))
	}
	sb.WriteString("\n")
}

// writeHeader names the two scans and notes a root mismatch.
func (r *Report) writeHeader(sb *strings.Builder) {
	fmt.Fprintf(sb, "- Baseline (A): **%s** (scan `%s`, %d events)\n",
		orNone(r.Baseline.Root), orNone(r.Baseline.ScanID), r.Baseline.Events)
	fmt.Fprintf(sb, "- Candidate (B): **%s** (scan `%s`, %d events)\n",
		orNone(r.Candidate.Root), orNone(r.Candidate.ScanID), r.Candidate.Events)
	if r.Summary.RootsDiffer {
		sb.WriteString("- Note: the two scans have different roots; \"missing\" and \"unexpected\" compare unlike estates.\n")
	}
	sb.WriteString("\n")
}

// writeSummary leads with the findings headline, then the four counts, then the
// per-type table.
func (r *Report) writeSummary(sb *strings.Builder) {
	sb.WriteString("## Summary\n\n")
	fmt.Fprintf(sb, "%s\n\n", r.findingsHeadline())
	fmt.Fprintf(sb, "- Matched: %d\n- Changed: %d\n- Missing: %d\n- Unexpected: %d\n\n",
		r.Summary.Matched, r.Summary.Changed, r.Summary.Missing, r.Summary.Unexpected)

	if r.Issues.A > 0 || r.Issues.B > 0 {
		fmt.Fprintf(sb, "Issues (operational, not diffed): baseline %d, candidate %d.\n\n", r.Issues.A, r.Issues.B)
	}

	if len(r.Summary.ByType) == 0 {
		return
	}
	sb.WriteString("| Type | Matched | Changed | Missing | Unexpected |\n")
	sb.WriteString("|------|---------|---------|---------|------------|\n")
	for _, typ := range sortedKeys(r.Summary.ByType) {
		c := r.Summary.ByType[typ]
		fmt.Fprintf(sb, "| %s | %d | %d | %d | %d |\n", typ, c.Matched, c.Changed, c.Missing, c.Unexpected)
	}
	sb.WriteString("\n")
}

// findingsHeadline renders the findings delta as the one prose line an operator
// reads first.
func (r *Report) findingsHeadline() string {
	adds := severityProse(r.Findings.NewBySeverity)
	resolves := severityProse(r.Findings.ResolvedBySeverity)

	var parts []string
	if adds != "" {
		parts = append(parts, "adds "+adds)
	}
	if resolves != "" {
		parts = append(parts, "resolves "+resolves)
	}
	if n := len(r.Findings.Changed); n > 0 {
		parts = append(parts, fmt.Sprintf("changes %d", n))
	}
	if len(parts) == 0 {
		return "Findings: no new, resolved, or changed findings."
	}
	return "Findings: candidate " + strings.Join(parts, "; ") + "."
}

// writeCoverage renders the per-kind table and the gained/lost members below it.
func (r *Report) writeCoverage(sb *strings.Builder) {
	sb.WriteString("## Coverage\n\n")
	sb.WriteString("| Entity | Baseline | Candidate | Common | Gained | Lost |\n")
	sb.WriteString("|--------|----------|-----------|--------|--------|------|\n")
	for _, c := range r.Coverage {
		fmt.Fprintf(sb, "| %s | %d | %d | %d | %d | %d |\n",
			c.Kind, c.ACount, c.BCount, c.Common, len(c.Added), len(c.Removed))
	}
	sb.WriteString("\n")

	for _, c := range r.Coverage {
		if len(c.Added) == 0 && len(c.Removed) == 0 {
			continue
		}
		fmt.Fprintf(sb, "### %s\n\n", c.Kind)
		if len(c.Added) > 0 {
			fmt.Fprintf(sb, "- gained (%d): %s\n", len(c.Added), capJoin(c.Added))
		}
		if len(c.Removed) > 0 {
			fmt.Fprintf(sb, "- lost (%d): %s\n", len(c.Removed), capJoin(c.Removed))
		}
		sb.WriteString("\n")
	}
}

// writeFindings lists the new, resolved, and changed findings - the operator's
// primary signal - with rule, severity, and asset.
func (r *Report) writeFindings(sb *strings.Builder) {
	sb.WriteString("## Findings\n\n")
	if len(r.Findings.New) == 0 && len(r.Findings.Resolved) == 0 && len(r.Findings.Changed) == 0 {
		sb.WriteString("No finding changes.\n\n")
		return
	}
	writeFindingList(sb, "New", r.Findings.New)
	writeFindingList(sb, "Resolved", r.Findings.Resolved)
	writeFindingList(sb, "Changed", r.Findings.Changed)
}

// writeChanges groups the changed events by type and renders each one's field
// changes, capped per group.
func (r *Report) writeChanges(sb *strings.Builder) {
	sb.WriteString("## Changes\n\n")
	byType := map[string][]EventDiff{}
	types := make([]string, 0)
	for _, d := range r.Events {
		if d.Class != Changed {
			continue
		}
		if _, ok := byType[d.Type]; !ok {
			types = append(types, d.Type)
		}
		byType[d.Type] = append(byType[d.Type], d)
	}
	if len(types) == 0 {
		sb.WriteString("No changed events.\n\n")
		return
	}
	sort.Strings(types)
	for _, typ := range types {
		fmt.Fprintf(sb, "### %s\n\n", typ)
		group := byType[typ]
		shown := group
		extra := 0
		if len(group) > maxListItems {
			shown = group[:maxListItems]
			extra = len(group) - maxListItems
		}
		for _, d := range shown {
			fmt.Fprintf(sb, "- `%s`\n", shortIdentity(d))
			for _, fc := range d.Changes {
				fmt.Fprintf(sb, "  - %s\n", fieldChangeLine(fc))
			}
		}
		if extra > 0 {
			fmt.Fprintf(sb, "- (+%d more)\n", extra)
		}
		sb.WriteString("\n")
	}
}

// writeAppearedDisappeared lists the unexpected (appeared) and missing
// (disappeared) events as compact, capped type+identity lists.
func (r *Report) writeAppearedDisappeared(sb *strings.Builder) {
	appeared := make([]string, 0)
	disappeared := make([]string, 0)
	for _, d := range r.Events {
		switch d.Class {
		case Unexpected:
			appeared = append(appeared, fmt.Sprintf("%s %s", d.Type, shortIdentity(d)))
		case Missing:
			disappeared = append(disappeared, fmt.Sprintf("%s %s", d.Type, shortIdentity(d)))
		case Matched, Changed:
			// Matched is not listed; Changed is rendered by writeChanges.
		}
	}

	sb.WriteString("## Appeared (unexpected in B)\n\n")
	writeCompactList(sb, appeared)
	sb.WriteString("## Disappeared (missing from B)\n\n")
	writeCompactList(sb, disappeared)
}

// writeOperational renders the per-provider operational delta, or a note that the
// tool-event stream was absent.
func (r *Report) writeOperational(sb *strings.Builder) {
	sb.WriteString("## Operational\n\n")
	if !r.Op.Available {
		sb.WriteString("Tool-event stream (tooling.jsonl) not found for one or both scans: operational delta unavailable.\n\n")
		return
	}
	providers := r.Op.sortedProviders()
	if len(providers) == 0 {
		sb.WriteString("No provider activity recorded.\n\n")
		return
	}
	sb.WriteString("| Provider | Calls A->B | Failed A->B | Empties A->B |\n")
	sb.WriteString("|----------|------------|-------------|--------------|\n")
	for _, p := range providers {
		fmt.Fprintf(sb, "| %s | %d->%d | %d->%d | %d->%d |\n",
			p.Provider, p.ACalls, p.BCalls, p.AFailed, p.BFailed, p.AEmpties, p.BEmpties)
	}
	sb.WriteString("\n")
}

// writeFindingList renders a labelled finding list when non-empty.
func writeFindingList(sb *strings.Builder, label string, refs []FindingRef) {
	if len(refs) == 0 {
		return
	}
	fmt.Fprintf(sb, "### %s (%d)\n\n", label, len(refs))
	shown := refs
	extra := 0
	if len(refs) > maxListItems {
		shown = refs[:maxListItems]
		extra = len(refs) - maxListItems
	}
	for _, f := range shown {
		fmt.Fprintf(sb, "- **%s** (%s) on %s %s\n", f.Rule, f.Severity, f.AssetKind, f.AssetID)
	}
	if extra > 0 {
		fmt.Fprintf(sb, "- (+%d more)\n", extra)
	}
	sb.WriteString("\n")
}

// writeCompactList renders a capped bullet list, or a "none" note when empty.
func writeCompactList(sb *strings.Builder, items []string) {
	if len(items) == 0 {
		sb.WriteString("None.\n\n")
		return
	}
	shown := items
	extra := 0
	if len(items) > maxListItems {
		shown = items[:maxListItems]
		extra = len(items) - maxListItems
	}
	for _, it := range shown {
		fmt.Fprintf(sb, "- %s\n", it)
	}
	if extra > 0 {
		fmt.Fprintf(sb, "- (+%d more)\n", extra)
	}
	sb.WriteString("\n")
}

// fieldChangeLine renders one FieldChange: a scalar as "name: a -> b", a set-valued
// field as "name: +added -removed".
func fieldChangeLine(fc FieldChange) string {
	if len(fc.A) <= 1 && len(fc.B) <= 1 {
		return fmt.Sprintf("%s: %s -> %s", fc.Name, firstOrNone(fc.A), firstOrNone(fc.B))
	}
	var parts []string
	if len(fc.Added) > 0 {
		parts = append(parts, "+"+strings.Join(fc.Added, ","))
	}
	if len(fc.Removed) > 0 {
		parts = append(parts, "-"+strings.Join(fc.Removed, ","))
	}
	return fmt.Sprintf("%s: %s", fc.Name, strings.Join(parts, " "))
}

// severityProse renders a by-severity count map as "1 critical, 2 high" in
// descending severity order, empty when the map is empty.
func severityProse(bySev map[string]int) string {
	order := []string{
		SeverityLabelCritical, SeverityLabelHigh, SeverityLabelMedium,
		SeverityLabelLow, SeverityLabelInfo,
	}
	var parts []string
	for _, sev := range order {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	return strings.Join(parts, ", ")
}

// Severity labels used for the headline ordering, matching events.Severity.String().
const (
	SeverityLabelCritical = "critical"
	SeverityLabelHigh     = "high"
	SeverityLabelMedium   = "medium"
	SeverityLabelLow      = "low"
	SeverityLabelInfo     = "info"
)

// shortIdentity drops the "Type|" prefix from an identity, since the type is shown
// as the group header or alongside the identity.
func shortIdentity(d EventDiff) string {
	return strings.TrimPrefix(d.Identity, d.Type+"|")
}

// capJoin joins up to maxListItems items with ", ", noting the omitted remainder.
func capJoin(items []string) string {
	if len(items) <= maxListItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxListItems], ", ") + fmt.Sprintf(" (+%d more)", len(items)-maxListItems)
}

// sortedKeys returns the map keys in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// orNone renders an empty string as "(none)".
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// firstOrNone renders the first element of a value set, or "(none)" when empty.
func firstOrNone(vals []string) string {
	if len(vals) == 0 {
		return "(none)"
	}
	return vals[0]
}

// markdownCell escapes characters that can break a table row.
func markdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
