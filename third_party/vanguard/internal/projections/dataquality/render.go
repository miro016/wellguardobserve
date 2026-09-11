package dataquality

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JSON renders the report as indented JSON. It is the machine-readable artifact
// (data-quality.json); every field is exported and deterministically ordered.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal data-quality report: %w", err)
	}
	return b, nil
}

// Markdown renders the analyst-facing report (data-quality.md) with five sections:
// the provider summary, the coverage matrix, the genuine conflicts, the coverage-gap
// scope differences, and the explainable efficiency score.
func (r *Report) Markdown() string {
	var sb strings.Builder
	sb.WriteString("# Provider Data Quality\n\n")

	r.writeProviderSummary(&sb)
	r.writeCoverage(&sb)
	r.writeConflicts(&sb)
	r.writeCoverageGaps(&sb)
	r.writeScores(&sb)

	return sb.String()
}

// writeProviderSummary renders the operational rollup, or a note when the
// tool-event stream was absent.
func (r *Report) writeProviderSummary(sb *strings.Builder) {
	sb.WriteString("## Provider summary (operational)\n\n")
	if !r.Op.Available {
		sb.WriteString("Tool-event stream (tooling.jsonl) not found: operational data unavailable.\n\n")
		return
	}
	sb.WriteString("| Provider | Calls | Failed | Unavailable | Events | Errors | Warns | Rate-limited | Empties | Median latency | Reliability |\n")
	sb.WriteString("|----------|-------|--------|-------------|--------|--------|-------|--------------|---------|----------------|-------------|\n")
	for _, p := range r.Op.sortedOps() {
		fmt.Fprintf(sb, "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s | %s |\n",
			p.Provider, p.Calls, p.FailedCalls, p.Unavailable, p.Events, p.Errors, p.Warns,
			p.RateLimited, p.Empties, p.MedianLatency, reliabilityCell(&p))
	}
	sb.WriteString("\n")
}

// reliabilityCell renders a provider's reliability as a percentage, or "n/a" when
// it is undefined (every correlated call was unavailable - the provider declined
// them all - so scoring it 0% would be misleading).
func reliabilityCell(p *ProviderOps) string {
	v, ok := p.Reliability()
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", v*100)
}

// writeCoverage renders the per-field coverage matrix.
func (r *Report) writeCoverage(sb *strings.Builder) {
	sb.WriteString("## Coverage by field\n\n")
	for _, f := range r.Fields {
		fmt.Fprintf(sb, "### %s (%d %s, %d agree, %d coverage-gap, %d conflict)\n\n",
			f.Field, f.TotalKeys, f.Unit, f.Agreements, len(f.CoverageGaps), len(f.Conflicts))
		if len(f.Providers) == 0 {
			sb.WriteString("No provider reported this field.\n\n")
			continue
		}
		sb.WriteString("| Provider | Keys | Values | Unique keys | Unique values |\n")
		sb.WriteString("|----------|------|--------|-------------|---------------|\n")
		for _, p := range f.Providers {
			fmt.Fprintf(sb, "| %s | %d | %d | %d | %d |\n",
				p.Provider, p.Keys, p.Values, p.UniqueKeys, p.UniqueValues)
		}
		sb.WriteString("\n")
	}
}

// writeConflicts lists the concrete disagreements per field for the analyst.
func (r *Report) writeConflicts(sb *strings.Builder) {
	sb.WriteString("## Conflicts\n\n")
	found := false
	for _, f := range r.Fields {
		if len(f.Conflicts) == 0 {
			continue
		}
		found = true
		fmt.Fprintf(sb, "### %s\n\n", f.Field)
		for _, c := range f.Conflicts {
			fmt.Fprintf(sb, "- **%s**\n", c.Key)
			for _, prov := range sortedConflictProviders(c.Values) {
				fmt.Fprintf(sb, "  - %s: %s\n", prov, strings.Join(c.Values[prov], ", "))
			}
		}
		sb.WriteString("\n")
	}
	if !found {
		sb.WriteString("No conflicts: providers agree wherever they overlap.\n\n")
	}
}

// writeCoverageGaps lists the scope differences per field: keys where the providers'
// value-sets are nested (one saw more than another) rather than contradictory. It is
// kept separate from conflicts so the conflict count is an accuracy signal, not a
// methodology artifact (an 18-port active scan structurally "differs" from a
// full-range passive provider on every extra port it never looked at).
func (r *Report) writeCoverageGaps(sb *strings.Builder) {
	sb.WriteString("## Coverage gaps (scope differences)\n\n")
	found := false
	for _, f := range r.Fields {
		if len(f.CoverageGaps) == 0 {
			continue
		}
		found = true
		fmt.Fprintf(sb, "### %s\n\n", f.Field)
		for _, c := range f.CoverageGaps {
			fmt.Fprintf(sb, "- **%s**\n", c.Key)
			for _, prov := range sortedConflictProviders(c.Values) {
				fmt.Fprintf(sb, "  - %s: %s\n", prov, strings.Join(c.Values[prov], ", "))
			}
		}
		sb.WriteString("\n")
	}
	if !found {
		sb.WriteString("No coverage gaps: where providers overlap, their value-sets match or genuinely conflict.\n\n")
	}
}

// writeScores renders the efficiency score with the weights printed.
func (r *Report) writeScores(sb *strings.Builder) {
	fmt.Fprintf(sb, "## Efficiency score (weights: coverage %.2f, unique %.2f, reliability %.2f)\n\n",
		r.Weights.Coverage, r.Weights.Unique, r.Weights.Reliability)
	if !r.Op.Available {
		sb.WriteString("Reliability term dropped (no tool-event stream); score is content-only.\n\n")
	}
	sb.WriteString("| Provider | Score | Coverage | Unique | Reliability |\n")
	sb.WriteString("|----------|-------|----------|--------|-------------|\n")
	for _, s := range r.Scores {
		fmt.Fprintf(sb, "| %s | %.2f | %.2f | %.2f | %.2f |\n",
			s.Provider, s.Score, s.Coverage, s.Unique, s.Reliability)
	}
	sb.WriteString("\n")
}

// sortedConflictProviders returns the providers of a conflict in deterministic
// order.
func sortedConflictProviders(values map[string][]string) []string {
	provs := make([]string, 0, len(values))
	for p := range values {
		provs = append(provs, p)
	}
	sort.Strings(provs)
	return provs
}
