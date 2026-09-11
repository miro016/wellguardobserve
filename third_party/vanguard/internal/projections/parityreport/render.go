package parityreport

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections/scandiff"
)

// JSON renders the complete deterministic corpus result.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal capture-parity report: %w", err)
	}
	return b, nil
}

// Markdown renders a compact operator summary followed by failed/skipped checks,
// provider gates, environment context, and coverage counts for each scenario.
func (r *Report) Markdown() string {
	var sb strings.Builder
	sb.WriteString("# Capture Parity\n\n")
	fmt.Fprintf(&sb, "- Baseline corpus: `%s`\n", r.BaselineRoot)
	fmt.Fprintf(&sb, "- Candidate corpus: `%s`\n", r.CandidateRoot)
	fmt.Fprintf(&sb, "- Manifest: `%s`\n\n", r.ManifestPath)

	sb.WriteString("## Summary\n\n")
	fmt.Fprintf(&sb, "Scenarios: %d total, %d passed, %d failed, %d inconclusive.\n\n",
		r.Summary.Total, r.Summary.Passed, r.Summary.Failed, r.Summary.Inconclusive)
	sb.WriteString("| Scenario | Status | Matched | Changed | Missing | Unexpected | Environment fields |\n")
	sb.WriteString("|----------|--------|--------:|--------:|--------:|-----------:|-------------------:|\n")
	for _, scenario := range r.Scenarios {
		fmt.Fprintf(&sb, "| %s | %s | %d | %d | %d | %d | %d |\n",
			scenario.Name, scenario.Status, scenario.Diff.Matched, scenario.Diff.Changed,
			scenario.Diff.Missing, scenario.Diff.Unexpected, len(scenario.EnvironmentChanges))
	}
	sb.WriteString("\n")

	for _, scenario := range r.Scenarios {
		fmt.Fprintf(&sb, "## %s\n\n", scenario.Name)
		fmt.Fprintf(&sb, "Status: **%s**\n\n", scenario.Status)
		if len(scenario.Gates) > 0 {
			sb.WriteString("Provider gates:\n\n")
			for _, gate := range scenario.Gates {
				fmt.Fprintf(&sb, "- `%s`: %s\n", gate.Provider, gate.Reason)
			}
			sb.WriteString("\n")
		}

		writeChecks(&sb, scenario.Checks)
		writeCoverage(&sb, scenario.Coverage)
		writeEnvironment(&sb, scenario.EnvironmentChanges)
	}
	return sb.String()
}

// writeChecks renders only failed and skipped assertions; an all-pass scenario gets
// one compact sentence.
func writeChecks(sb *strings.Builder, checks []CheckResult) {
	interesting := make([]CheckResult, 0)
	for _, result := range checks {
		if result.Status != CheckPass {
			interesting = append(interesting, result)
		}
	}
	if len(interesting) == 0 {
		sb.WriteString("Checks: all passed.\n\n")
		return
	}
	sb.WriteString("### Non-passing checks\n\n")
	sb.WriteString("| Check | Status | Detail |\n")
	sb.WriteString("|-------|--------|--------|\n")
	for _, result := range interesting {
		fmt.Fprintf(sb, "| %s | %s | %s |\n", cell(result.Name), result.Status, cell(result.Detail))
	}
	sb.WriteString("\n")
}

// writeCoverage renders per-kind counts without duplicating potentially long keys.
func writeCoverage(sb *strings.Builder, coverage []scandiff.CoverageDelta) {
	if len(coverage) == 0 {
		return
	}
	sb.WriteString("### Coverage\n\n")
	sb.WriteString("| Entity | Baseline | Candidate | Common | Gained | Lost |\n")
	sb.WriteString("|--------|---------:|----------:|-------:|-------:|-----:|\n")
	for _, item := range coverage {
		fmt.Fprintf(sb, "| %s | %d | %d | %d | %d | %d |\n",
			item.Kind, item.ACount, item.BCount, item.Common, len(item.Added), len(item.Removed))
	}
	sb.WriteString("\n")
}

// writeEnvironment renders non-gating reproducibility context.
func writeEnvironment(sb *strings.Builder, changes []scandiff.EnvironmentChange) {
	if len(changes) == 0 {
		return
	}
	sb.WriteString("### Environment context\n\n")
	sb.WriteString("| Field | Baseline | Candidate |\n")
	sb.WriteString("|-------|----------|-----------|\n")
	for _, change := range changes {
		fmt.Fprintf(sb, "| %s | %s | %s |\n", cell(change.Field), cell(value(change.Baseline)), cell(value(change.Candidate)))
	}
	sb.WriteString("\n")
}

// cell escapes a value for a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// value makes an empty environment value visible.
func value(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
