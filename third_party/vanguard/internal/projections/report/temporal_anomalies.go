package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/projections/facts"
)

// TemporalAnomalies is the complete anomaly ledger for one scan, split out of the
// operator report so both can be read for what they are.
//
// The ledger is additive: every row flags evidence for review and none of it is
// removed from the report. That is exactly why it does not belong inline. One
// anomaly type fires once per subject it applies to, so on a real estate the ledger
// runs to hundreds of rows and pushes the hosts, findings, and issues past where
// anyone scrolls. The operator report keeps the per-type counts; this carries the
// rows, and it carries both sources of them - the facts graph's own coverage
// anomalies and the report-only entity-to-facts reconciliation - so a reader
// auditing dating quality has one place to look rather than two.
type TemporalAnomalies struct {
	// ScanID and RootTarget identify the scan the ledger belongs to, so a file
	// separated from its directory is still attributable.
	ScanID     string
	RootTarget string
	// AnalysisAsOf is the cutoff every temporal judgement below was made against.
	AnalysisAsOf time.Time
	// Counts summarizes the coverage anomalies by type, matching the summary table
	// in the operator report.
	Counts []facts.TemporalAnomalyCount
	// Coverage holds the facts graph's own temporal anomalies, and Reconciliation
	// the report-only cross-checks between the entity projection and the classified
	// surface. They are kept apart because they answer different questions: one is
	// about how well the evidence is dated, the other about whether two views of
	// the same scan agree.
	Coverage       []facts.TemporalAnomaly
	Reconciliation []facts.TemporalAnomaly
}

// TemporalAnomalies gathers the report's complete anomaly ledger. It returns a zero
// value with no rows when the report carried no temporal coverage, which is what a
// scan with no facts graph produces.
func (r Report) TemporalAnomalies() TemporalAnomalies {
	out := TemporalAnomalies{ScanID: r.ScanID, RootTarget: r.RootTarget, AnalysisAsOf: r.AnalysisAsOf}
	if r.TemporalCoverage != nil {
		out.Counts = r.TemporalCoverage.AnomalyCounts()
		out.Coverage = r.TemporalCoverage.Anomalies
	}
	if r.Reconciliation != nil {
		out.Reconciliation = r.Reconciliation.Anomalies
	}
	return out
}

// Total is how many anomalies the ledger holds across both sections.
func (a TemporalAnomalies) Total() int { return len(a.Coverage) + len(a.Reconciliation) }

// Markdown renders the ledger as a standalone document.
func (a TemporalAnomalies) Markdown() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Temporal Anomalies: %s\n\n", a.RootTarget)
	fmt.Fprintf(&sb, "- Scan ID: %s\n", a.ScanID)
	fmt.Fprintf(&sb, "- Analysis as of: %s\n", formatTime(a.AnalysisAsOf))
	fmt.Fprintf(&sb, "- Anomalies: %d\n\n", a.Total())
	sb.WriteString("Every row flags evidence for review. Nothing here is removed from the scan: an " +
		"anomaly records that a claim's dating is incomplete or self-contradictory, never that the " +
		"claim itself is wrong.\n\n")

	if a.Total() == 0 {
		sb.WriteString("No temporal anomalies detected.\n")
		return sb.String()
	}

	if len(a.Counts) > 0 {
		sb.WriteString("## By type\n\n| Type | Severity | Subjects |\n|---|---:|---:|\n")
		for _, row := range a.Counts {
			fmt.Fprintf(&sb, "| %s | %d | %d |\n", row.Type, row.Severity, row.Count)
		}
		sb.WriteString("\n")
	}

	if len(a.Coverage) > 0 {
		fmt.Fprintf(&sb, "## Temporal coverage (%d)\n\n", len(a.Coverage))
		sb.WriteString(facts.AnomalyTable(a.Coverage))
		sb.WriteString("\n")
	}

	if len(a.Reconciliation) > 0 {
		fmt.Fprintf(&sb, "## Entity-facts reconciliation (%d)\n\n", len(a.Reconciliation))
		sb.WriteString("Report-only cross-checks between the entity projection (headline totals) and the " +
			"classified facts surface. Both complete views are retained; neither is rescaled to agree.\n\n")
		sb.WriteString(facts.AnomalyTable(a.Reconciliation))
		sb.WriteString("\n")
	}
	return sb.String()
}
