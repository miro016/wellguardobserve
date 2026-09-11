package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// issueListCap bounds each compact operator-report issue subsection. The complete
// ledger is always available beside the report.
const (
	issueListCap      = 12
	issueSourceScope  = "scope"
	issueSourceBudget = "budget"
	// issuesLedgerLink is the relative Markdown link target for the complete issue
	// ledger, which the projector writes beside this report in the same directory.
	// This package renders text and writes nothing, so it states the link as its own
	// literal rather than borrowing the writer's file name.
	issuesLedgerLink = "issues.md"
)

// IssueLedger is the complete, uncapped set of issues for one scan.
type IssueLedger struct {
	// ScanID and RootTarget identify the scan if the artifact is separated from its directory.
	ScanID     string
	RootTarget string
	// Issues holds every IssueObserved folded into the report in deterministic order.
	Issues []Issue
}

// IssueLedger returns the report's complete issue artifact.
func (r Report) IssueLedger() IssueLedger {
	issues := make([]Issue, len(r.Issues))
	copy(issues, r.Issues)
	sortIssues(issues)
	return IssueLedger{ScanID: r.ScanID, RootTarget: r.RootTarget, Issues: issues}
}

// Total reports how many issue rows the ledger contains.
func (l IssueLedger) Total() int { return len(l.Issues) }

// Markdown renders the complete issue ledger grouped by producer class and severity.
func (l IssueLedger) Markdown() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Issue Ledger: %s\n\n", l.RootTarget)
	fmt.Fprintf(&sb, "- Scan ID: %s\n", valueOrDash(l.ScanID))
	fmt.Fprintf(&sb, "- Issues: %d\n\n", l.Total())
	if l.Total() == 0 {
		sb.WriteString("No scan issues recorded.\n")
		return sb.String()
	}

	byClass := make(map[string]map[events.Severity][]Issue)
	for i := range l.Issues {
		class := ledgerClass(l.Issues[i])
		if byClass[class] == nil {
			byClass[class] = make(map[events.Severity][]Issue)
		}
		byClass[class][l.Issues[i].Severity] = append(byClass[class][l.Issues[i].Severity], l.Issues[i])
	}
	classes := make([]string, 0, len(byClass))
	for class := range byClass {
		classes = append(classes, class)
	}
	sort.Strings(classes)

	for _, class := range classes {
		classCount := 0
		for _, rows := range byClass[class] {
			classCount += len(rows)
		}
		fmt.Fprintf(&sb, "## %s (%d)\n\n", class, classCount)
		for _, severity := range sortedSeverities(byClass[class]) {
			rows := byClass[class][severity]
			sortIssues(rows)
			fmt.Fprintf(&sb, "### %s (%d)\n\n", severity.String(), len(rows))
			sb.WriteString("| Source | Target | Message | Triggering event | Captured | Event ID |\n")
			sb.WriteString("|---|---|---|---|---|---|\n")
			for i := range rows {
				fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s |\n",
					markdownCell(rows[i].Source), markdownCell(rows[i].Query), markdownCell(rows[i].Message),
					markdownCell(rows[i].CausationID), markdownCell(formatTime(rows[i].CapturedAt)),
					markdownCell(rows[i].EventID))
			}
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// writeIssues renders the compact coverage and tool-error subsets. Every row is
// also present in the complete issue ledger linked from the section header.
func (r Report) writeIssues(sb *strings.Builder) {
	sb.WriteString("## Issues\n\n")
	fmt.Fprintf(sb, "Complete ledger: [%s](%s) (%d total).\n\n",
		issuesLedgerLink, issuesLedgerLink, len(r.Issues))
	if len(r.CoverageGaps) == 0 && len(r.ToolErrors) == 0 {
		sb.WriteString("No coverage gaps or tool errors recorded.\n\n")
		return
	}
	if len(r.CoverageGaps) > 0 {
		fmt.Fprintf(sb, "**Coverage gaps (%d):** active probing was incomplete for these targets; "+
			"the missing port/TLS/web data is a gap, not a clean result.\n\n", len(r.CoverageGaps))
		writeIssueList(sb, r.CoverageGaps)
		sb.WriteString("\n")
	}
	if len(r.ToolErrors) > 0 {
		fmt.Fprintf(sb, "**Tool errors (%d):** a tool failed; not a target weakness.\n\n", len(r.ToolErrors))
		writeIssueList(sb, r.ToolErrors)
		sb.WriteString("\n")
	}
}

// writeIssueList prints the highest-priority compact rows and points to the ledger
// for any omitted rows.
func writeIssueList(sb *strings.Builder, issues []Issue) {
	limit := min(len(issues), issueListCap)
	for i := range limit {
		target := valueOrDash(issues[i].Query)
		source := valueOrDash(issues[i].Source)
		fmt.Fprintf(sb, "- **%s** `%s` - %s: %s", issues[i].Severity.String(), source, target, oneLine(issues[i].Message))
		if issues[i].CausationID != "" {
			fmt.Fprintf(sb, " (trigger: `%s`)", issues[i].CausationID)
		}
		sb.WriteString("\n")
	}
	if omitted := len(issues) - limit; omitted > 0 {
		fmt.Fprintf(sb, "- %d more omitted here; see [%s](%s) for every issue.\n",
			omitted, issuesLedgerLink, issuesLedgerLink)
	}
}

// writeScopeBudget renders the deterministic scope ledger and the compact
// control-decision subsets with complete counts.
func (r Report) writeScopeBudget(sb *strings.Builder) {
	hasAccounting := r.ScopeAccounting != nil
	if !hasAccounting && len(r.ScopeExclusions) == 0 && len(r.BudgetExclusions) == 0 {
		return
	}
	sb.WriteString("## Scope & Budget\n\n")
	r.writeScopeAccounting(sb)
	if len(r.ScopeExclusions) == 0 && len(r.BudgetExclusions) == 0 {
		return
	}
	fmt.Fprintf(sb, "%d scope exclusion(s), %d budget exclusion(s). Complete details: [%s](%s).\n\n",
		len(r.ScopeExclusions), len(r.BudgetExclusions), issuesLedgerLink, issuesLedgerLink)
	if len(r.ScopeExclusions) > 0 {
		fmt.Fprintf(sb, "**Scope exclusions (%d):**\n\n", len(r.ScopeExclusions))
		writeIssueList(sb, r.ScopeExclusions)
		sb.WriteString("\n")
	}
	if len(r.BudgetExclusions) > 0 {
		fmt.Fprintf(sb, "**Budget exclusions (%d):**\n\n", len(r.BudgetExclusions))
		writeIssueList(sb, r.BudgetExclusions)
		sb.WriteString("\n")
	}
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity > issues[j].Severity
		}
		if issues[i].Source != issues[j].Source {
			return issues[i].Source < issues[j].Source
		}
		if issues[i].Query != issues[j].Query {
			return issues[i].Query < issues[j].Query
		}
		if issues[i].Message != issues[j].Message {
			return issues[i].Message < issues[j].Message
		}
		return issues[i].EventID < issues[j].EventID
	})
}

func ledgerClass(issue Issue) string {
	if class := strings.TrimSpace(issue.Class); class != "" {
		return class
	}
	if issue.Source == issueSourceScope || issue.Source == issueSourceBudget {
		return issue.Source
	}
	return "unclassified"
}

func sortedSeverities(groups map[events.Severity][]Issue) []events.Severity {
	severities := make([]events.Severity, 0, len(groups))
	for severity := range groups {
		severities = append(severities, severity)
	}
	sort.Slice(severities, func(i, j int) bool { return severities[i] > severities[j] })
	return severities
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func oneLine(value string) string { return strings.Join(strings.Fields(value), " ") }

func markdownCell(value string) string {
	value = valueOrDash(oneLine(value))
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, "|", "\\|")
}
