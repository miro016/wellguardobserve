package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/threats"
)

// threatLedgerLink is the relative Markdown link target for the complete
// threat-scenario report, which the projector writes beside the operator report in
// the same directory. This package renders text and writes nothing, so it states
// the link as its own literal rather than borrowing the writer's file name.
const threatLedgerLink = "threat-scenarios.md"

// ThreatLedger is the complete set of fired attack-path scenarios for one scan.
//
// It is its own artifact rather than a section of the operator report because a
// scenario is a narrative: it carries an explanation, a severity, a reference list,
// and the evidence chain behind every asset it fired on, and a scan that fires
// twenty of them buries the surface, host, and finding sections a reader came for.
// The operator report keeps the headline count and links here; nothing is dropped.
type ThreatLedger struct {
	// ScanID and RootTarget identify the scan if the artifact is separated from its
	// directory.
	ScanID     string
	RootTarget string
	// Scenarios holds every scenario that fired, in the order the report ranked
	// them: worst path first.
	Scenarios []threats.ThreatScenario
}

// ThreatLedger returns the report's complete threat-scenario artifact.
func (r Report) ThreatLedger() ThreatLedger {
	scenarios := make([]threats.ThreatScenario, len(r.Threats))
	copy(scenarios, r.Threats)
	return ThreatLedger{ScanID: r.ScanID, RootTarget: r.RootTarget, Scenarios: scenarios}
}

// Total reports how many scenarios the ledger contains.
func (l ThreatLedger) Total() int { return len(l.Scenarios) }

// Markdown renders the fired attack paths, one section per scenario class rather
// than one per asset.
//
// A scenario is a template: it fires once per asset that matches it, and the
// resulting narratives differ only in the asset substituted into them. Rendering
// each as its own section repeated the explanation, the severity, and the reference
// list once per asset - 184 of the 743 lines of the captures/vissim.no report were
// 20 scenarios drawn from 3 templates, 13 of them consecutive and identically
// titled. A reader who meets the same paragraph thirteen times learns to skip the
// section that carries the analysis.
//
// So the shared half is stated once and the assets are listed beneath it. Nothing is
// dropped: every scenario still contributes its assets and its own evidence.
func (l ThreatLedger) Markdown() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Threat Scenarios: %s\n\n", l.RootTarget)
	fmt.Fprintf(&sb, "- Scan ID: %s\n", valueOrDash(l.ScanID))
	fmt.Fprintf(&sb, "- Threat scenarios: %d (%s)\n\n", l.Total(), threatComposition(l.Scenarios))
	if l.Total() == 0 {
		sb.WriteString("No threat scenarios fired (no qualifying combinations of findings).\n")
		return sb.String()
	}
	for _, group := range groupThreats(l.Scenarios) {
		fmt.Fprintf(&sb, "## %s (%s)\n\n", group.Name, events.Severity(group.Severity))
		if group.Summary != "" {
			fmt.Fprintf(&sb, "%s\n\n", group.Summary)
		}
		if len(group.References) > 0 {
			fmt.Fprintf(&sb, "References: %s\n\n", strings.Join(group.References, ", "))
		}
		for _, t := range group.Members {
			assets := make([]string, 0, len(t.Assets))
			for _, a := range t.Assets {
				assets = append(assets, a.Kind+" "+a.ID)
			}
			fmt.Fprintf(&sb, "- %s\n", strings.Join(assets, ", "))
			for _, e := range t.Evidence {
				fmt.Fprintf(&sb, "  - %s\n", e)
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// threatGroup is the scenarios of one class that share everything except which
// assets they fired on.
type threatGroup struct {
	Name       string
	Severity   int
	Summary    string
	References []string
	Members    []threats.ThreatScenario
}

// groupThreats folds scenarios that say the same thing about different assets into
// one group, preserving the order they were ranked in: a group takes the position of
// its first member, so the worst path still leads.
//
// Everything a group states once is part of its key, which is what makes the fold
// safe rather than merely tidy. Two instances of one scenario whose chains differ in
// currentness carry different summaries and stay apart, because the heading would
// otherwise claim of every asset what is true of only one.
func groupThreats(in []threats.ThreatScenario) []threatGroup {
	out := make([]threatGroup, 0, len(in))
	at := make(map[string]int, len(in))
	for _, t := range in {
		key := strings.Join([]string{
			t.Name, strconv.Itoa(t.Severity),
			t.Summary, strings.Join(t.References, "|"),
		}, "\x00")
		i, ok := at[key]
		if !ok {
			i = len(out)
			at[key] = i
			out = append(out, threatGroup{
				Name: t.Name, Severity: t.Severity, Summary: t.Summary,
				References: t.References,
			})
		}
		out[i].Members = append(out[i].Members, t)
	}
	return out
}
