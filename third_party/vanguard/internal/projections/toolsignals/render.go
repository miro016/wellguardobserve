package toolsignals

import (
	"fmt"
	"strings"
)

// maxListItems caps how many members a single Markdown list shows; the omitted
// remainder is summarized. The JSON always carries the complete set.
const maxListItems = 20

// Markdown renders the operator-facing report. Every section is omitted when empty,
// so a clean corpus stays short, and every list is sorted and capped, so the output
// is deterministic and golden-testable.
func (r *Report) Markdown() string {
	var sb strings.Builder
	sb.WriteString("# Tool Health Signals\n\n")

	r.writeHeader(&sb)
	r.writeIntegrityCaveats(&sb)
	r.writeSignals(&sb)
	r.writeToolRollup(&sb)
	r.writeScans(&sb)

	return sb.String()
}

// writeHeader gives the corpus size, mode, thresholds, and the one-line rollup.
func (r *Report) writeHeader(sb *strings.Builder) {
	fmt.Fprintf(sb, "- Corpus: **%d scan(s)** (mode `%s`)\n", r.Corpus.ScanCount, r.Corpus.Mode)
	fmt.Fprintf(sb, "- Min severity shown: `%s`\n", severityOrDefault(r.Corpus.MinSeverity, SeverityInfo))
	c := r.Corpus.Counts
	fmt.Fprintf(sb, "- Signals shown: %d (%d high, %d medium, %d low, %d info)\n",
		c.High+c.Medium+c.Low+c.Info, c.High, c.Medium, c.Low, c.Info)
	if r.hasIntegrityCaveat() {
		sb.WriteString("- Note: log-integrity signals present; the numbers below may be incomplete.\n")
	}
	sb.WriteString("\n")
}

// writeIntegrityCaveats leads with any log-integrity signal, because a bad log
// caveats every number under it.
func (r *Report) writeIntegrityCaveats(sb *strings.Builder) {
	integrity := r.integritySignals()
	if len(integrity) == 0 {
		return
	}
	sb.WriteString("## Integrity caveats\n\n")
	for _, s := range integrity {
		fmt.Fprintf(sb, "- **%s** `%s`%s - %s (%s)\n",
			s.Severity, s.ID, toolTarget(s), s.Summary, scansLabel(s))
	}
	sb.WriteString("\n")
}

// writeSignals renders the flat, ranked, non-integrity signals.
func (r *Report) writeSignals(sb *strings.Builder) {
	sb.WriteString("## Signals\n\n")
	rest := r.nonIntegritySignals()
	if len(rest) == 0 {
		sb.WriteString("No signals.\n\n")
		return
	}
	for _, s := range rest {
		fmt.Fprintf(sb, "- **%s** `%s` (%s)%s - %s. %s\n",
			s.Severity, s.ID, s.Scope, toolTarget(s), s.Summary, scansLabel(s))
	}
	sb.WriteString("\n")
}

// writeToolRollup renders the corpus-level per-tool operational table.
func (r *Report) writeToolRollup(sb *strings.Builder) {
	if len(r.Tools) == 0 {
		return
	}
	sb.WriteString("## Per-tool corpus rollup\n\n")
	sb.WriteString("| Tool | Events | Errors | Warns | RateLimited | Calls | Failed |\n")
	sb.WriteString("|------|--------|--------|-------|-------------|-------|--------|\n")
	for _, t := range r.Tools {
		fmt.Fprintf(sb, "| %s | %d | %d | %d | %d | %d | %d |\n",
			t.Tool, t.Events, t.Errors, t.Warns, t.RateLimited, t.Calls, t.FailedCalls)
	}
	sb.WriteString("\n")
}

// writeScans renders the per-scan summary and footnotes any skipped subfolders.
func (r *Report) writeScans(sb *strings.Builder) {
	sb.WriteString("## Per-scan summary\n\n")
	sb.WriteString("| Scan | ScanID | Status | Events | Tools | High | Medium | Low | Info |\n")
	sb.WriteString("|------|--------|--------|--------|-------|------|--------|-----|------|\n")
	for _, s := range r.Scans {
		fmt.Fprintf(sb, "| %s | %s | %s | %d | %d | %d | %d | %d | %d |\n",
			s.Label, orDash(s.ScanID), s.Status, s.Events, s.Tools,
			s.Signals.High, s.Signals.Medium, s.Signals.Low, s.Signals.Info)
	}
	sb.WriteString("\n")
	if len(r.Skipped) > 0 {
		fmt.Fprintf(sb, "%d subfolder(s) skipped (no tooling log): %s\n\n",
			len(r.Skipped), capJoin(r.Skipped))
	}
}

// integritySignals returns the shown log-integrity signals in ranked order.
func (r *Report) integritySignals() []Signal {
	var out []Signal
	for _, s := range r.Signals {
		if isIntegrityID(s.ID) {
			out = append(out, s)
		}
	}
	return out
}

// nonIntegritySignals returns the shown non-integrity signals in ranked order.
func (r *Report) nonIntegritySignals() []Signal {
	var out []Signal
	for _, s := range r.Signals {
		if !isIntegrityID(s.ID) {
			out = append(out, s)
		}
	}
	return out
}

// hasIntegrityCaveat reports whether any shown signal is a log-integrity one.
func (r *Report) hasIntegrityCaveat() bool {
	for _, s := range r.Signals {
		if isIntegrityID(s.ID) {
			return true
		}
	}
	return false
}

// isIntegrityID reports whether a catalogue id is in the log-integrity family.
func isIntegrityID(id string) bool {
	return strings.HasPrefix(id, "log-integrity/")
}

// toolTarget renders the " on tool/target" clause a signal carries, or empty.
func toolTarget(s Signal) string {
	switch {
	case s.Tool != "" && s.Target != "":
		return fmt.Sprintf(" on %s/%s", s.Tool, s.Target)
	case s.Tool != "":
		return fmt.Sprintf(" on %s", s.Tool)
	default:
		return ""
	}
}

// scansLabel renders which scans a signal was seen in: one label for a one-off, a
// count plus the capped list for a multi-scan signal.
func scansLabel(s Signal) string {
	if len(s.Scans) == 1 {
		return fmt.Sprintf("seen in %s", s.Scans[0])
	}
	return fmt.Sprintf("seen in %d scans: %s", len(s.Scans), capJoin(s.Scans))
}

// capJoin joins up to maxListItems items with ", ", noting the omitted remainder.
func capJoin(items []string) string {
	if len(items) <= maxListItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxListItems], ", ") + fmt.Sprintf(" (+%d more)", len(items)-maxListItems)
}

// severityOrDefault renders s, or def when s is empty.
func severityOrDefault(s, def Severity) Severity {
	if s == "" {
		return def
	}
	return s
}

// orDash renders an empty string as "-".
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
