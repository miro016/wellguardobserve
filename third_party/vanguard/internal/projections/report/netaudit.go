package report

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections/netaudit"
)

// The relative Markdown link target for the decoded network-audit projection, which
// the projector writes into a sibling bucket of this report's own directory. This
// package renders text and writes nothing, so it states the link as its own literals
// rather than borrowing the writer's names.
const (
	netauditBucketLink  = "netaudit"
	netauditSummaryLink = "summary.md"
)

// writeNetworkAudit renders the always-present Network Audit & Exclusion
// Verification section: the summary, the capture-health row, one assessment row per
// configured exclusion, the compact violation table, and the limitations and next
// actions. It states capture availability and health
// explicitly, so a reader can never mistake a missing or broken capture for a clean
// zero-violation result.
//
// The section is packet evidence only. It never alters findings or the target's
// risk score; a confirmed scanner-policy violation is an operator issue about the
// scan, not a finding about the target.
func (r Report) writeNetworkAudit(sb *strings.Builder) {
	m := r.NetworkAudit
	if m == nil {
		return
	}
	sb.WriteString("## Network Audit & Exclusion Verification\n\n")
	sb.WriteString("Packet-capture evidence, independent of the domain and tool event streams. It " +
		"corroborates that exclusion enforcement held or exposes a violation; it never changes " +
		"target findings or risk. Negative (zero-contact) conclusions are drawn only from a complete " +
		"capture; positive packet evidence stands even from a partial capture.\n\n")

	writeNetAuditSummary(sb, m.Summary)
	writeNetAuditCapture(sb, m.Capture)
	writeNetAuditViolations(sb, m)
	writeNetAuditNotes(sb, m)
}

func writeNetAuditSummary(sb *strings.Builder, s netaudit.Summary) {
	sb.WriteString("**Summary:**\n\n")
	sb.WriteString("| Measure | Value |\n|---|---|\n")
	fmt.Fprintf(sb, "| Capture status | %s |\n", s.CaptureStatus)
	fmt.Fprintf(sb, "| Packets observed | %d |\n", s.Packets)
	fmt.Fprintf(sb, "| Confirmed violations | %d |\n", s.ViolationsConfirmed)
	fmt.Fprintf(sb, "| Possible violations | %d |\n", s.ViolationsPossible)
	fmt.Fprintf(sb, "| Rules corroborated (zero contact) | %d |\n", s.RulesCorroborated)
	fmt.Fprintf(sb, "| Rules not exercised | %d |\n", s.RulesNotExercised)
	fmt.Fprintf(sb, "| Rules inconclusive | %d |\n", s.RulesInconclusive)
	sb.WriteString("\n")
}

func writeNetAuditCapture(sb *strings.Builder, e netaudit.CaptureAudit) {
	h := e.Health
	fmt.Fprintf(sb, "### Capture: %s\n\n", h.Status)
	sb.WriteString("| Field | Value |\n|---|---|\n")
	fmt.Fprintf(sb, "| Backend | %s |\n", markdownCell(string(h.Backend)))
	if h.RelPath != "" {
		fmt.Fprintf(sb, "| Path | %s |\n", markdownCell(h.RelPath))
	}
	if h.SHA256 != "" {
		fmt.Fprintf(sb, "| SHA-256 | %s |\n", markdownCell(h.SHA256))
	}
	if h.ByteSize > 0 {
		fmt.Fprintf(sb, "| Size (bytes) | %d |\n", h.ByteSize)
	}
	fmt.Fprintf(sb, "| Packets (remote/loopback) | %d (%d/%d) |\n", h.PacketCount, h.RemotePackets, h.LoopbackPackets)
	if h.DroppedPackets > 0 {
		fmt.Fprintf(sb, "| Dropped packets | %d |\n", h.DroppedPackets)
	}
	fmt.Fprintf(sb, "| Process attribution | %t |\n", h.ProcessAttribution)
	if len(h.SkippedLinkTypes) > 0 {
		fmt.Fprintf(sb, "| Skipped link types | %s |\n", markdownCell(strings.Join(h.SkippedLinkTypes, ", ")))
	}
	sb.WriteString("\n")

	if len(h.Limitations) > 0 {
		sb.WriteString("Capture limitations:\n\n")
		for _, l := range h.Limitations {
			fmt.Fprintf(sb, "- %s\n", l)
		}
		sb.WriteString("\n")
	}

	writeNetAuditTraffic(sb, e.Traffic)
	sb.WriteString(netAuditStatusStatement(e))
	sb.WriteString("\n")

	if len(e.Rules) == 0 {
		sb.WriteString("No domain or IP exclusion rules were configured for this collection.\n\n")
		return
	}
	sb.WriteString("| Rule | Kind | Verdict | Exclusion issues | Tool rejections | Packet conversations | Detail |\n")
	sb.WriteString("|---|---|---|---:|---:|---:|---|\n")
	for i := range e.Rules {
		ra := e.Rules[i]
		fmt.Fprintf(sb, "| %s | %s | %s | %d | %d | %d | %s |\n",
			markdownCell(ra.Rule), ra.Kind, ra.Verdict, ra.ExclusionIssues, ra.ToolRejections,
			ra.PacketConversations, markdownCell(ra.Detail))
	}
	sb.WriteString("\n")
	writeNetAuditUnmatched(sb, e.UnmatchedRejections)
}

// writeNetAuditUnmatched lists the typed tool rejections whose denied destination
// matched no configured rule. They are enforcement evidence the rule table cannot
// account for, so they are stated rather than dropped: either the engagement
// snapshot does not describe the rule that fired, or the destination could not be
// derived from the rejection event.
func writeNetAuditUnmatched(sb *strings.Builder, rejections []netaudit.UnmatchedRejection) {
	if len(rejections) == 0 {
		return
	}
	sb.WriteString("Tool rejections not attributable to a configured rule:\n\n")
	sb.WriteString("| Tool | Denied destination | Reason | Time |\n|---|---|---|---|\n")
	for _, r := range rejections {
		fmt.Fprintf(sb, "| %s | %s | %s | %s |\n",
			markdownCell(r.Tool), markdownCell(r.Destination), markdownCell(r.Reason), formatTime(r.At))
	}
	sb.WriteString("\n")
}

// writeNetAuditTraffic renders the compact decoded-traffic overview and points at
// the raw investigation projection. It orients a reader even when no exclusion rule
// is configured, where the verdict rows alone would say little.
func writeNetAuditTraffic(sb *strings.Builder, t netaudit.TrafficSummary) {
	if t.Conversations == 0 && t.RemotePeers == 0 && t.DNSQueries == 0 {
		return
	}
	fmt.Fprintf(sb, "Observed traffic: %d conversations to %d distinct remote peers; "+
		"DNS %d queries / %d answers; %d TLS SNI, %d HTTP Host observed. "+
		"Full decoded detail: [%s](../%s/%s).\n\n",
		t.Conversations, t.RemotePeers, t.DNSQueries, t.DNSAnswers, t.TLSHandshakes, t.HTTPRequests,
		netauditSummaryLink, netauditBucketLink, netauditSummaryLink)
	if len(t.TopDestinations) > 0 {
		sb.WriteString("Busiest destinations: ")
		parts := make([]string, 0, len(t.TopDestinations))
		for _, d := range t.TopDestinations {
			parts = append(parts, fmt.Sprintf("%s (%d)", d.Addr, d.Packets))
		}
		sb.WriteString(strings.Join(parts, ", "))
		sb.WriteString(".\n\n")
	}
}

// netAuditStatusStatement renders the explicit wording the plan mandates for each
// capture status, so the report never implies "no violations" from incomplete data.
func netAuditStatusStatement(e netaudit.CaptureAudit) string {
	h := e.Health
	switch h.Status {
	case netaudit.StatusAbsent:
		return "Capture absent; exclusion traffic verification was not performed for this collection.\n"
	case netaudit.StatusUnreadable:
		return "Capture unreadable; packet-level exclusion verification is inconclusive.\n"
	case netaudit.StatusParseFailed:
		return fmt.Sprintf("Capture parsing failed at packet %d (%s); packet-level verdict is inconclusive.\n", h.ParseOffset, h.ParseError)
	case netaudit.StatusCollectionMismatch:
		return "Capture could not be bound to this collection; packet-level verdict is inconclusive.\n"
	case netaudit.StatusPartial:
		return "Capture is partial; only positive packet evidence is used, negative conclusions are withheld.\n"
	case netaudit.StatusComplete:
		exercised := countExercised(e)
		if exercised == 0 {
			return "Complete capture, but no configured rule was exercised by this run; this is not enforcement confirmation.\n"
		}
		return fmt.Sprintf("No violation observed in a complete capture for %d exercised rule(s).\n", exercised)
	default:
		return ""
	}
}

func countExercised(e netaudit.CaptureAudit) int {
	n := 0
	for i := range e.Rules {
		switch e.Rules[i].Verdict {
		case netaudit.VerdictZeroContactCorroborated, netaudit.VerdictViolationConfirmed, netaudit.VerdictViolationPossible:
			n++
		case netaudit.VerdictNotExercised, netaudit.VerdictInconclusive:
			// Not an exercised rule.
		}
	}
	return n
}

func writeNetAuditViolations(sb *strings.Builder, m *netaudit.Model) {
	violations := m.Capture.Violations
	if len(violations) == 0 {
		return
	}
	sb.WriteString("### Confirmed and possible violations\n\n")
	sb.WriteString("| Rule | Destination | Protocol/Port | Attribution | First | Last | Packets | Confidence |\n")
	sb.WriteString("|---|---|---|---|---|---|---:|---|\n")
	for i := range violations {
		v := violations[i]
		protoPort := v.Protocol
		if v.Port > 0 {
			protoPort = fmt.Sprintf("%s/%d", v.Protocol, v.Port)
		}
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s | %d | %s |\n",
			markdownCell(v.Rule), markdownCell(v.Destination), markdownCell(protoPort),
			markdownCell(v.Attribution), formatTime(v.First), formatTime(v.Last), v.Packets, v.Confidence)
	}
	sb.WriteString("\n")
}

func writeNetAuditNotes(sb *strings.Builder, m *netaudit.Model) {
	if len(m.Notes) == 0 {
		return
	}
	sb.WriteString("Notes:\n\n")
	for _, n := range m.Notes {
		fmt.Fprintf(sb, "- %s\n", n)
	}
	sb.WriteString("\n")
	sb.WriteString("To regenerate this section after restoring a missing capture, place it under " +
		"`netaudit/` below the collection root and re-run `vanguard-projections build`.\n\n")
}

// netAuditNextSteps returns the operator next steps the packet evidence adds: a
// confirmed scanner-policy violation is a high-severity, immediate action, while
// possible violations and incomplete coverage are review/coverage items. These are
// scan-hygiene actions, not target remediation.
func (r Report) netAuditNextSteps() []string {
	m := r.NetworkAudit
	if m == nil {
		return nil
	}
	var steps []string
	if m.Summary.ViolationsConfirmed > 0 {
		steps = append(steps, fmt.Sprintf("URGENT: %d confirmed exclusion violation(s) in packet capture. "+
			"A target-facing connection reached an excluded destination. Halt and investigate the scanner "+
			"policy path before the next run.", m.Summary.ViolationsConfirmed))
	}
	if m.Summary.ViolationsPossible > 0 {
		steps = append(steps, fmt.Sprintf("Review %d possible exclusion violation(s): traffic correlated to an "+
			"excluded DNS answer without direct hostname proof.", m.Summary.ViolationsPossible))
	}
	switch m.Summary.CaptureStatus {
	case netaudit.StatusAbsent, netaudit.StatusUnreadable, netaudit.StatusParseFailed,
		netaudit.StatusCollectionMismatch:
		steps = append(steps, fmt.Sprintf("Restore packet capture coverage: the capture for this collection is "+
			"%s, so exclusion traffic could not be verified.", m.Summary.CaptureStatus))
	case netaudit.StatusComplete, netaudit.StatusPartial:
		// A parsed capture needs no coverage action; its limitations are stated above.
	}
	return steps
}
