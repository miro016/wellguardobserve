package toolsignals

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Input is the already-loaded, already-ordered corpus handed to Build. The
// filesystem discovery and per-scan loading that produce it live in
// internal/projections/persistence; Build stays pure.
type Input struct {
	// Mode is how the corpus was resolved: "root" or "scans".
	Mode string
	// Scans is the ordered corpus. For "scans" the order is the caller's argument
	// order; for "root" it is earliest-envelope time then label. Cross-scan trend
	// signals (a later step) rely on this being the defined corpus order.
	Scans []ScanData
	// Skipped lists directories under -root that were not scans (no tooling log),
	// recorded for the report footnote. Empty for "scans".
	Skipped []string
	// MinSeverity drops signals below this level from the rendered report. Empty means
	// info (show everything). It does not affect the gate: TopSeverity records the most
	// severe signal found regardless of this filter.
	MinSeverity Severity
}

// Report is the pure, JSON-serializable read model: corpus metadata, the ordered
// per-scan summaries, the flat ranked signals, and the per-tool corpus rollup. It
// renders to deterministic JSON and Markdown.
type Report struct {
	Corpus  CorpusMeta    `json:"corpus"`
	Signals []Signal      `json:"signals"`
	Tools   []ToolRollup  `json:"tools"`
	Scans   []ScanSummary `json:"scans"`
	Skipped []string      `json:"skipped,omitempty"`
}

// CorpusMeta is the corpus-level header.
type CorpusMeta struct {
	// ScanCount is the number of analyzed scans (excludes skipped dirs).
	ScanCount int `json:"scanCount"`
	// Mode is "root" or "scans".
	Mode string `json:"mode"`
	// MinSeverity is the display floor in effect (empty means info).
	MinSeverity Severity `json:"minSeverity,omitempty"`
	// TopSeverity is the most severe signal found before the MinSeverity filter, or
	// empty when no signal fired. The -fail-on gate reads this, so hiding a signal for
	// display never hides it from the gate.
	TopSeverity Severity `json:"topSeverity,omitempty"`
	// Counts tallies the shown signals by severity.
	Counts SeverityCounts `json:"counts"`
}

// SeverityCounts tallies signals or findings by severity.
type SeverityCounts struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// add increments the bucket for s.
func (c *SeverityCounts) add(s Severity) {
	switch s {
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	case SeverityLow:
		c.Low++
	case SeverityInfo:
		c.Info++
	}
}

// Signal is a corpus-level finding: one grouped defect and the scans it was seen in.
type Signal struct {
	// ID is the catalogue id (the group key).
	ID string `json:"id"`
	// Severity is the base catalogue severity, escalated one step when systemic.
	Severity Severity `json:"severity"`
	// Scope is "scan" for a one-off (a single scan) or "corpus" for a signal seen in
	// more than one scan.
	Scope string `json:"scope"`
	// Tool and Target are what the signal concerns, empty when not tool/target-scoped.
	Tool   string `json:"tool,omitempty"`
	Target string `json:"target,omitempty"`
	// Summary is the representative one-line description.
	Summary string `json:"summary"`
	// Evidence is the representative deterministic evidence (from the first member
	// scan in sorted order).
	Evidence map[string]any `json:"evidence,omitempty"`
	// Scans are the labels of the scans this signal was seen in, sorted.
	Scans []string `json:"scans"`
}

// ScanSummary is one scan's row in the report.
type ScanSummary struct {
	Label   string         `json:"label"`
	ScanID  string         `json:"scanID,omitempty"`
	Status  LoadStatus     `json:"status"`
	Events  int            `json:"events"`
	Tools   int            `json:"tools"`
	Signals SeverityCounts `json:"signals"`
}

// ToolRollup is one tool's operational totals summed across the corpus, the
// corpus-level analogue of the single-scan provider table.
type ToolRollup struct {
	Tool        string `json:"tool"`
	Events      int    `json:"events"`
	Errors      int    `json:"errors"`
	Warns       int    `json:"warns"`
	RateLimited int    `json:"rateLimited"`
	Calls       int    `json:"calls"`
	FailedCalls int    `json:"failedCalls"`
}

// Build runs the detector registry over every scan, aggregates the findings across
// the corpus, and returns the ranked Report. It is deterministic: identical input
// and config yield identical output.
func Build(in Input, cfg Config) Report {
	groups := map[groupIdentity]*signalGroup{}
	scanSummaries := make([]ScanSummary, 0, len(in.Scans))

	for _, sd := range in.Scans {
		findings := runDetectors(sd, cfg)

		summary := ScanSummary{
			Label:  sd.Label,
			ScanID: sd.ScanID,
			Status: sd.Status,
			Events: sd.Events,
			Tools:  len(sd.Stats.Tools),
		}
		for _, f := range findings {
			summary.Signals.add(f.Severity)
			id := groupIdentity{id: f.ID, tool: f.Tool, target: f.Target}
			g := groups[id]
			if g == nil {
				g = &signalGroup{base: f.Severity}
				groups[id] = g
			}
			g.members = append(g.members, scanFinding{label: sd.Label, f: f})
		}
		scanSummaries = append(scanSummaries, summary)
	}

	signals, top := aggregate(groups, len(in.Scans), cfg)

	// Cross-scan trend signals are computed from the ordered corpus, not the grouped
	// per-scan findings, then ranked alongside them.
	for _, ts := range trendSignals(in.Scans, cfg) {
		signals = append(signals, ts)
		if severityRank(ts.Severity) > severityRank(top) {
			top = ts.Severity
		}
	}
	sortSignals(signals)

	rep := Report{
		Corpus: CorpusMeta{
			ScanCount:   len(in.Scans),
			Mode:        in.Mode,
			MinSeverity: in.MinSeverity,
			TopSeverity: top,
		},
		Tools:   corpusToolRollup(in.Scans),
		Scans:   scanSummaries,
		Skipped: sortedCopy(in.Skipped),
	}

	// Filter for display, then tally the shown counts.
	for _, s := range signals {
		if in.MinSeverity != "" && !s.Severity.atOrAbove(in.MinSeverity) {
			continue
		}
		rep.Signals = append(rep.Signals, s)
		rep.Corpus.Counts.add(s.Severity)
	}
	return rep
}

// GateBreached reports whether any signal found (before the display filter) is at or
// above failOn. An empty failOn never gates.
func (r *Report) GateBreached(failOn Severity) bool {
	return r.Corpus.TopSeverity.atOrAbove(failOn)
}

// JSON renders the report as indented JSON, the machine-readable source of truth.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal signals report: %w", err)
	}
	return b, nil
}

// groupIdentity is the cross-scan grouping key: same defect on the same target.
type groupIdentity struct {
	id     string
	tool   string
	target string
}

// scanFinding pairs a finding with the scan label it came from.
type scanFinding struct {
	label string
	f     Finding
}

// signalGroup accumulates the members of one grouped signal.
type signalGroup struct {
	base    Severity
	members []scanFinding
}

// aggregate turns the grouped findings into ranked Signals and reports the most
// severe signal found (post-escalation, pre-display-filter) for the gate.
func aggregate(groups map[groupIdentity]*signalGroup, scanCount int, cfg Config) ([]Signal, Severity) {
	signals := make([]Signal, 0, len(groups))
	var top Severity

	for id, g := range groups {
		labels := memberLabels(g.members)
		sev := g.base
		if isSystemic(len(labels), scanCount, cfg) {
			sev = sev.escalate()
		}
		scope := "scan"
		if len(labels) > 1 {
			scope = "corpus"
		}
		rep := representative(g.members, labels)
		signals = append(signals, Signal{
			ID:       id.id,
			Severity: sev,
			Scope:    scope,
			Tool:     id.tool,
			Target:   id.target,
			Summary:  rep.Summary,
			Evidence: rep.Evidence,
			Scans:    labels,
		})
		if severityRank(sev) > severityRank(top) {
			top = sev
		}
	}
	// Not sorted here: Build appends the cross-scan trend signals, then sorts the whole
	// set once.
	return signals, top
}

// isSystemic reports whether a signal present in seen scans out of total counts as
// systemic (a strong-majority share). A single-scan corpus is never systemic.
func isSystemic(seen, total int, cfg Config) bool {
	if total < 2 || seen < 2 {
		return false
	}
	return float64(seen)/float64(total) >= cfg.SystemicFraction
}

// memberLabels returns the distinct member scan labels, sorted.
func memberLabels(members []scanFinding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(members))
	for _, m := range members {
		if _, ok := seen[m.label]; ok {
			continue
		}
		seen[m.label] = struct{}{}
		out = append(out, m.label)
	}
	sort.Strings(out)
	return out
}

// representative picks the finding whose scan label sorts first, so the summary and
// evidence a grouped signal shows are deterministic.
func representative(members []scanFinding, labels []string) Finding {
	first := labels[0]
	for _, m := range members {
		if m.label == first {
			return m.f
		}
	}
	return members[0].f
}

// sortSignals imposes the final, fully deterministic ranking: severity high->info,
// then id, tool, target, then the member-scan labels.
func sortSignals(signals []Signal) {
	sort.Slice(signals, func(i, j int) bool {
		a, b := signals[i], signals[j]
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return joinLabels(a.Scans) < joinLabels(b.Scans)
	})
}

// corpusToolRollup sums each tool's operational rollup across every scan, sorted by
// tool.
func corpusToolRollup(scans []ScanData) []ToolRollup {
	byTool := map[string]*ToolRollup{}
	for _, sd := range scans {
		for name, ts := range sd.Stats.Tools {
			r := byTool[name]
			if r == nil {
				r = &ToolRollup{Tool: name}
				byTool[name] = r
			}
			r.Events += ts.Total
			r.Errors += ts.ByLevel["error"]
			r.Warns += ts.ByLevel["warn"]
			r.RateLimited += ts.RateLimited
			r.Calls += ts.Calls
			r.FailedCalls += ts.FailedCalls
		}
	}
	out := make([]ToolRollup, 0, len(byTool))
	for _, r := range byTool {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// joinLabels joins labels for a stable tie-break key.
func joinLabels(labels []string) string {
	return strings.Join(labels, ",")
}

// sortedCopy returns a sorted copy of xs, or nil when empty.
func sortedCopy(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}
