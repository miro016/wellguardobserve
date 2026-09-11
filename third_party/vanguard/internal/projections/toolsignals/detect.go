package toolsignals

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// Finding is one detector's per-scan result: the catalogue id it raised, its base
// severity, the tool/target it concerns, a one-line summary, and the deterministic
// evidence fields from the catalogue. Findings are grouped across scans into Signals
// by (ID, Tool, Target).
type Finding struct {
	ID       string
	Severity Severity
	Tool     string
	Target   string
	Summary  string
	Evidence map[string]any
}

// Evidence map keys reused across detectors, named once so the JSON evidence shape
// stays consistent.
const (
	evCount      = "count"
	evSampleName = "sampleName"
)

// detector is a pure predicate over one scan's folded state. It reads only what it
// needs, does no I/O, and never looks at another scan.
type detector func(sd ScanData, cfg Config) []Finding

// registry is the fixed, ordered set of detectors. Order is deterministic; findings
// are re-sorted at the end regardless, so this only fixes evaluation order.
var registry = []detector{
	detectDecode,
	detectSchema,
	detectSeqGap,
	detectMissingCorr,
	detectAttributionTargetGap,
	detectDuplicateConcurrentQuery,
	detectUDPPassTerminal,
	detectUDPPortAccounting,
	detectUDPPartialEvidence,
	detectSelfInflictedRateLimit,
	detectExternalRateLimit,
	detectDegradationStorm,
	detectFailedCallRate,
	detectOpaqueProviderError,
	detectExpectedOutcomeAtWarn,
}

// runDetectors runs every detector over one scan and returns the flattened findings.
func runDetectors(sd ScanData, cfg Config) []Finding {
	var out []Finding
	for _, d := range registry {
		out = append(out, d(sd, cfg)...)
	}
	return out
}

// detectDecode fires when the log had a line that failed to decode. High severity:
// the log is corrupt and every other number for this scan is suspect.
func detectDecode(sd ScanData, _ Config) []Finding {
	if sd.Decode == nil {
		return nil
	}
	return []Finding{{
		ID:       SigLogIntegrityDecode,
		Severity: SeverityHigh,
		Summary:  fmt.Sprintf("tool-event log failed to decode at line %d", sd.Decode.Line),
		Evidence: map[string]any{"line": sd.Decode.Line, "error": sd.Decode.Err},
	}}
}

// detectSchema fires when any envelope carries a Version other than the expected
// SchemaVersion: the reader may be misreading fields written by a different schema.
func detectSchema(sd ScanData, _ Config) []Finding {
	var seen []int
	for v := range sd.SchemaVersions {
		if v != tooleventlog.SchemaVersion {
			seen = append(seen, v)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	sort.Ints(seen)
	return []Finding{{
		ID:       SigLogIntegritySchema,
		Severity: SeverityMedium,
		Summary:  fmt.Sprintf("envelope schema version(s) %v differ from expected %d", seen, tooleventlog.SchemaVersion),
		Evidence: map[string]any{"seen": seen, "expected": tooleventlog.SchemaVersion},
	}}
}

// detectSeqGap fires when the per-scan sequence is not a gap-free, duplicate-free
// 1..Events set: a missing seq (dropped write) leaves SeqMax above the event count, a
// duplicate (double write) leaves it below, and a SeqMin above 1 means the head was
// truncated. It reads the set invariant, not file order, because passive tools write
// concurrently so the log is legitimately not sorted by seq. It is silent for an
// empty log and for an integrity-flagged (partially read) log, where the decode
// signal already caveats the counts.
func detectSeqGap(sd ScanData, _ Config) []Finding {
	if sd.Events == 0 || sd.Decode != nil {
		return nil
	}
	if sd.SeqMin == 1 && sd.SeqMax == int64(sd.Events) {
		return nil
	}
	var kind string
	switch {
	case sd.SeqMin != 1:
		kind = "sequence does not start at 1 (head truncated)"
	case sd.SeqMax > int64(sd.Events):
		kind = "sequence has gaps (missing envelopes)"
	default:
		kind = "sequence has duplicates (repeated envelopes)"
	}
	return []Finding{{
		ID:       SigLogIntegritySeqGap,
		Severity: SeverityMedium,
		Summary:  fmt.Sprintf("%s: min=%d max=%d events=%d", kind, sd.SeqMin, sd.SeqMax, sd.Events),
		Evidence: map[string]any{"min": sd.SeqMin, "max": sd.SeqMax, "events": sd.Events},
	}}
}

// detectMissingCorr fires when call-boundary events lack a CorrID or Phase, so a
// finding cannot be joined back to its provider call. Low severity: a hygiene guard
// against regression.
func detectMissingCorr(sd ScanData, _ Config) []Finding {
	if sd.MissingCorr == nil {
		return nil
	}
	return []Finding{{
		ID:       SigLogIntegrityMissingCorr,
		Severity: SeverityLow,
		Tool:     sd.MissingCorr.SampleTool,
		Summary:  fmt.Sprintf("%d call-boundary event(s) missing corrID/phase", sd.MissingCorr.Count),
		Evidence: map[string]any{
			evCount:      sd.MissingCorr.Count,
			"sampleTool": sd.MissingCorr.SampleTool,
			evSampleName: sd.MissingCorr.SampleName,
		},
	}}
}

// detectAttributionTargetGap fires when a per-target tool (on the config allowlist)
// leaves too large a share of its events unattributed to a target - the crtsh
// 603/603-unattributed defect. It is silent for tools not on the allowlist, so a
// genuinely target-less system tool never false-positives. One finding per tool.
func detectAttributionTargetGap(sd ScanData, cfg Config) []Finding {
	var out []Finding
	for _, tool := range mapKeysSorted(sd.Attribution) {
		a := sd.Attribution[tool]
		if a.total() == 0 || !cfg.isTargetedTool(tool) {
			continue
		}
		if a.targetedRatio() >= cfg.TargetRatioThreshold {
			continue
		}
		out = append(out, Finding{
			ID:       SigAttributionTargetGap,
			Severity: SeverityMedium,
			Tool:     tool,
			Summary: fmt.Sprintf("%s attributed only %d/%d events to a target (%.0f%%)",
				tool, a.NonEmpty, a.total(), a.targetedRatio()*100),
			Evidence: map[string]any{
				"empty":       a.Empty,
				"nonEmpty":    a.NonEmpty,
				"total":       a.total(),
				"sampleNames": a.SampleNames,
			},
		})
	}
	return out
}

// detectDuplicateConcurrentQuery fires when the same (tool,target) is queried by two
// or more calls whose time spans overlap - a duplicated, racing query. One finding
// per (tool,target). Uncorrelated or target-less calls are ignored (nothing to
// attribute a duplicate to).
func detectDuplicateConcurrentQuery(sd ScanData, _ Config) []Finding {
	windows := duplicateOverlaps(sd.Calls)
	var out []Finding
	for _, k := range sortedGroupKeys(windows) {
		w := windows[k]
		out = append(out, Finding{
			ID:       SigWasteDuplicateConcurrentQuery,
			Severity: SeverityMedium,
			Tool:     k.tool,
			Target:   k.target,
			Summary:  fmt.Sprintf("%s queried %s by %d overlapping calls", k.tool, k.target, len(w.corrIDs)),
			Evidence: map[string]any{
				"corrIDs": w.corrIDs,
				"start":   w.start,
				"end":     w.end,
			},
		})
	}
	return out
}

// detectSelfInflictedRateLimit fires when a rate-limit event lands inside a
// duplicate-concurrent overlap window for the same (tool,target): the throttle was
// self-inflicted by the tool racing itself, not an external budget limit. High
// severity - it is a code-side defect. One finding per (tool,target).
func detectSelfInflictedRateLimit(sd ScanData, _ Config) []Finding {
	windows := duplicateOverlaps(sd.Calls)
	if len(windows) == 0 {
		return nil
	}
	hits := map[groupKey][]time.Time{}
	for _, rl := range sd.RateLimits {
		if rl.Target == "" {
			continue
		}
		k := groupKey{tool: rl.Tool, target: rl.Target}
		w, ok := windows[k]
		if !ok {
			continue
		}
		if withinInclusive(rl.At, w.start, w.end) {
			hits[k] = append(hits[k], rl.At)
		}
	}
	var out []Finding
	for _, k := range sortedGroupKeys(hits) {
		w := windows[k]
		out = append(out, Finding{
			ID:       SigWasteSelfInflictedRateLimit,
			Severity: SeverityHigh,
			Tool:     k.tool,
			Target:   k.target,
			Summary:  fmt.Sprintf("%s hit a self-inflicted rate limit while double-querying %s", k.tool, k.target),
			Evidence: map[string]any{
				"corrIDs": w.corrIDs,
				"at":      hits[k],
			},
		})
	}
	return out
}

// minCallsForRate is the smallest number of available calls the failed-call-rate
// detector will judge, so a 1-of-1 or 2-of-2 small sample does not fire on noise.
const minCallsForRate = 3

// expectedAtWarnMinCount is the smallest number of curated-benign warns before the
// expected-outcome-at-warn detector fires, so a single stray warn does not.
const expectedAtWarnMinCount = 3

// degradationMarkers name the retry/backoff/degraded/gave-up edges of a struggling
// call, matched against event names for the degradation-storm detector.
var degradationMarkers = []string{"retry", "retrying", "backoff", "gave up", "giving up", "degraded"}

// detectExternalRateLimit fires for rate-limit events that are not self-inflicted by a
// duplicate-concurrent query: an external API-key or budget throttle, not a code
// defect. Low severity (informational). One finding per tool.
func detectExternalRateLimit(sd ScanData, _ Config) []Finding {
	windows := duplicateOverlaps(sd.Calls)
	type tally struct {
		count   int
		targets map[string]struct{}
	}
	perTool := map[string]*tally{}
	for _, rl := range sd.RateLimits {
		if isSelfInflictedRL(rl, windows) {
			continue
		}
		t := perTool[rl.Tool]
		if t == nil {
			t = &tally{targets: map[string]struct{}{}}
			perTool[rl.Tool] = t
		}
		t.count++
		if rl.Target != "" {
			t.targets[rl.Target] = struct{}{}
		}
	}
	var out []Finding
	for _, tool := range mapKeysSorted(perTool) {
		t := perTool[tool]
		out = append(out, Finding{
			ID: SigReliabilityExternalRateLimit, Severity: SeverityLow, Tool: tool,
			Summary:  fmt.Sprintf("%s hit %d external rate limit(s)", tool, t.count),
			Evidence: map[string]any{evCount: t.count, "targets": mapKeysSorted(t.targets)},
		})
	}
	return out
}

// isSelfInflictedRL reports whether a rate-limit event fell inside a
// duplicate-concurrent overlap window for its own (tool,target).
func isSelfInflictedRL(rl RateLimitEvent, windows map[groupKey]overlapWindow) bool {
	if rl.Target == "" {
		return false
	}
	w, ok := windows[groupKey{tool: rl.Tool, target: rl.Target}]
	if !ok {
		return false
	}
	return withinInclusive(rl.At, w.start, w.end)
}

// detectDegradationStorm fires when a tool burns many retry/backoff/degraded events
// or terminally gave up: a provider struggling to answer (the crtsh 502/degraded-empty
// storms). One finding per tool.
func detectDegradationStorm(sd ScanData, cfg Config) []Finding {
	var out []Finding
	for _, tool := range mapKeysSorted(sd.WarnErrorNames) {
		count, gaveUp, sample := 0, false, ""
		for _, name := range mapKeysSorted(sd.WarnErrorNames[tool]) {
			if !matchesAny(name, degradationMarkers) {
				continue
			}
			count += sd.WarnErrorNames[tool][name].Count
			if sample == "" {
				sample = name
			}
			lower := strings.ToLower(name)
			if strings.Contains(lower, "gave up") || strings.Contains(lower, "giving up") {
				gaveUp = true
			}
		}
		if count == 0 || (count < cfg.DegradationThreshold && !gaveUp) {
			continue
		}
		out = append(out, Finding{
			ID: SigReliabilityDegradationStorm, Severity: SeverityMedium, Tool: tool,
			Summary:  fmt.Sprintf("%s burned %d retry/degraded events", tool, count),
			Evidence: map[string]any{evCount: count, "gaveUp": gaveUp, evSampleName: sample},
		})
	}
	return out
}

// detectFailedCallRate fires when a tool's failed-call rate over its available calls
// (total minus provider-declined) is at or above the threshold, on a sample large
// enough to judge. One finding per tool.
func detectFailedCallRate(sd ScanData, cfg Config) []Finding {
	var out []Finding
	for _, tool := range mapKeysSorted(sd.Stats.Tools) {
		ts := sd.Stats.Tools[tool]
		avail := ts.Calls - ts.Unavailable
		if avail < minCallsForRate {
			continue
		}
		rate := float64(ts.FailedCalls) / float64(avail)
		if rate < cfg.FailedCallRateThreshold {
			continue
		}
		out = append(out, Finding{
			ID: SigReliabilityFailedCallRate, Severity: SeverityMedium, Tool: tool,
			Summary:  fmt.Sprintf("%s failed %d of %d available calls (%.0f%%)", tool, ts.FailedCalls, avail, rate*100),
			Evidence: map[string]any{"failed": ts.FailedCalls, "available": avail},
		})
	}
	return out
}

// detectOpaqueProviderError fires when a tool emits curated-name warn/error events
// that carry no concrete cause (a generic "reported N error(s)"): a diagnosability
// gap. Low severity. One finding per tool.
func detectOpaqueProviderError(sd ScanData, cfg Config) []Finding {
	var out []Finding
	for _, tool := range mapKeysSorted(sd.WarnErrorNames) {
		opaque, sample := 0, ""
		for _, name := range mapKeysSorted(sd.WarnErrorNames[tool]) {
			st := sd.WarnErrorNames[tool][name]
			if !matchesAny(name, cfg.OpaqueErrorNames) || st.Opaque == 0 {
				continue
			}
			opaque += st.Opaque
			if sample == "" {
				sample = name
			}
		}
		if opaque == 0 {
			continue
		}
		out = append(out, Finding{
			ID: SigDiagOpaqueProviderError, Severity: SeverityLow, Tool: tool,
			Summary:  fmt.Sprintf("%s logged %d opaque error(s) with no concrete cause", tool, opaque),
			Evidence: map[string]any{evCount: opaque, evSampleName: sample},
		})
	}
	return out
}

// detectExpectedOutcomeAtWarn fires when a tool's warns are dominated by curated-benign,
// expected outcomes (the dnsinfo zone-transfer refusals): warn-volume inflation, a
// hygiene issue. Low severity. One finding per tool.
func detectExpectedOutcomeAtWarn(sd ScanData, cfg Config) []Finding {
	var out []Finding
	for _, tool := range mapKeysSorted(sd.WarnErrorNames) {
		totalWarns, expected, sample := 0, 0, ""
		for _, name := range mapKeysSorted(sd.WarnErrorNames[tool]) {
			st := sd.WarnErrorNames[tool][name]
			if st.Level != "warn" {
				continue
			}
			totalWarns += st.Count
			if matchesAny(name, cfg.ExpectedAtWarnNames) {
				expected += st.Count
				if sample == "" {
					sample = name
				}
			}
		}
		if totalWarns == 0 || expected < expectedAtWarnMinCount {
			continue
		}
		share := float64(expected) / float64(totalWarns)
		if share < cfg.ExpectedWarnShareThreshold {
			continue
		}
		out = append(out, Finding{
			ID: SigHygieneExpectedOutcomeAtWarn, Severity: SeverityLow, Tool: tool,
			Summary:  fmt.Sprintf("%s logs %d of %d warns for expected benign outcomes (%.0f%%)", tool, expected, totalWarns, share*100),
			Evidence: map[string]any{"expected": expected, "totalWarns": totalWarns, evSampleName: sample},
		})
	}
	return out
}

// matchesAny reports whether name contains any of subs, case-insensitively.
func matchesAny(name string, subs []string) bool {
	lower := strings.ToLower(name)
	for _, s := range subs {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// groupKey identifies a (tool, target) pair for grouping calls and windows.
type groupKey struct {
	tool   string
	target string
}

// overlapWindow is the intersection of two or more overlapping call spans for one
// (tool,target): the window an event must fall in to be self-inflicted, and the set
// of colliding call ids.
type overlapWindow struct {
	start   time.Time
	end     time.Time
	corrIDs []string
}

// duplicateOverlaps groups target-bearing correlated calls by (tool,target) and, for
// any group with time-overlapping spans, returns the overlap window and the ids of
// every call in the group. Only groups that actually overlap are returned.
func duplicateOverlaps(calls []CallSpan) map[groupKey]overlapWindow {
	groups := map[groupKey][]CallSpan{}
	for _, c := range calls {
		if c.Target == "" || c.CorrID == "" {
			continue
		}
		k := groupKey{tool: c.Tool, target: c.Target}
		groups[k] = append(groups[k], c)
	}

	out := map[groupKey]overlapWindow{}
	for k, spans := range groups {
		if len(spans) < 2 {
			continue
		}
		if !anyOverlap(spans) {
			continue
		}
		start, end := intersection(spans)
		corrIDs := make([]string, 0, len(spans))
		for _, s := range spans {
			corrIDs = append(corrIDs, s.CorrID)
		}
		sort.Strings(corrIDs)
		out[k] = overlapWindow{start: start, end: end, corrIDs: corrIDs}
	}
	return out
}

// anyOverlap reports whether any two spans in the group overlap in time (inclusive).
func anyOverlap(spans []CallSpan) bool {
	for i := range spans {
		for j := i + 1; j < len(spans); j++ {
			if !spans[i].First.After(spans[j].Last) && !spans[j].First.After(spans[i].Last) {
				return true
			}
		}
	}
	return false
}

// intersection returns the common overlap window across the group: the latest start
// and the earliest end. When spans are staggered this can be empty (start > end);
// callers only use it to test rate-limit membership, and a racing double-query (the
// grounded case) has a real, non-empty intersection.
func intersection(spans []CallSpan) (start, end time.Time) {
	start = spans[0].First
	end = spans[0].Last
	for _, s := range spans[1:] {
		if s.First.After(start) {
			start = s.First
		}
		if s.Last.Before(end) {
			end = s.Last
		}
	}
	return start, end
}

// withinInclusive reports whether t is in [start, end].
func withinInclusive(t, start, end time.Time) bool {
	return !t.Before(start) && !t.After(end)
}

// sortedGroupKeys returns a group map's keys in (tool, target) order.
func sortedGroupKeys[V any](m map[groupKey]V) []groupKey {
	keys := make([]groupKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tool != keys[j].tool {
			return keys[i].tool < keys[j].tool
		}
		return keys[i].target < keys[j].target
	})
	return keys
}

// mapKeysSorted returns the keys of a string-keyed map in sorted order, for
// deterministic iteration over the fold's per-tool and per-name aggregates.
func mapKeysSorted[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
