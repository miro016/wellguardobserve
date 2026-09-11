package toolsignals

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// maxLineBytes bounds a single envelope line, matching tooleventlog's reader: error
// events embed raw response bodies, so the scanner buffer is raised past the default.
const maxLineBytes = 8 * 1024 * 1024

// LoadStatus records how cleanly a scan's tool-event log was folded.
type LoadStatus string

const (
	// LoadOK means the whole log decoded without error.
	LoadOK LoadStatus = "ok"
	// LoadIntegrityFlagged means a line failed to decode; the fold stopped there and
	// the scan carries a log-integrity/decode signal. Its counts are partial.
	LoadIntegrityFlagged LoadStatus = "integrity-flagged"
)

// ScanData is one scan's folded tool-event state: everything the detectors read,
// built in a single streaming pass (Fold) or by hand in a test. It holds only the
// aggregates the detectors need; raw envelopes are not retained.
type ScanData struct {
	// Label is the human-meaningful scan name (the scan directory's base name).
	Label string
	// ScanID is the id read from the first envelope, joining back to the domain-event
	// stream. Empty for a log whose envelopes carry none.
	ScanID string
	// Status is the load outcome (ok or integrity-flagged).
	Status LoadStatus
	// EarliestAt is the earliest envelope timestamp, the corpus-ordering key.
	EarliestAt time.Time
	// Events is the number of envelopes folded.
	Events int

	// Stats is the reused per-tool operational rollup (from tooleventlog.ReplayTooling),
	// attached by the caller after a clean fold. Zero-valued when the log was
	// integrity-flagged (a corrupt log is not replayed).
	Stats tooleventlog.ToolingStats

	// SchemaVersions counts the distinct envelope Version values seen.
	SchemaVersions map[int]int
	// SeqMin and SeqMax are the smallest and largest per-scan sequence numbers seen.
	// Because seq is globally unique and assigned 1..N, a healthy log is a gap-free,
	// duplicate-free set iff SeqMin==1 and SeqMax==Events. That set check is robust to
	// the concurrent-write reordering that leaves the file not sorted by seq, unlike a
	// naive adjacent-in-file-order check.
	SeqMin int64
	SeqMax int64
	// MissingCorr summarizes call-boundary events lacking a CorrID or Phase, nil when
	// none.
	MissingCorr *MissingCorr
	// Decode is the first decode failure, nil when the log is clean.
	Decode *DecodeError

	// Attribution is the per-tool target-attribution tally.
	Attribution map[string]*ToolAttribution
	// Calls is one span per correlated call (CorrID), sorted by (tool, target, first).
	Calls []CallSpan
	// UDPPasses is one entry per correlated UDP portscan pass, sorted by
	// (target, corrID). The UDP pass gets its own correlation id and its own target
	// form, so it is a separate call from the TCP pass on the same host and the
	// duplicate-concurrent-query detector never sees the two as one call reported
	// twice. Empty for a capture whose profile did not enable the UDP pass.
	UDPPasses []UDPPass
	// RateLimits is every rate-limit event, in stream order.
	RateLimits []RateLimitEvent
	// WarnErrorNames tallies warn/error events per tool and event name, with the
	// opaque subset (no concrete error detail). The reliability, diagnosability, and
	// hygiene detectors read policy-free tallies here and apply their curated lists and
	// thresholds themselves, so the fold carries no configuration.
	WarnErrorNames map[string]map[string]*NameStat
}

// NameStat tallies one (tool, event name) at warn or error level.
type NameStat struct {
	// Name is the event name.
	Name string `json:"name"`
	// Level is the rendered level ("warn" or "error").
	Level string `json:"level"`
	// Count is how many events of this name the tool emitted.
	Count int `json:"count"`
	// Opaque is the subset of Count whose attributes carry no concrete error detail: a
	// missing error/message, or a generic "reported N error(s)" with no cause.
	Opaque int `json:"opaque"`
}

// MissingCorr summarizes correlated-looking events (a call's started/completed
// boundary) that carry no CorrID or Phase, so a finding cannot be joined back to its
// call.
type MissingCorr struct {
	Count      int    `json:"count"`
	SampleTool string `json:"sampleTool"`
	SampleName string `json:"sampleName"`
}

// DecodeError records the first line that failed to decode.
type DecodeError struct {
	Line int    `json:"line"`
	Err  string `json:"err"`
}

// ToolAttribution tallies how one tool attributes its events to a target.
type ToolAttribution struct {
	// Empty is the count of events with an empty Target.
	Empty int `json:"empty"`
	// NonEmpty is the count of events carrying a Target.
	NonEmpty int `json:"nonEmpty"`
	// SampleNames holds up to a few distinct event names seen with an empty target.
	SampleNames []string `json:"sampleNames,omitempty"`
}

// total is the tool's folded event count.
func (a *ToolAttribution) total() int { return a.Empty + a.NonEmpty }

// targetedRatio is the fraction of the tool's events carrying a target, 0 when it
// emitted nothing.
func (a *ToolAttribution) targetedRatio() float64 {
	if a.total() == 0 {
		return 0
	}
	return float64(a.NonEmpty) / float64(a.total())
}

// CallSpan is one correlated tool invocation's time bounds and identity, folded from
// the envelopes sharing a CorrID.
type CallSpan struct {
	Tool   string    `json:"tool"`
	Target string    `json:"target"`
	CorrID string    `json:"corrID"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
}

// RateLimitEvent is one rate-limit-class event, kept to test whether it fell inside a
// self-inflicted duplicate-query window.
type RateLimitEvent struct {
	Tool   string    `json:"tool"`
	Target string    `json:"target"`
	Name   string    `json:"name"`
	At     time.Time `json:"at"`
}

// Fold streams one scan's tool-event log from r into a ScanData, decoding line by
// line so memory stays bounded. A decode failure is not a hard error: the first bad
// line is recorded (surfacing later as a log-integrity/decode signal), the status is
// flagged, and the fold stops - the rest of the corpus still analyzes. A read error
// (not a decode error) is returned.
func Fold(label string, r io.Reader) (ScanData, error) {
	sd := ScanData{
		Label:          label,
		Status:         LoadOK,
		SchemaVersions: map[int]int{},
		Attribution:    map[string]*ToolAttribution{},
		WarnErrorNames: map[string]map[string]*NameStat{},
	}
	calls := map[string]*CallSpan{}
	udpPasses := map[string]*UDPPass{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lineNo := 0
	haveSeq := false

	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		env, err := tooleventlog.DecodeEnvelope(line)
		if err != nil {
			sd.Decode = &DecodeError{Line: lineNo, Err: err.Error()}
			sd.Status = LoadIntegrityFlagged
			break
		}

		sd.Events++
		if sd.ScanID == "" && env.ScanID != "" {
			sd.ScanID = env.ScanID
		}
		if sd.EarliestAt.IsZero() || env.At.Before(sd.EarliestAt) {
			sd.EarliestAt = env.At
		}
		sd.SchemaVersions[env.Version]++

		if !haveSeq || env.Seq < sd.SeqMin {
			sd.SeqMin = env.Seq
		}
		if env.Seq > sd.SeqMax {
			sd.SeqMax = env.Seq
		}
		haveSeq = true

		foldAttribution(&sd, &env)
		foldMissingCorr(&sd, &env)
		foldCall(calls, &env)
		foldUDPPass(udpPasses, &env)
		foldRateLimit(&sd, &env)
		foldWarnError(&sd, &env)
	}
	if err := scanner.Err(); err != nil {
		return sd, fmt.Errorf("read tooling log: %w", err)
	}

	sd.Calls = sortedCalls(calls)
	sd.UDPPasses = sortedUDPPasses(udpPasses)
	return sd, nil
}

// foldAttribution records one envelope's contribution to its tool's target tally.
func foldAttribution(sd *ScanData, env *tooleventlog.ToolEventEnvelope) {
	a := sd.Attribution[env.Tool]
	if a == nil {
		a = &ToolAttribution{}
		sd.Attribution[env.Tool] = a
	}
	if env.Target == "" {
		a.Empty++
		if len(a.SampleNames) < 3 && !containsString(a.SampleNames, env.Name) {
			a.SampleNames = append(a.SampleNames, env.Name)
		}
		return
	}
	a.NonEmpty++
}

// foldMissingCorr counts call-boundary events (a call's started/completed/succeeded
// edge) that carry no CorrID or Phase, so they cannot be joined to their call.
func foldMissingCorr(sd *ScanData, env *tooleventlog.ToolEventEnvelope) {
	if !isCallBoundary(env.Name) {
		return
	}
	if env.CorrID != "" && env.Phase != "" {
		return
	}
	if sd.MissingCorr == nil {
		sd.MissingCorr = &MissingCorr{SampleTool: env.Tool, SampleName: env.Name}
	}
	sd.MissingCorr.Count++
}

// foldCall extends the span of the correlated call an envelope belongs to.
// Uncorrelated envelopes (no CorrID) contribute no span.
func foldCall(calls map[string]*CallSpan, env *tooleventlog.ToolEventEnvelope) {
	if env.CorrID == "" {
		return
	}
	c := calls[env.CorrID]
	if c == nil {
		c = &CallSpan{Tool: env.Tool, Target: env.Target, CorrID: env.CorrID, First: env.At, Last: env.At}
		calls[env.CorrID] = c
		return
	}
	if c.Target == "" && env.Target != "" {
		c.Target = env.Target
	}
	if env.At.Before(c.First) {
		c.First = env.At
	}
	if env.At.After(c.Last) {
		c.Last = env.At
	}
}

// foldRateLimit records a rate-limit-class event for the self-inflicted-429 check.
func foldRateLimit(sd *ScanData, env *tooleventlog.ToolEventEnvelope) {
	if !isRateLimited(env.Name) {
		return
	}
	sd.RateLimits = append(sd.RateLimits, RateLimitEvent{
		Tool: env.Tool, Target: env.Target, Name: env.Name, At: env.At,
	})
}

// foldWarnError tallies a warn/error event under its tool and name, tracking the
// opaque subset. It is policy-free: which names matter is decided by the detectors.
func foldWarnError(sd *ScanData, env *tooleventlog.ToolEventEnvelope) {
	if env.Level != "warn" && env.Level != "error" {
		return
	}
	byName := sd.WarnErrorNames[env.Tool]
	if byName == nil {
		byName = map[string]*NameStat{}
		sd.WarnErrorNames[env.Tool] = byName
	}
	st := byName[env.Name]
	if st == nil {
		st = &NameStat{Name: env.Name, Level: env.Level}
		byName[env.Name] = st
	}
	st.Count++
	if isOpaqueError(env.Attrs) {
		st.Opaque++
	}
}

// isOpaqueError reports whether an event's attributes carry no actionable error
// detail: no error/message string at all, or a generic "reported N error(s)" that
// names a count but no concrete cause.
func isOpaqueError(attrs map[string]any) bool {
	msg := stringAttr(attrs, "error")
	if msg == "" {
		msg = stringAttr(attrs, "message")
	}
	if msg == "" {
		return true
	}
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "reported") && strings.Contains(lower, "error(s)")
}

// stringAttr returns the string value of attrs[key], or "" when absent or not a
// non-empty string.
func stringAttr(attrs map[string]any, key string) string {
	if s, ok := attrs[key].(string); ok {
		return s
	}
	return ""
}

// callBoundaryMarkers name the edges of a correlated call: a started or a finished
// event. An event matching one of these is expected to carry correlation.
var callBoundaryMarkers = []string{"started", "completed", "succeeded"}

// isCallBoundary reports whether an event name marks the start or end of a call.
func isCallBoundary(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range callBoundaryMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// isRateLimited reports whether an event name marks a provider rate-limit hit,
// matching tooleventlog's classification.
func isRateLimited(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "rate limit") || strings.Contains(lower, "ratelimit")
}

// sortedCalls flattens the per-CorrID spans into a deterministically ordered slice.
func sortedCalls(calls map[string]*CallSpan) []CallSpan {
	out := make([]CallSpan, 0, len(calls))
	for _, c := range calls {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if !out[i].First.Equal(out[j].First) {
			return out[i].First.Before(out[j].First)
		}
		return out[i].CorrID < out[j].CorrID
	})
	return out
}

// containsString reports whether s is in xs.
func containsString(xs []string, s string) bool {
	return slices.Contains(xs, s)
}
