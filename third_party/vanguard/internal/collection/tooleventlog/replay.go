package tooleventlog

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
)

// maxToolingLineBytes bounds a single envelope line. Error events embed raw
// response bodies, so the scanner buffer is raised well past the default.
const maxToolingLineBytes = 8 * 1024 * 1024

// countAttrKeys are the attribute keys, in priority order, that carry the result
// count on a tool's completion event. The first present key decides whether a
// successful call returned nothing (an empty result). "matches" is wappalyzer's
// per-run match count, so a clean run that fingerprinted nothing reads as empty.
var countAttrKeys = []string{
	"hits", "count", "results", "subdomains", "records", "found", "hosts",
	"assets", "ports", "certificates", "matches",
}

// connectivityCountKeys are completion-event counts from active probes where an
// all-zero value means the probe connected to nothing - a failed call, even though
// its connection errors were logged at warn, not error. A port scan that found no
// open port (open), an https probe that negotiated no TLS version (supported_tls),
// an smtp probe where no MX offered STARTTLS (starttls_hosts), an http sweep that
// surfaced no endpoint (endpoints), a webinfo or httpprobe run where no fetch
// completed (successful_fetches, successful_probes).
//
// The last two matter more than they look. classifyCompletion treats a completion
// with no recognised count as productive - the right default for a whois or asn
// lookup that simply succeeded - which means a tool whose counts are not listed here
// scores as perfectly reliable no matter how often it fails. Any active probe that
// reports how many of its fetches succeeded belongs on this list, or its failures are
// invisible to the reliability term.
var connectivityCountKeys = []string{
	"open", "supported_tls", "starttls_hosts", "endpoints",
	"successful_fetches", "successful_probes",
}

// coverageCountKey is the completion-event attribute that says how much of the
// requested work a pass actually accounted for, rather than how much it found.
//
// It exists because "found nothing" and "reached nothing" are the same number for
// most probes but not for all of them. A UDP pass returns a verdict for every port
// it probed - open, silent, refused, or filtered - and only the first is a
// service, so its open count is zero on most healthy hosts. Reading that as an
// all-zero connectivity count would make every quiet host a failed call and every
// honest UDP scan look like a broken scanner. A completion that reports its
// coverage is therefore judged on that instead: it accounted for its ports, so the
// call worked, whatever the ports turned out to be.
const coverageCountKey = "accounted"

// partialCompletionKey is the completion-event attribute a pass sets when it
// returned real evidence and then failed before finishing. Such a call is not a
// success: it kept what it found, and it lost the rest. Without this the
// evidence would outrank the loss - a productive completion is the highest
// precedence outcome a call can have - and a pass that covered half its ports
// would be indistinguishable from one that covered them all.
const partialCompletionKey = "partial"

// resultCountKeys are completion-event counts from passive searches where an
// all-zero value is a clean empty result, NOT a failure: the provider answered, the
// target simply has no such data (a web search with no dork hits, a CT search with
// no certs, a VirusTotal not-found, a fingerprint run that matched nothing). These do not
// count against reliability.
var resultCountKeys = []string{
	"hits", "count", "results", "subdomains", "records", "found", "hosts",
	"assets", "ports", "certificates", "certs", "matches",
}

// ToolStats is the per-tool operational rollup folded from the tool-event log. It
// is the operational-quality half of the data-quality report: how much a
// provider did, how reliably, and how fast.
type ToolStats struct {
	// Tool is the tool identifier.
	Tool string
	// Total is the number of events the tool emitted.
	Total int
	// ByLevel counts events by rendered level (debug/info/warn/error).
	ByLevel map[string]int
	// ErrorCategories counts warn/error events by category (network, http_status,
	// parse, rate_limit, paid_plan, other), classified from the event name.
	ErrorCategories map[string]int
	// RateLimited counts events that report a provider rate-limit hit.
	RateLimited int
	// Empties counts successful calls that returned zero results.
	Empties int
	// Calls is the number of distinct correlated tool invocations (by CorrID) seen
	// for this tool; the denominator for empty-rate and latency.
	Calls int
	// FailedCalls is the number of correlated calls that genuinely failed: a call
	// that emitted a transport/protocol failure, or an active probe whose completion
	// connected to nothing (an all-zero connectivity count), and never had a
	// productive completion. A passive search that completed cleanly with zero
	// results (an empty-but-valid call) is NOT counted here, nor is a call the
	// provider declined (see Unavailable). It is the numerator of the reliability
	// term and captures active probes whose connection failures are warns, not errors.
	FailedCalls int
	// Unavailable is the number of correlated calls the provider declined to serve
	// rather than failing in transit: a free key hitting a paid endpoint, a
	// membership/subscription wall, an auth refusal, or a rate-limit throttle. These
	// are excluded from both FailedCalls and the reliability denominator, so an
	// unavailable provider reads as "n/a" rather than 0% reliable.
	Unavailable int
	// TotalLatency is the summed duration of the correlated calls (first to last
	// event per CorrID); divide by Calls for the mean.
	TotalLatency time.Duration
	// latencies holds the per-call durations, kept for the median.
	latencies []time.Duration
}

// MedianLatency returns the median correlated-call duration, or 0 when no call
// had a measurable span. It sorts a copy so the read model stays immutable.
func (t *ToolStats) MedianLatency() time.Duration {
	if len(t.latencies) == 0 {
		return 0
	}
	d := append([]time.Duration(nil), t.latencies...)
	slices.Sort(d)
	mid := len(d) / 2
	if len(d)%2 == 1 {
		return d[mid]
	}
	return (d[mid-1] + d[mid]) / 2
}

// ToolingStats is the read model reconstructed from the tool-event log alone: a
// per-tool rollup keyed by tool name, plus the total envelope count. It is
// driven only by the persisted stream so it is reconstructable offline.
type ToolingStats struct {
	// Tools maps tool name to its rollup.
	Tools map[string]*ToolStats
	// Total is the number of envelopes folded.
	Total int
}

// callSpan tracks one correlated tool invocation: its time bounds (for latency)
// and its outcome flags (for the failed-call count), folded once the whole stream
// has been read.
type callSpan struct {
	tool  string
	first time.Time
	last  time.Time
	// hadFailure is set by an error event or a warn whose name marks a failed step.
	hadFailure bool
	// hadProductiveCompletion is set by a completion whose result counts were not
	// all zero (or carried no recognised count, so productivity cannot be denied).
	hadProductiveCompletion bool
	// hadConnectivityFailure is set by an active-probe completion whose connectivity
	// counts were all zero - the probe finished but connected to nothing. Counts as
	// a failure.
	hadConnectivityFailure bool
	// hadEmptyValid is set by a passive-search completion whose result counts were
	// all zero - the provider answered cleanly, the target just has no such data. NOT
	// a failure.
	hadEmptyValid bool
	// hadUnavailable is set when the provider declined to serve (paid plan, auth
	// refusal, membership wall, or rate-limit). Excluded from failed and from the
	// reliability denominator.
	hadUnavailable bool
}

// failed reports whether the call genuinely failed: it never had a productive
// completion and either emitted a transport/protocol failure or an active-probe
// completion that connected to nothing. An empty-but-valid passive result is not a
// failure, and an unavailable call is resolved separately (see foldLatencies). A
// silent call (no completion and no failure) is not counted as failed.
func (s *callSpan) failed() bool {
	return !s.hadProductiveCompletion && (s.hadFailure || s.hadConnectivityFailure)
}

// ReplayTooling folds a persisted tool-event stream into a fresh ToolingStats. It
// runs no tools: every counter is reconstructed from the persisted envelopes,
// proving the stream is replayable like the domain log.
//
// It takes a reader rather than a directory because this package owns the envelope
// format and the fold over it, not where the bytes live. Opening the stream is the
// business of whoever knows the layout - internal/collection/persistence for a
// collection on disk.
func ReplayTooling(r io.Reader) (ToolingStats, error) {
	stats := ToolingStats{Tools: make(map[string]*ToolStats)}
	spans := make(map[string]*callSpan)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxToolingLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		env, err := DecodeEnvelope(line)
		if err != nil {
			return stats, fmt.Errorf("decode tool event: %w", err)
		}
		stats.apply(&env)
		trackSpan(spans, &env)
	}
	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read tooling log: %w", err)
	}
	stats.foldLatencies(spans)
	return stats, nil
}

// apply folds a single envelope into the read model.
func (s *ToolingStats) apply(env *ToolEventEnvelope) {
	s.Total++
	ts, ok := s.Tools[env.Tool]
	if !ok {
		ts = &ToolStats{Tool: env.Tool, ByLevel: make(map[string]int), ErrorCategories: make(map[string]int)}
		s.Tools[env.Tool] = ts
	}
	ts.Total++
	ts.ByLevel[env.Level]++

	lower := strings.ToLower(env.Name)
	if strings.Contains(lower, "rate limit") || strings.Contains(lower, "ratelimit") {
		ts.RateLimited++
	}
	if env.Level == levelWarn || env.Level == levelError {
		ts.ErrorCategories[classifyError(lower)]++
	}
	if isEmptyResult(env) {
		ts.Empties++
	}
}

// trackSpan extends the time bounds of the call a correlated envelope belongs to
// and folds the envelope's outcome into the span. Uncorrelated envelopes (no
// CorrID) contribute no latency and no outcome.
func trackSpan(spans map[string]*callSpan, env *ToolEventEnvelope) {
	if env.CorrID == "" {
		return
	}
	sp, ok := spans[env.CorrID]
	if !ok {
		sp = &callSpan{tool: env.Tool, first: env.At, last: env.At}
		spans[env.CorrID] = sp
	}
	if env.At.Before(sp.first) {
		sp.first = env.At
	}
	if env.At.After(sp.last) {
		sp.last = env.At
	}
	foldOutcome(sp, env)
}

// foldOutcome records one envelope's contribution to its call's outcome.
func foldOutcome(sp *callSpan, env *ToolEventEnvelope) {
	name := strings.ToLower(env.Name)
	if (env.Level == levelWarn || env.Level == levelError) && unavailableSignal(env, name) {
		sp.hadUnavailable = true
	}
	if env.Level == levelError || (env.Level == levelWarn && strings.Contains(name, "failed")) {
		sp.hadFailure = true
	}
	if !strings.Contains(name, "succeeded") && !strings.Contains(name, "completed") {
		return
	}
	switch classifyCompletion(env) {
	case completionProductive:
		sp.hadProductiveCompletion = true
	case completionEmptyValid:
		sp.hadEmptyValid = true
	case completionConnectivityFailed:
		sp.hadConnectivityFailure = true
	}
}

// completionOutcome classifies a completion event's result counts.
type completionOutcome int

const (
	// completionProductive: at least one recognised count is non-zero, or the event
	// carries no recognised count (a whois/asn/dns-style success).
	completionProductive completionOutcome = iota
	// completionEmptyValid: every passive-search result count present is zero - the
	// provider answered cleanly, the target has no such data. Not a failure.
	completionEmptyValid
	// completionConnectivityFailed: every active-probe connectivity count present is
	// zero - the probe connected to nothing. A failure.
	completionConnectivityFailed
)

// classifyCompletion buckets a completion event by its recognised result counts.
// Active-probe connectivity counts take precedence: an all-zero connectivity count
// means the probe reached nothing (failed), while an all-zero passive-search result
// count is a clean empty result (valid). A completion with no recognised count is
// productive by default (whois/asn lookups that simply succeeded, or a retry that
// eventually returned).
func classifyCompletion(env *ToolEventEnvelope) completionOutcome {
	// A completion that declares itself partial has already answered the question:
	// the call did not finish the work it was asked to do, whatever it managed to
	// return on the way.
	if partial, ok := env.Attrs[partialCompletionKey].(bool); ok && partial {
		return completionConnectivityFailed
	}
	// Coverage takes precedence over every result count: a pass that says how much
	// of its requested work it settled has already answered whether the call
	// worked. Zero coverage is a call that settled nothing, which is a failure
	// however the rest of the event reads.
	if saw, positive := scanCounts(env, []string{coverageCountKey}); saw {
		if !positive {
			return completionConnectivityFailed
		}
		// It covered its work. Whether it found anything is a fact about the target:
		// a pass with confirmed results is productive, one with none is a clean
		// empty, and neither is a scanner failure.
		if _, confirmed := scanCounts(env, connectivityCountKeys); confirmed {
			return completionProductive
		}
		return completionEmptyValid
	}
	if saw, positive := scanCounts(env, connectivityCountKeys); saw {
		if positive {
			return completionProductive
		}
		return completionConnectivityFailed
	}
	if saw, positive := scanCounts(env, resultCountKeys); saw {
		if positive {
			return completionProductive
		}
		return completionEmptyValid
	}
	return completionProductive
}

// scanCounts reports whether env carries any of keys (saw) and whether any present
// key is greater than zero (positive).
func scanCounts(env *ToolEventEnvelope, keys []string) (saw, positive bool) {
	for _, k := range keys {
		v, ok := env.Attrs[k]
		if !ok {
			continue
		}
		saw = true
		if toInt64(v) > 0 {
			positive = true
		}
	}
	return saw, positive
}

// unavailableMarkers identify a provider declining to serve (rather than failing in
// transit): a free key hitting a paid endpoint, a membership/subscription wall, an
// auth refusal, or a rate-limit throttle. They are matched against the event name
// and its error detail, because some providers carry the signal in a dedicated
// event name (censys "paid plan required") and others fold it into a generic
// failure's error text (shodan "Requires membership").
var unavailableMarkers = []string{
	"paid plan", "membership", "subscription", "payment required",
	"unauthorized", "forbidden", "access denied", "rate limit", "ratelimit",
	"quota",
}

// unavailableSignal reports whether a warn/error envelope means the provider
// declined to serve. lowerName is env.Name already lowercased.
func unavailableSignal(env *ToolEventEnvelope, lowerName string) bool {
	if containsAny(lowerName, unavailableMarkers) {
		return true
	}
	if msg, ok := env.Attrs["error"].(string); ok {
		return containsAny(strings.ToLower(msg), unavailableMarkers)
	}
	return false
}

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// foldLatencies assigns each correlated call's duration to its tool, after the
// whole stream has been read so a call's first and last events are both known.
func (s *ToolingStats) foldLatencies(spans map[string]*callSpan) {
	for _, sp := range spans {
		ts, ok := s.Tools[sp.tool]
		if !ok {
			continue
		}
		ts.Calls++
		// Resolve the call's outcome once, precedence highest first: a productive
		// completion is a success; otherwise an unavailable provider is excluded from
		// reliability; otherwise a genuine failure counts against reliability. An
		// empty-but-valid passive result falls through all three (a clean, available,
		// non-failing call).
		switch {
		case sp.hadProductiveCompletion:
		case sp.hadUnavailable:
			ts.Unavailable++
		case sp.failed():
			ts.FailedCalls++
		}
		dur := sp.last.Sub(sp.first)
		ts.TotalLatency += dur
		ts.latencies = append(ts.latencies, dur)
	}
}

// classifyError buckets a warn/error event name into a coarse category, so a
// provider's failure profile (transport vs protocol vs quota) is visible at a
// glance. The name is already lowercased.
func classifyError(name string) string {
	switch {
	case strings.Contains(name, "rate limit") || strings.Contains(name, "ratelimit"):
		return "rate_limit"
	case strings.Contains(name, "paid plan"):
		return "paid_plan"
	case strings.Contains(name, "network"):
		return "network"
	case strings.Contains(name, "status"):
		return "http_status"
	case strings.Contains(name, "json") || strings.Contains(name, "parse"):
		return "parse"
	default:
		return "other"
	}
}

// isEmptyResult reports whether env is a successful completion event that returned
// zero results, read from the first present count attribute. It is best-effort:
// tools name their completion events "... succeeded" / "... completed" and carry a
// numeric count attr (for example censys "hits").
//
// A completion flagged degraded is never an empty result. "Empty" is a statement
// about the target - the call worked and the target has nothing - so a call that
// reached nothing must not be filed under it, or a tool that failed on every target
// would read as a tool whose targets were all uninteresting.
func isEmptyResult(env *ToolEventEnvelope) bool {
	name := strings.ToLower(env.Name)
	if !strings.Contains(name, "succeeded") && !strings.Contains(name, "completed") {
		return false
	}
	if degraded, ok := env.Attrs["degraded"].(bool); ok && degraded {
		return false
	}
	for _, k := range countAttrKeys {
		if v, ok := env.Attrs[k]; ok {
			return toInt64(v) == 0
		}
	}
	return false
}

// toInt64 coerces a flattened attr value to int64; JSON decoding yields float64,
// while a freshly built envelope yields int64.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	default:
		return -1
	}
}

// Summary renders a compact, deterministic one-line-per-tool rollup of the
// tool-event log, sorted by tool name, for the CLI replay output.
func (s *ToolingStats) Summary() string {
	if s.Total == 0 {
		return "no tool events\n"
	}
	tools := make([]string, 0, len(s.Tools))
	for name := range s.Tools {
		tools = append(tools, name)
	}
	sort.Strings(tools)

	var b strings.Builder
	fmt.Fprintf(&b, "Tool events: %d total across %d tools\n", s.Total, len(s.Tools))
	for _, name := range tools {
		ts := s.Tools[name]
		fmt.Fprintf(&b, "  %-12s %d (errors=%d warns=%d ratelimited=%d empties=%d calls=%d failed=%d unavailable=%d median=%s)\n",
			name, ts.Total, ts.ByLevel["error"], ts.ByLevel["warn"],
			ts.RateLimited, ts.Empties, ts.Calls, ts.FailedCalls, ts.Unavailable, ts.MedianLatency())
	}
	return b.String()
}
