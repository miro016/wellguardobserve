package persistence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/config"
	"github.com/velgard-sk/vanguard/internal/collection/events"
	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/projections/netaudit"
)

// bindSlack absorbs clock/scheduling skew when deciding whether a capture overlaps
// the collection: a capture started a few seconds before the first scan event, or
// stopped a few seconds after the last, still belongs to it.
const bindSlack = 30 * time.Second

// buildNetAudit assembles both the immutable network-audit report model and the
// decoded raw investigation capture for a finished collection directory, in one pass
// over the capture, the manifest, the engagement snapshot, the exclusion issue rows
// in evts, and the tool event log. It performs all filesystem I/O here so the pure
// netaudit analyzer and the report stay deterministic functions of an explicit
// input, and so the report section and the netaudit/ artifacts at the projection
// destination always describe the same evidence.
//
// A missing manifest, missing capture, unreadable file, or parse failure is model
// data, not an error, so this never fails: the returned values always describe the
// collection.
func buildNetAudit(dataPath string, evts []events.DomainEvent) (*netaudit.Model, netaudit.RawCapture) {
	w := collectionWindow(dataPath, evts)
	spans, spanErr := loadToolSpans(dataPath)

	var notes []string
	if spanErr != nil {
		notes = append(notes, fmt.Sprintf("tool-event spans could not be read: %v", spanErr))
	}

	in := netaudit.CaptureInput{
		Started:         w.started,
		Completed:       w.completed,
		ActiveRan:       w.activeRan,
		ExclusionIssues: exclusionIssues(evts, w),
		ToolSpans:       spansInWindow(spans, w),
	}
	eng := loadEngagement(dataPath, w.engagement)
	if eng != nil {
		in.DomainRules = eng.ExcludedDomains()
		in.CIDRRules = eng.ExcludedIPPrefixes()
	}
	in.Capture = discoverCapture(dataPath, w, eng != nil)

	audit := netaudit.AssessCapture(in)
	model := netaudit.BuildModel(audit, notes)
	return &model, netaudit.BuildRaw(audit.Health.Status, in.Capture)
}

// writeNetAuditProjection writes the decoded raw network-audit investigation files
// into the destination's netaudit/ bucket. They are rebuildable from the immutable
// packet evidence in the collection, so they are rewritten whole on every build. A
// write failure is returned so the caller can surface it.
func writeNetAuditProjection(dst string, raw netaudit.RawCapture) error {
	jsonl, err := netaudit.RawJSONL(raw)
	if err != nil {
		return fmt.Errorf("render %s: %w", netauditRawJSONL, err)
	}
	if err := writeFile(dst, netauditBucket, netauditSummaryMD, []byte(netaudit.SummaryMarkdown(raw))); err != nil {
		return err
	}
	return writeFile(dst, netauditBucket, netauditRawJSONL, jsonl)
}

// collectionSpan is the collection's binding facts, from the manifest or synthesized
// from the event stream when no manifest can be read.
type collectionSpan struct {
	started   time.Time
	completed time.Time
	activeRan bool
	// engagement is the collection-relative, slash-form engagement snapshot the
	// manifest recorded, or "" for a synthesized span.
	engagement string
}

// collectionWindow returns the collection's span: the manifest's own bracket when it
// can be read, or the extent of the event stream when it cannot.
//
// A failed, interrupted, or still-running collection gets a span too: it ran, so it
// may have produced a capture, and a capture nobody assesses is evidence quietly
// dropped. A collection with no recorded completion is closed at the end of the
// event stream so its span is bounded.
func collectionWindow(dataPath string, evts []events.DomainEvent) collectionSpan {
	start, end, active := streamWindow(evts)
	manifest, ok, err := collection.LoadManifest(dataPath)
	if err != nil || !ok {
		return collectionSpan{started: start, completed: end, activeRan: active}
	}
	completed := manifest.CompletedAt
	if completed.IsZero() {
		completed = end
	}
	return collectionSpan{
		started:    manifest.StartedAt,
		completed:  completed,
		activeRan:  phasesRanActive(manifest.Phases),
		engagement: manifest.Engagement,
	}
}

// streamWindow returns the first and last event instants and whether the stream
// contains any target-facing active or exploit work.
func streamWindow(evts []events.DomainEvent) (start, end time.Time, active bool) {
	for _, evt := range evts {
		at := evt.At()
		if start.IsZero() || at.Before(start) {
			start = at
		}
		if at.After(end) {
			end = at
		}
		if evt.Meta().Phase == events.PhaseActive {
			active = true
		}
	}
	return start, end, active
}

// phasesRanActive reports whether the collection's phase set included any
// target-facing active work, so a loopback-only capture is judged partial rather
// than complete.
func phasesRanActive(phases []string) bool {
	for _, p := range phases {
		lp := strings.ToLower(p)
		if strings.Contains(lp, "active") || strings.Contains(lp, "exploit") ||
			strings.Contains(lp, "port") || strings.Contains(lp, "http") ||
			strings.Contains(lp, "web") {
			return true
		}
	}
	return false
}

// loadEngagement loads the engagement the collection ran with. It prefers the
// snapshot path the manifest recorded - the manifest is the authority on which file
// belongs to the run, so the name is never rebuilt here - and falls back to the
// engagement.yaml the collection writes when the span was synthesized from a
// directory with no readable manifest. A load failure returns nil: the capture is
// then assessed with no rules rather than aborting.
func loadEngagement(dataPath, engagementRel string) *config.EngagementConfig {
	var candidates []string
	if engagementRel != "" {
		candidates = append(candidates, filepath.Join(dataPath, filepath.FromSlash(engagementRel)))
	}
	candidates = append(candidates, collection.EngagementSnapshotPath(dataPath))
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		eng, err := config.LoadEngagement(path)
		if err != nil {
			continue
		}
		return &eng
	}
	return nil
}

// discoverCapture finds the collection's capture, hashes it, reads its meta
// sidecar, and streams it into observations. A missing capture returns nil
// (absent); an unreadable one returns a non-nil source with Readable=false.
//
// haveConfig says whether the collection's engagement snapshot was loaded, which is
// what lets the assessment judge the capture against the rules the run actually had
// rather than against nothing.
func discoverCapture(dataPath string, w collectionSpan, haveConfig bool) *netaudit.CaptureSource {
	dir := netauditDirPath(dataPath)
	for _, name := range captureFileNames {
		if src := readCapture(dataPath, filepath.Join(dir, name), dir, w, haveConfig); src != nil {
			return src
		}
	}
	return nil
}

// readCapture builds a CaptureSource for path when it exists, or nil when it does
// not.
//
// The hash and byte size describe the file as stored, which for collected evidence
// means the compressed bytes. That is deliberate: the hash has to identify the thing
// that was downloaded and can be re-examined, not a decompression of it that no two
// gzip implementations need agree on.
func readCapture(dataPath, path, metaDir string, w collectionSpan, haveConfig bool) *netaudit.CaptureSource {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	rel, relErr := filepath.Rel(dataPath, path)
	if relErr != nil {
		rel = path
	}
	src := &netaudit.CaptureSource{
		RelPath:      filepath.ToSlash(rel),
		ByteSize:     fi.Size(),
		TimeOverlap:  true,
		UniqueConfig: haveConfig,
	}
	backend, start, stop := readCaptureMeta(filepath.Join(metaDir, captureMeta))
	src.Start, src.Stop = start, stop

	sum, hashErr := hashFile(path)
	if hashErr != nil {
		src.Readable = false
		return src
	}
	src.SHA256 = sum

	f, err := os.Open(path)
	if err != nil {
		src.Readable = false
		return src
	}
	res, err := netaudit.Extract(bufio.NewReader(f))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		src.Readable = false
		return src
	}
	src.Readable = true
	if backend != "" {
		res.Backend = backend
	}
	src.Extract = res

	// Overlap check: the capture window (meta times, or packet times when meta is
	// absent) must intersect the collection's own.
	if !w.started.IsZero() && !w.completed.IsZero() {
		cs, ce := captureWindow(src)
		if !cs.IsZero() && !ce.IsZero() {
			src.TimeOverlap = cs.Before(w.completed.Add(bindSlack)) && ce.After(w.started.Add(-bindSlack))
		}
	}
	return src
}

// captureWindow returns the capture's effective time span: the wrapper meta bracket
// when present, otherwise the first/last observed packet time.
func captureWindow(src *netaudit.CaptureSource) (start, stop time.Time) {
	if !src.Start.IsZero() && !src.Stop.IsZero() {
		return src.Start, src.Stop
	}
	obs := src.Extract.Observations
	if len(obs) == 0 {
		return time.Time{}, time.Time{}
	}
	start, stop = obs[0].Time, obs[0].Time
	for i := range obs {
		if obs[i].Time.Before(start) {
			start = obs[i].Time
		}
		if obs[i].Time.After(stop) {
			stop = obs[i].Time
		}
	}
	return start, stop
}

// readCaptureMeta parses the wrapper-written capture.meta.txt key=value sidecar. A
// missing or malformed file yields zero values, which the caller treats as "meta
// unknown" rather than an error.
func readCaptureMeta(path string) (backend netaudit.Backend, start, stop time.Time) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, time.Time{}
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "backend":
			switch val {
			case "ptcpdump":
				backend = netaudit.BackendPtcpdump
			case "tcpdump":
				backend = netaudit.BackendTcpdump
			}
		case "started":
			start, _ = time.Parse(time.RFC3339, val)
		case "stopped":
			stop, _ = time.Parse(time.RFC3339, val)
		}
	}
	return backend, start, stop
}

// hashFile returns the hex SHA-256 of a file's bytes, streamed with bounded memory.
func hashFile(path string) (digest string, resultErr error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close: %w", err))
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// exclusionIssues returns the domain exclusion IssueObserved rows whose capture
// time falls within the collection's span.
func exclusionIssues(evts []events.DomainEvent, w collectionSpan) []netaudit.ExclusionIssue {
	var out []netaudit.ExclusionIssue
	for _, evt := range evts {
		issue, ok := evt.(events.IssueObserved)
		if !ok || issue.Class != events.IssueClassExclusion {
			continue
		}
		if !inWindow(issue.At(), w) {
			continue
		}
		out = append(out, netaudit.ExclusionIssue{Target: issue.Query, At: issue.At()})
	}
	return out
}

// maxToolLogLineBytes bounds a single tool-event line. Error events embed raw
// response bodies, so the scanner buffer is raised well past the default.
const maxToolLogLineBytes = 8 * 1024 * 1024

// loadToolSpans reads the tool-event log and returns the active/exploit invocation
// spans and typed rejections. A missing log is not an error (older scans have none).
func loadToolSpans(dataPath string) (spans []netaudit.ToolSpan, resultErr error) {
	f, ok, err := collection.ReadToolLog(dataPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close tool-event log: %w", err))
		}
	}()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxToolLogLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		env, err := tooleventlog.DecodeEnvelope([]byte(line))
		if err != nil {
			return spans, fmt.Errorf("decode tool-event log line %d: %w", lineNumber, err)
		}
		rejected := isPolicyRejection(env)
		activeTarget := env.Target != "" && env.Phase == string(events.PhaseActive)
		if !rejected && !activeTarget {
			continue
		}
		span := netaudit.ToolSpan{
			Tool:     env.Tool,
			Target:   env.Target,
			Phase:    env.Phase,
			At:       env.At,
			Rejected: rejected,
		}
		if rejected {
			span.Destinations = rejectionDestinations(env)
			span.Reason, _ = env.Attrs["reason"].(string)
		}
		spans = append(spans, span)
	}
	if err := scanner.Err(); err != nil {
		return spans, err
	}
	return spans, nil
}

// isPolicyRejection reports whether an envelope is a typed exclusion-policy
// rejection. The name alone is not enough: "smtp: connection rejected" is a remote
// server refusing a connection, not the scanner denying a destination. Every typed
// policy rejection records the deciding rule in a "reason" attribute, so the two
// are told apart by that attribute rather than by enumerating tool event names.
func isPolicyRejection(env tooleventlog.ToolEventEnvelope) bool {
	if !strings.Contains(strings.ToLower(env.Name), "reject") {
		return false
	}
	reason, _ := env.Attrs["reason"].(string)
	return strings.TrimSpace(reason) != ""
}

// rejectionDestinationKeys are the envelope attribute keys that carry a denied
// destination, in preference order and grouped by how a rejection describes it.
// The first group that yields anything wins, so a derived destination (the
// nameserver, the MX host, the resolved address) is always preferred over the
// invocation target the rejection was raised under.
//
// The groups mirror the typed rejection events: dnsinfo zone-transfer rejections
// carry nameserver (+resolved_ip), smtp MX rejections carry host (+resolved_ip),
// portscan carries ip, redirect rejections carry to_url, target-level rejections
// (https, exploit) carry target, and smtp target rejections carry domain.
var rejectionDestinationKeys = [][]string{
	{"resolved_ips", "resolved_ip", "nameserver", "host", "mx_host"},
	{"ip"},
	{"to_url"},
	{"target"},
	{"domain"},
}

// rejectionDestinations derives the destinations a rejection actually denied from
// its own attributes, falling back to the envelope's invocation target when the
// event carried none. All destinations of the winning group are kept, so a
// rejection that names both a host and its resolved address can reconcile against
// a domain rule and a CIDR rule alike.
func rejectionDestinations(env tooleventlog.ToolEventEnvelope) []string {
	for _, group := range rejectionDestinationKeys {
		var out []string
		for _, key := range group {
			for _, raw := range attrStrings(env.Attrs[key]) {
				v := normalizeDestination(key, raw)
				if v == "" || slices.Contains(out, v) {
					continue
				}
				out = append(out, v)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if env.Target != "" {
		return []string{env.Target}
	}
	return nil
}

// attrStrings reads one destination attribute as a list. An attribute is normally a
// single string, but a rejection that denied several addresses at once records them
// as an array, which decodes from JSON as []any.
func attrStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// normalizeDestination trims a destination attribute to the bare host identity the
// rule matcher expects: a URL reduces to its hostname, and a DNS name loses its
// trailing root dot and case.
func normalizeDestination(key, value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	if key == "to_url" {
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		v = u.Hostname()
	}
	return strings.ToLower(strings.TrimSuffix(v, "."))
}

// spansInWindow returns the tool spans whose time falls within the collection.
func spansInWindow(spans []netaudit.ToolSpan, w collectionSpan) []netaudit.ToolSpan {
	if w.started.IsZero() && w.completed.IsZero() {
		return spans
	}
	var out []netaudit.ToolSpan
	for _, s := range spans {
		if inWindow(s.At, w) {
			out = append(out, s)
		}
	}
	return out
}

// inWindow reports whether t falls within the collection's span, with binding slack.
// A span with zero bounds (no manifest, no events) admits everything.
func inWindow(t time.Time, w collectionSpan) bool {
	if w.started.IsZero() && w.completed.IsZero() {
		return true
	}
	if !w.started.IsZero() && t.Before(w.started.Add(-bindSlack)) {
		return false
	}
	if !w.completed.IsZero() && t.After(w.completed.Add(bindSlack)) {
		return false
	}
	return true
}
