package scandiff

import (
	"sort"
	"strconv"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Report is the full scan-comparison result: who was compared, the headline
// summary, the classified event differences, the entity coverage deltas, the
// findings view, and the optional operational delta. It renders to deterministic
// JSON (the source of truth) and a human-readable Markdown summary.
type Report struct {
	Baseline    ScanRef          `json:"baseline"`  // A, the reference / "before"
	Candidate   ScanRef          `json:"candidate"` // B, the inspected / "after"
	Summary     Summary          `json:"summary"`
	Findings    FindingsDelta    `json:"findings"`
	Coverage    []CoverageDelta  `json:"coverage"`
	Events      []EventDiff      `json:"events"`
	Issues      IssueDelta       `json:"issues"`
	Op          OpDelta          `json:"op"`
	Environment EnvironmentDelta `json:"environment"`
}

// EnvironmentDelta describes execution-input changes between sessions. Changes is
// ordered deterministically by field and names the exact build, runtime, embedded
// snapshot, module, or configuration value that differs.
type EnvironmentDelta struct {
	Changed   bool                            `json:"changed"`
	Changes   []EnvironmentChange             `json:"changes,omitempty"`
	Baseline  *events.ScanEnvironmentRecorded `json:"baseline,omitempty"`
	Candidate *events.ScanEnvironmentRecorded `json:"candidate,omitempty"`
}

// EnvironmentChange is one differing environment field. Empty values are retained
// so JSON callers can distinguish a value being removed from no reported change.
type EnvironmentChange struct {
	Field     string `json:"field"`
	Baseline  string `json:"baseline"`
	Candidate string `json:"candidate"`
}

// ScanRef identifies one side of the comparison, recovered from its lifecycle
// events the same way the persistence layer recovers scan identity: the earliest
// ScanStarted gives the root and ScanID, and Events is the stream length.
type ScanRef struct {
	Root      string    `json:"root"`
	ScanID    string    `json:"scanID"`
	Events    int       `json:"events"`
	StartedAt time.Time `json:"startedAt,omitempty"`
}

// Summary is the headline rollup: the four class counts overall and per event type,
// plus a flag when the two scans have different roots.
type Summary struct {
	Matched     int                    `json:"matched"`
	Changed     int                    `json:"changed"`
	Missing     int                    `json:"missing"`
	Unexpected  int                    `json:"unexpected"`
	RootsDiffer bool                   `json:"rootsDiffer"`
	ByType      map[string]ClassCounts `json:"byType"`
}

// ClassCounts is the per-type breakdown of the four verdict classes.
type ClassCounts struct {
	Matched    int `json:"matched"`
	Changed    int `json:"changed"`
	Missing    int `json:"missing"`
	Unexpected int `json:"unexpected"`
}

// IssueDelta summarizes the run-specific operational errors (IssueObserved) per
// side. Issues are not diffed as content - they are run-specific by nature - so the
// report carries only their counts, per the recorded "issues summarized" decision.
type IssueDelta struct {
	A int `json:"a"`
	B int `json:"b"`
}

// OpDelta is the optional per-provider operational delta between the two scans. It
// is filled by projection persistence from each collection's tooling.jsonl; Available is
// false when either side lacks the tool-event log, and the report then degrades to
// content-only.
type OpDelta struct {
	Available bool              `json:"available"`
	Providers []ProviderOpDelta `json:"providers,omitempty"`
}

// ProviderOpDelta is one provider's operational change between the two scans:
// calls, failed calls, and empty-but-valid results on each side. Latency and
// per-field reliability stay in the quality report; the diff keeps the operational
// view to the few counts that explain a content change.
type ProviderOpDelta struct {
	Provider string `json:"provider"`
	ACalls   int    `json:"aCalls"`
	BCalls   int    `json:"bCalls"`
	AFailed  int    `json:"aFailed"`
	BFailed  int    `json:"bFailed"`
	AEmpties int    `json:"aEmpties"`
	BEmpties int    `json:"bEmpties"`
}

// Build computes the comparison report from the two raw event streams and the
// operational delta. It is deterministic and fully offline: the same inputs always
// produce the same report. Pass an empty OpDelta (Available false) for a
// content-only report. The operational delta is passed in already folded - the I/O
// that reads tooling.jsonl lives in projection persistence, so Build stays pure.
func Build(baseline, candidate []events.DomainEvent, op OpDelta, opts Options) Report {
	all := Differ{Opts: opts}.Classify(baseline, candidate)

	summary := tallySummary(all)
	base := recoverScanRef(baseline)
	cand := recoverScanRef(candidate)
	summary.RootsDiffer = rootsDiffer(base.Root, cand.Root)

	evts := all
	if !opts.IncludeMatched {
		evts = dropMatched(all)
	}

	return Report{
		Baseline:    base,
		Candidate:   cand,
		Summary:     summary,
		Findings:    Findings(baseline, candidate),
		Coverage:    Coverage(baseline, candidate),
		Events:      evts,
		Issues:      IssueDelta{A: countIssues(baseline), B: countIssues(candidate)},
		Op:          op,
		Environment: compareEnvironment(baseline, candidate),
	}
}

func compareEnvironment(a, b []events.DomainEvent) EnvironmentDelta {
	latest := func(stream []events.DomainEvent) *events.ScanEnvironmentRecorded {
		var out *events.ScanEnvironmentRecorded
		for _, raw := range stream {
			if e, ok := events.AsValue(raw).(events.ScanEnvironmentRecorded); ok {
				snapshot := e
				snapshot.EventMeta = events.EventMeta{}
				out = &snapshot
			}
		}
		return out
	}
	ae, be := latest(a), latest(b)
	changes := compareEnvironmentFields(ae, be)
	return EnvironmentDelta{Changed: len(changes) > 0, Changes: changes, Baseline: ae, Candidate: be}
}

// compareEnvironmentFields compares stable semantic fields and treats snapshot and
// module slices as keyed sets, so input ordering cannot create a false warning.
func compareEnvironmentFields(a, b *events.ScanEnvironmentRecorded) []EnvironmentChange {
	if a == nil || b == nil {
		if a == b {
			return nil
		}
		return []EnvironmentChange{{Field: "record", Baseline: presence(a != nil), Candidate: presence(b != nil)}}
	}

	var out []EnvironmentChange
	// The actor's version is compared as one value, because it is one value: whoever
	// started the collection composed it, and a difference anywhere inside it means a
	// different build ran, which is the whole question this line answers.
	addEnvironmentChange(&out, "actor.name", a.Actor.Name, b.Actor.Name)
	addEnvironmentChange(&out, "actor.version", a.Actor.Version, b.Actor.Version)

	addEnvironmentChange(&out, "runtime.nmapPath", a.Runtime.NmapPath, b.Runtime.NmapPath)
	addEnvironmentChange(&out, "runtime.nmapVersion", a.Runtime.NmapVersion, b.Runtime.NmapVersion)
	addEnvironmentChange(&out, "runtime.pythonPath", a.Runtime.PythonPath, b.Runtime.PythonPath)
	addEnvironmentChange(&out, "runtime.pythonVersion", a.Runtime.PythonVersion, b.Runtime.PythonVersion)
	addEnvironmentChange(&out, "runtime.sslyzeVersion", a.Runtime.SslyzeVersion, b.Runtime.SslyzeVersion)
	addEnvironmentChange(&out, "configSHA256", a.ConfigSHA256, b.ConfigSHA256)

	out = append(out, compareSnapshots(a.Snapshots, b.Snapshots)...)
	out = append(out, compareModules(a.Modules, b.Modules)...)
	return out
}

// addEnvironmentChange appends one field only when its values differ.
func addEnvironmentChange(out *[]EnvironmentChange, field, a, b string) {
	if a == b {
		return
	}
	*out = append(*out, EnvironmentChange{Field: field, Baseline: a, Candidate: b})
}

// compareSnapshots compares embedded datasets by snapshot name rather than slice
// position.
func compareSnapshots(a, b []events.EnvironmentSnapshot) []EnvironmentChange {
	am := make(map[string]events.EnvironmentSnapshot, len(a))
	bm := make(map[string]events.EnvironmentSnapshot, len(b))
	for _, snapshot := range a {
		am[snapshot.Name] = snapshot
	}
	for _, snapshot := range b {
		bm[snapshot.Name] = snapshot
	}
	names := unionKeys(am, bm)
	out := make([]EnvironmentChange, 0)
	for _, name := range names {
		as, aok := am[name]
		bs, bok := bm[name]
		prefix := "snapshots." + name
		if !aok || !bok {
			addEnvironmentChange(&out, prefix, presence(aok), presence(bok))
			continue
		}
		addEnvironmentChange(&out, prefix+".version", as.Version, bs.Version)
		addEnvironmentChange(&out, prefix+".released", as.Released, bs.Released)
		addEnvironmentChange(&out, prefix+".count", strconv.Itoa(as.Count), strconv.Itoa(bs.Count))
		addEnvironmentChange(&out, prefix+".digest", as.Digest, bs.Digest)
	}
	return out
}

// compareModules compares behavior-affecting dependencies by module path.
func compareModules(a, b []events.ModuleVersion) []EnvironmentChange {
	am := make(map[string]string, len(a))
	bm := make(map[string]string, len(b))
	for _, module := range a {
		am[module.Path] = module.Version
	}
	for _, module := range b {
		bm[module.Path] = module.Version
	}
	paths := unionKeys(am, bm)
	out := make([]EnvironmentChange, 0)
	for _, path := range paths {
		av, aok := am[path]
		bv, bok := bm[path]
		field := "modules." + path
		if !aok || !bok {
			addEnvironmentChange(&out, field, presence(aok), presence(bok))
			continue
		}
		addEnvironmentChange(&out, field, av, bv)
	}
	return out
}

// unionKeys returns the sorted union of two string-keyed maps.
func unionKeys[V any](a, b map[string]V) []string {
	keys := make(map[string]struct{}, len(a)+len(b))
	for key := range a {
		keys[key] = struct{}{}
	}
	for key := range b {
		keys[key] = struct{}{}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// presence renders whether one side recorded a keyed environment item.
func presence(present bool) string {
	if present {
		return "present"
	}
	return "missing"
}

// countIssues counts the run-specific IssueObserved events in a stream, used for
// the summarized (not diffed) issue counts.
func countIssues(evts []events.DomainEvent) int {
	n := 0
	for _, evt := range evts {
		if events.AsValue(evt).Meta().Category == events.CategoryIssue {
			n++
		}
	}
	return n
}

// tallySummary counts the four classes overall and per type from the full
// classification (matched included), before matched is dropped from the slice.
func tallySummary(diffs []EventDiff) Summary {
	s := Summary{ByType: map[string]ClassCounts{}}
	for _, d := range diffs {
		cc := s.ByType[d.Type]
		switch d.Class {
		case Matched:
			s.Matched++
			cc.Matched++
		case Changed:
			s.Changed++
			cc.Changed++
		case Missing:
			s.Missing++
			cc.Missing++
		case Unexpected:
			s.Unexpected++
			cc.Unexpected++
		}
		s.ByType[d.Type] = cc
	}
	return s
}

// dropMatched returns the diffs without the Matched entries, preserving order.
func dropMatched(diffs []EventDiff) []EventDiff {
	out := make([]EventDiff, 0, len(diffs))
	for _, d := range diffs {
		if d.Class != Matched {
			out = append(out, d)
		}
	}
	return out
}

// recoverScanRef rebuilds a side's identity from its stream: the earliest
// ScanStarted gives the root and ScanID, and Events is the stream length.
func recoverScanRef(evts []events.DomainEvent) ScanRef {
	ref := ScanRef{Events: len(evts)}
	found := false
	for _, evt := range evts {
		s, ok := events.AsValue(evt).(events.ScanStarted)
		if !ok {
			continue
		}
		if !found || s.At().Before(ref.StartedAt) {
			ref.Root = s.RootTarget
			ref.ScanID = s.Meta().ScanID
			ref.StartedAt = s.At()
			found = true
		}
	}
	return ref
}

// rootsDiffer reports whether two recovered roots are both known and different,
// comparing them normalized so a trailing dot or case is not a spurious mismatch.
func rootsDiffer(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return normalizeDomain(a) != normalizeDomain(b)
}

// sortedProviders returns the operational deltas ordered by provider name.
func (o OpDelta) sortedProviders() []ProviderOpDelta {
	out := make([]ProviderOpDelta, len(o.Providers))
	copy(out, o.Providers)
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}
