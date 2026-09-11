package health

import (
	"sort"
	"sync"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const (
	// MaxIdentities is the number of distinct (code, tool, component) rows the
	// monitor keeps. Beyond it, further identities fold into CodeOverflow, so a tool
	// emitting an unbounded set of components cannot grow monitor memory.
	MaxIdentities = 64
	// maxFieldLen bounds every producer-supplied string the monitor stores or hands
	// to the live callback. Codes and component names are short by contract; this is
	// the enforcement of that contract against a producer that ignores it.
	maxFieldLen = 120
	// CodeOverflow is the reserved identity that counts problems arriving after the
	// identity cap is reached. It is always available, so a full table still counts.
	CodeOverflow = "collection.problem_overflow"
	// CodeInvalidEvent is the reserved identity for an event that claimed a problem
	// but supplied no code or no tool name. Invalid producer output is counted rather
	// than dropped: a silently discarded problem is the one failure mode this package
	// exists to prevent.
	CodeInvalidEvent = "collection.invalid_health_event"
)

// Problem is the live form of one observed collection problem: the safe fields the
// producer reported, the tool that reported them, and when it did. It is passed to
// the notification callback and is not retained afterwards.
type Problem struct {
	// At is the event's emission time, as stamped by the tool sink.
	At time.Time
	// Tool is the reporting tool's identifier (e.g. "subfinder").
	Tool string
	// Code is the producer-owned stable identity (e.g. "subfinder.provider_failed"),
	// or one of the reserved codes when the monitor had to substitute one.
	Code string
	// Component optionally identifies the bounded provider or module that failed.
	Component string
	// Target optionally identifies the affected domain, address, or URL. It is
	// live-display only and is never counted or persisted.
	Target string
	// SafeDetail is optional producer-written context safe to print.
	SafeDetail string
}

// ProblemCount is one row of an assessment: a distinct problem identity and how
// many events reported it.
type ProblemCount struct {
	// Code is the problem identity's stable code.
	Code string
	// Tool is the reporting tool.
	Tool string
	// Component is the reporting component, empty when the producer named none.
	Component string
	// Count is the number of events that reported this identity.
	Count int
}

// Assessment is the immutable collection-health result of one run: the total number
// of health-bearing events observed, and the per-identity counts sorted by code,
// tool, and component.
type Assessment struct {
	// Total is the number of health-bearing events observed, counting repeats.
	Total int
	// Problems are the distinct identities and their counts, in deterministic order.
	Problems []ProblemCount
}

// Degraded reports whether the run lost collection work.
func (a Assessment) Degraded() bool { return a.Total > 0 }

// identity is the map key: everything that makes two problems the same problem.
// Target and detail are deliberately absent, so a provider failing across a
// thousand targets is one row.
type identity struct {
	code      string
	tool      string
	component string
}

// Monitor folds health-bearing tool events into one bounded assessment and notifies
// a caller the first time each identity appears. The zero value is not usable; use
// [New]. All methods are safe for concurrent use, which they have to be: tool events
// arrive from the orchestrator's worker groups.
type Monitor struct {
	mu       sync.Mutex
	total    int
	counts   map[identity]int
	notified map[identity]bool

	// notify is called outside the lock for the first occurrence of each identity. It
	// is synchronous by design: the caller's live progress output is synchronous
	// already, and a queue here would add a second error path and a shutdown
	// sequence for no gain.
	notify func(Problem)
}

// New returns a monitor that calls notify once per distinct problem identity.
// A nil notify is allowed and means counting only.
func New(notify func(Problem)) *Monitor {
	return &Monitor{
		counts:   make(map[identity]int),
		notified: make(map[identity]bool),
		notify:   notify,
	}
}

// Observe folds one tool event. Events that carry no collection-health meaning, and
// health-aware events whose concrete outcome was healthy, are ignored. Safe to call
// on a nil *Monitor.
func (m *Monitor) Observe(at time.Time, event tooleventlog.Event) {
	if m == nil || event == nil {
		return
	}
	he, ok := event.(tooleventlog.HealthEvent)
	if !ok {
		return
	}
	problem, degraded := he.CollectionHealth()
	if !degraded {
		return
	}

	id := identity{
		code:      bound(problem.Code),
		tool:      bound(event.ToolName()),
		component: bound(problem.Component),
	}
	live := Problem{
		At:         at,
		Tool:       id.tool,
		Code:       id.code,
		Component:  id.component,
		Target:     bound(problem.Target),
		SafeDetail: bound(problem.SafeDetail),
	}
	// A problem without a code or a tool cannot be attributed, so it is counted under
	// the reserved identity instead: the producer is broken, and that is itself worth
	// seeing rather than losing.
	if id.code == "" || id.tool == "" {
		id = identity{code: CodeInvalidEvent, tool: id.tool}
		live = Problem{At: at, Tool: id.tool, Code: id.code}
	}

	m.mu.Lock()
	m.total++
	if _, exists := m.counts[id]; !exists && len(m.counts) >= MaxIdentities && id.code != CodeOverflow {
		// The table is full and this is a new identity: fold it into the reserved
		// overflow row, which is allowed to exceed the cap by one so counting never
		// stops. Identities already present keep counting normally.
		id = identity{code: CodeOverflow}
		live = Problem{At: at, Code: id.code}
	}
	m.counts[id]++
	first := !m.notified[id]
	m.notified[id] = true
	m.mu.Unlock()

	if first && m.notify != nil {
		m.notify(live)
	}
}

// Assessment returns the run's collection-health result so far. The returned rows
// are a copy in deterministic order: a caller may keep or mutate them without
// touching monitor state. Safe to call on a nil *Monitor, which is healthy.
func (m *Monitor) Assessment() Assessment {
	if m == nil {
		return Assessment{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	problems := make([]ProblemCount, 0, len(m.counts))
	for id, count := range m.counts {
		problems = append(problems, ProblemCount{
			Code: id.code, Tool: id.tool, Component: id.component, Count: count,
		})
	}
	sort.Slice(problems, func(i, j int) bool {
		a, b := problems[i], problems[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		return a.Component < b.Component
	})
	return Assessment{Total: m.total, Problems: problems}
}

// bound truncates a producer-supplied string to the field limit. It cuts on a rune
// boundary so a truncated field is still printable text.
func bound(s string) string {
	if len(s) <= maxFieldLen {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxFieldLen {
		return s
	}
	return string(runes[:maxFieldLen])
}
