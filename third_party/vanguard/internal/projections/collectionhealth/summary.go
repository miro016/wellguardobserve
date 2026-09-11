package collectionhealth

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Status is the outcome of the collection a projection was built from. The
// vocabulary is the collected manifest's own, copied rather than reinterpreted: a
// projection that renamed a status would be a second opinion about an outcome it did
// not observe.
type Status string

const (
	// StatusRunning means the collection had not reached a terminal state when it was
	// projected: it is still running, or its collector died without recording an
	// outcome. It carries no health because nothing concluded.
	StatusRunning Status = "running"
	// StatusSucceeded means every phase the collection ran completed cleanly and no
	// tool reported lost work.
	StatusSucceeded Status = "succeeded"
	// StatusDegraded means the collection concluded and wrote its streams, but at
	// least one tool reported collection work it attempted and lost. The evidence
	// collected is exactly as trustworthy as it looks; what is missing is the
	// Problems list.
	StatusDegraded Status = "degraded"
	// StatusFailed means the collector ran to a conclusion and reported an error.
	StatusFailed Status = "failed"
	// StatusInterrupted means the collector was cancelled and recorded that before
	// exiting.
	StatusInterrupted Status = "interrupted"
)

// Problem is one collection-health identity and how many events reported it. It is a
// count, not a log: the per-event evidence stays in the capture's tool stream.
type Problem struct {
	// Code is the stable lower-case dotted identity owned by the producing tool.
	Code string `json:"code"`
	// Tool is the tool that reported it.
	Tool string `json:"tool"`
	// Component is the provider or module inside that tool, when it named one.
	Component string `json:"component,omitempty"`
	// Count is the number of events that reported this identity. It is positive.
	Count int `json:"count"`
}

// Summary is the projection-owned collection outcome: which source produced the
// evidence, how the collection ended, and what it lost. It is built by [New], which
// is the only way to obtain a valid one, and is treated as immutable afterwards.
type Summary struct {
	// ScanID is the collection's run identity, so a summary read out of context still
	// names the collection it describes.
	ScanID string `json:"scan_id"`
	// Status is the collection's outcome.
	Status Status `json:"status"`
	// Phases is the phase set the collection was asked to run, in canonical order. It
	// states what was attempted; whether it finished is Status.
	Phases []string `json:"phases"`
	// Total is the number of health-bearing tool events the collection observed,
	// counting repeats. It is zero for a clean collection.
	Total int `json:"health_total"`
	// Problems are the distinct problem identities and their counts, sorted by code,
	// tool, then component. The order is part of the value: two collections that lost
	// the same work render identically.
	Problems []Problem `json:"problems,omitempty"`
}

// New validates in and returns the summary a renderer may use, with every slice
// cloned so the result cannot alias or be mutated through the caller's value.
//
// It enforces the invariants the collected manifest already maintains rather than
// trusting them, because this value is copied across a package boundary and a
// summary that contradicts itself would be rendered as confidently as a correct one:
// a known status, positive and canonically ordered problem rows whose counts sum to
// the total, a degraded collection that describes its loss, and a succeeded or
// running one that claims none.
func New(in Summary) (Summary, error) {
	if strings.TrimSpace(in.ScanID) == "" {
		return Summary{}, errors.New("collection health: scan ID must be set")
	}
	switch in.Status {
	case StatusRunning, StatusSucceeded, StatusDegraded, StatusFailed, StatusInterrupted:
	default:
		return Summary{}, fmt.Errorf("collection health: unknown collection status %q", in.Status)
	}
	if err := validateProblems(in); err != nil {
		return Summary{}, err
	}
	switch {
	case in.Status == StatusDegraded && in.Total <= 0:
		return Summary{}, errors.New("collection health: a degraded collection must describe the work it lost")
	case in.Status == StatusSucceeded && in.Total != 0:
		return Summary{}, fmt.Errorf("collection health: a succeeded collection reports %d problem event(s)", in.Total)
	case in.Status == StatusRunning && in.Total != 0:
		return Summary{}, fmt.Errorf("collection health: a running collection reports %d problem event(s)", in.Total)
	}
	return Summary{
		ScanID:   in.ScanID,
		Status:   in.Status,
		Phases:   slices.Clone(in.Phases),
		Total:    in.Total,
		Problems: slices.Clone(in.Problems),
	}, nil
}

// validateProblems checks the rows are identifiable, positive, canonically ordered
// and unique, and that they account for the total exactly.
func validateProblems(in Summary) error {
	if in.Total < 0 {
		return fmt.Errorf("collection health: total %d must not be negative", in.Total)
	}
	sum := 0
	for i, p := range in.Problems {
		if strings.TrimSpace(p.Code) == "" || strings.TrimSpace(p.Tool) == "" {
			return fmt.Errorf("collection health: problem %d names no code or tool", i+1)
		}
		if p.Count <= 0 {
			return fmt.Errorf("collection health: problem %q has a non-positive count", p.Code)
		}
		if i > 0 && !problemLess(in.Problems[i-1], p) {
			return errors.New("collection health: problems must be unique and sorted by code, tool, then component")
		}
		sum += p.Count
	}
	if sum != in.Total {
		return fmt.Errorf("collection health: problem counts sum to %d but total is %d", sum, in.Total)
	}
	return nil
}

// problemLess is the canonical problem order, and therefore also the uniqueness
// test: equal rows are not less than each other.
func problemLess(a, b Problem) bool {
	if a.Code != b.Code {
		return a.Code < b.Code
	}
	if a.Tool != b.Tool {
		return a.Tool < b.Tool
	}
	return a.Component < b.Component
}

// Clean reports whether the collection concluded with nothing lost. It is the one
// condition under which a renderer may present absence as evidence of absence.
func (s Summary) Clean() bool {
	return s.Status == StatusSucceeded && s.Total == 0
}

// Incomplete reports whether the collection is known to have lost work or to have
// stopped short of a clean conclusion. It never implies a target is at risk: an
// incomplete collection is a statement about what was looked at, not about what was
// found.
func (s Summary) Incomplete() bool {
	return !s.Clean()
}

// StatusLine is the one-line verdict every artifact opens with, so the report, the
// attack surface, and the projection manifest cannot describe one outcome in three
// ways.
func (s Summary) StatusLine() string {
	if s.Clean() {
		return "succeeded, no collection problems"
	}
	return fmt.Sprintf("%s, %d collection problem event(s)", s.Status, s.Total)
}
