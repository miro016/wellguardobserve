package collect

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/health"
	"github.com/velgard-sk/vanguard/internal/collection/persistence"
)

// HealthProblem is one kind of collection work a run attempted and lost, and how
// often it happened. It is an identity and a count, deliberately not an incident
// log: the per-event evidence, with targets and provider responses, is in the
// capture's tool stream.
type HealthProblem struct {
	// Code is the stable lower-case dotted identity owned by the producing tool,
	// for example "subfinder.provider_failed". It is the field to branch on.
	Code string
	// Tool is the tool that reported the problem, for example "subfinder".
	Tool string
	// Component is the provider or module inside that tool, when the tool named one,
	// for example "waybackarchive". It is empty when the problem is the tool's own.
	Component string
	// Count is how many events reported this identity during the run.
	Count int
}

// HealthSummary is a run's whole collection-health result: how many health-bearing
// events were observed, and the distinct problems behind them, sorted by code,
// tool, then component so two runs that lost the same work compare equal.
type HealthSummary struct {
	// Total is the number of health-bearing events observed, counting repeats.
	Total int
	// Problems are the distinct problem identities and their counts.
	Problems []HealthProblem
}

// DegradedError is returned by [Collector.Run] when the collection finished and
// wrote its capture cleanly but at least one tool reported work it attempted and
// could not complete.
//
// It is not a failure of the run. Everything that was collected is in the capture
// and is exactly as trustworthy as it looks; what is missing is described by
// [DegradedError.Summary], and the capture's manifest records the same summary
// against a "degraded" execution. Because a degraded execution contributes no
// phases, running the same collection again against the same directory retries
// exactly the incomplete work and keeps what already succeeded.
//
// What to do with it is a policy the caller owns: alert on it, retry it later, or
// accept a partial estate for this engagement. Vanguard will not decide that, but
// it will not let the run be mistaken for a complete one either.
//
// Match it with errors.As:
//
//	var degraded *collect.DegradedError
//	if errors.As(err, &degraded) { ... }
type DegradedError struct {
	// summary is unexported so the value a caller holds cannot be edited into a
	// claim the capture does not make. Summary returns a copy.
	summary HealthSummary
}

// Error renders the verdict and the problems behind it. The wording is for humans
// and is not a machine protocol: read [DegradedError.Summary] for that.
func (e *DegradedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "collection degraded: %d collection problems across %d identities",
		e.summary.Total, len(e.summary.Problems))
	// The rows are bounded but can still be dozens; an error string is read in a log
	// line, so it names the worst few and leaves the rest to the summary.
	const shown = 5
	for i, problem := range e.summary.Problems {
		if i == shown {
			fmt.Fprintf(&b, "; and %d more", len(e.summary.Problems)-shown)
			break
		}
		b.WriteString("; ")
		b.WriteString(problemLine(problem))
	}
	return b.String()
}

// Summary returns a deep copy of the run's collection-health result, so a caller
// may keep, sort, or edit it without touching the error it came from.
func (e *DegradedError) Summary() HealthSummary {
	if e == nil {
		return HealthSummary{}
	}
	return HealthSummary{
		Total:    e.summary.Total,
		Problems: append([]HealthProblem(nil), e.summary.Problems...),
	}
}

// problemLine renders one problem the way both the error string and an operator
// summary want it: identity, where it came from, how often.
func problemLine(problem HealthProblem) string {
	where := problem.Tool
	if problem.Component != "" {
		where += "/" + problem.Component
	}
	return fmt.Sprintf("%s [%s] x%d", problem.Code, where, problem.Count)
}

// publicSummary converts the internal assessment into the public result type. It is
// the only place the two shapes meet, so the manifest summary and the returned
// error are two renderings of one fold rather than two independent counts.
func publicSummary(assessment health.Assessment) HealthSummary {
	summary := HealthSummary{Total: assessment.Total}
	for _, problem := range assessment.Problems {
		summary.Problems = append(summary.Problems, HealthProblem{
			Code: problem.Code, Tool: problem.Tool, Component: problem.Component, Count: problem.Count,
		})
	}
	return summary
}

// collectionHealth converts the same assessment into the manifest's summary, or nil
// when the run lost nothing. A healthy collection stores no health object at all, so
// "degraded" and "succeeded with an empty summary" cannot both exist on disk.
func collectionHealth(assessment health.Assessment) *persistence.CollectionHealth {
	if !assessment.Degraded() {
		return nil
	}
	stored := &persistence.CollectionHealth{Total: assessment.Total}
	for _, problem := range assessment.Problems {
		stored.Problems = append(stored.Problems, persistence.HealthProblemCount{
			Code: problem.Code, Tool: problem.Tool, Component: problem.Component, Count: problem.Count,
		})
	}
	return stored
}
