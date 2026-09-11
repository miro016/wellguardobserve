package parityreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections/scandiff"
)

// ScenarioStatus is the outcome of one corpus pair.
type ScenarioStatus string

const (
	// StatusPass means all applicable checks passed.
	StatusPass ScenarioStatus = "pass"
	// StatusFail means at least one structural or content check failed.
	StatusFail ScenarioStatus = "fail"
	// StatusInconclusive means structural checks passed but a configured provider
	// gate prevented a trustworthy content verdict.
	StatusInconclusive ScenarioStatus = "inconclusive"
)

// CheckStatus is the outcome of one explicit scenario assertion.
type CheckStatus string

const (
	// CheckPass means the assertion held.
	CheckPass CheckStatus = "pass"
	// CheckFail means the assertion did not hold.
	CheckFail CheckStatus = "fail"
	// CheckSkipped means a provider gate made a content assertion inconclusive.
	CheckSkipped CheckStatus = "skipped"
)

// Manifest defines the checked-in corpus expectations. Version must be 1 and
// scenario names are relative child-directory names under both corpus roots.
type Manifest struct {
	Version   int            `json:"version"`
	Scenarios []ScenarioSpec `json:"scenarios"`
}

// ScenarioSpec defines stable expectations and explicit dynamic allowances for
// one named capture pair.
type ScenarioSpec struct {
	// Name is the child-directory name under both corpus roots.
	Name string `json:"name"`
	// ExpectedPhases is the exact sorted set of non-empty event phases required on
	// both sides, such as passive, active, and exploit.
	ExpectedPhases []string `json:"expectedPhases"`
	// RequiredEventTypes must be present on both sides with equal counts.
	RequiredEventTypes []string `json:"requiredEventTypes,omitempty"`
	// ProviderGates make content checks inconclusive when candidate tooling data is
	// unavailable, the provider made no call, or any provider call failed.
	ProviderGates []string `json:"providerGates,omitempty"`
	// AllowCoverageAdded lists entity kinds whose candidate-only keys are expected
	// to vary between collection times.
	AllowCoverageAdded []scandiff.EntityKind `json:"allowCoverageAdded,omitempty"`
	// AllowCoverageRemoved lists entity kinds whose baseline-only keys are expected
	// to vary between collection times.
	AllowCoverageRemoved []scandiff.EntityKind `json:"allowCoverageRemoved,omitempty"`
	// AllowFindingSeverityChanges permits severity drift on an existing finding
	// identity. It does not permit additions or removals, which use the coverage lists.
	AllowFindingSeverityChanges bool `json:"allowFindingSeverityChanges,omitempty"`
}

// Report is the deterministic corpus comparison rendered as JSON and Markdown.
type Report struct {
	// BaselineRoot is the corpus containing the reference scans.
	BaselineRoot string `json:"baselineRoot"`
	// CandidateRoot is the corpus being assessed.
	CandidateRoot string `json:"candidateRoot"`
	// ManifestPath identifies the expectations used for the run.
	ManifestPath string `json:"manifestPath"`
	// Summary counts the three scenario outcomes.
	Summary Summary `json:"summary"`
	// Scenarios retains manifest order for stable, reviewable output.
	Scenarios []ScenarioResult `json:"scenarios"`
}

// Summary counts scenario outcomes across the corpus.
type Summary struct {
	// Total is the number of manifest scenarios.
	Total int `json:"total"`
	// Passed is the number with all applicable checks passing.
	Passed int `json:"passed"`
	// Failed is the number with at least one failed check.
	Failed int `json:"failed"`
	// Inconclusive is the number qualified by a provider gate.
	Inconclusive int `json:"inconclusive"`
}

// ScenarioResult contains one pair's semantic summary, checks, provider gates,
// environment context, and complete coverage delta.
type ScenarioResult struct {
	// Name is the manifest scenario and child-directory name.
	Name string `json:"name"`
	// Status is pass, fail, or inconclusive.
	Status ScenarioStatus `json:"status"`
	// Diff is the semantic event-class summary.
	Diff scandiff.Summary `json:"diff"`
	// Checks contains every structural and content assertion.
	Checks []CheckResult `json:"checks"`
	// Gates explains any provider-caused inconclusive result.
	Gates []ProviderGate `json:"gates,omitempty"`
	// EnvironmentChanges provides non-gating execution context.
	EnvironmentChanges []scandiff.EnvironmentChange `json:"environmentChanges,omitempty"`
	// Coverage is the complete per-kind key delta.
	Coverage []scandiff.CoverageDelta `json:"coverage,omitempty"`
}

// CheckResult records one manifest or structural assertion.
type CheckResult struct {
	// Name is the stable machine-readable assertion name.
	Name string `json:"name"`
	// Status is pass, fail, or skipped.
	Status CheckStatus `json:"status"`
	// Detail contains the observed values or failure reason.
	Detail string `json:"detail"`
}

// ProviderGate explains why a scenario's content verdict is inconclusive.
type ProviderGate struct {
	// Provider is the configured tool name.
	Provider string `json:"provider"`
	// Reason states why its candidate output cannot support a content verdict.
	Reason string `json:"reason"`
}

// ScanAudit is the structural view of one collection needed beside its semantic
// diff. Persistence derives it from the canonical stream and per-type splits.
type ScanAudit struct {
	// Phases is the sorted set of non-empty phases in the canonical stream.
	Phases []string
	// EventCounts maps persisted event type names to their canonical counts.
	EventCounts map[string]int
	// SplitError records a mismatch between the canonical stream and its per-type
	// convenience splits. It is a report check rather than an operational failure.
	SplitError error
}

// ScenarioInput contains the already-loaded values needed to assess one manifest
// scenario. It keeps corpus filesystem discovery outside this policy package.
type ScenarioInput struct {
	// Spec is the checked-in expectation for the scenario.
	Spec ScenarioSpec
	// Baseline is the structural audit of the reference collection.
	Baseline ScanAudit
	// Candidate is the structural audit of the collection being assessed.
	Candidate ScanAudit
	// Diff is the semantic comparison of the same collection pair.
	Diff scandiff.Report
}

// Build evaluates already-loaded scenarios and returns one deterministic corpus
// report. Loading files belongs to internal/projections/persistence; split
// reconciliation defects arrive in [ScanAudit] and become scenario failures.
func Build(baselineRoot, candidateRoot, manifestPath string, scenarios []ScenarioInput) Report {
	report := Report{
		BaselineRoot:  filepath.Clean(baselineRoot),
		CandidateRoot: filepath.Clean(candidateRoot),
		ManifestPath:  filepath.Clean(manifestPath),
		Scenarios:     make([]ScenarioResult, 0, len(scenarios)),
	}
	for _, scenario := range scenarios {
		report.Scenarios = append(report.Scenarios, buildScenario(scenario))
	}
	report.Summary = summarize(report.Scenarios)
	return report
}

// buildScenario evaluates one loaded collection pair against its manifest policy.
func buildScenario(in ScenarioInput) ScenarioResult {
	spec, a, b, diff := in.Spec, in.Baseline, in.Candidate, in.Diff
	result := ScenarioResult{
		Name:               spec.Name,
		Diff:               diff.Summary,
		EnvironmentChanges: diff.Environment.Changes,
		Coverage:           diff.Coverage,
	}

	result.Checks = append(result.Checks,
		check("baseline.splitReconciliation", a.SplitError == nil, errorDetail(a.SplitError, "canonical and per-type events match")),
		check("candidate.splitReconciliation", b.SplitError == nil, errorDetail(b.SplitError, "canonical and per-type events match")),
		check("root", !diff.Summary.RootsDiffer, fmt.Sprintf("baseline=%q candidate=%q", diff.Baseline.Root, diff.Candidate.Root)),
		check("baseline.phases", equalStrings(a.Phases, spec.ExpectedPhases), fmt.Sprintf("actual=%v expected=%v", a.Phases, spec.ExpectedPhases)),
		check("candidate.phases", equalStrings(b.Phases, spec.ExpectedPhases), fmt.Sprintf("actual=%v expected=%v", b.Phases, spec.ExpectedPhases)),
		check("environmentRecord", diff.Environment.Baseline != nil && diff.Environment.Candidate != nil,
			fmt.Sprintf("baseline=%s candidate=%s", presence(diff.Environment.Baseline != nil), presence(diff.Environment.Candidate != nil))),
	)
	for _, eventType := range spec.RequiredEventTypes {
		ac, bc := a.EventCounts[eventType], b.EventCounts[eventType]
		result.Checks = append(result.Checks, check("events."+eventType, ac > 0 && ac == bc,
			fmt.Sprintf("baseline=%d candidate=%d", ac, bc)))
	}

	result.Gates = providerGates(diff.Op, spec.ProviderGates)
	gated := len(result.Gates) > 0
	allowedAdded := kindSet(spec.AllowCoverageAdded)
	allowedRemoved := kindSet(spec.AllowCoverageRemoved)
	for _, coverage := range diff.Coverage {
		result.Checks = append(result.Checks,
			contentCheck("coverage."+string(coverage.Kind)+".added", len(coverage.Added) == 0 || allowedAdded[coverage.Kind], gated,
				fmt.Sprintf("count=%d allowed=%t", len(coverage.Added), allowedAdded[coverage.Kind])),
			contentCheck("coverage."+string(coverage.Kind)+".removed", len(coverage.Removed) == 0 || allowedRemoved[coverage.Kind], gated,
				fmt.Sprintf("count=%d allowed=%t", len(coverage.Removed), allowedRemoved[coverage.Kind])),
		)
	}
	severityChanges := findingSeverityChanges(diff.Events)
	result.Checks = append(result.Checks, contentCheck("findings.severityChanged",
		severityChanges == 0 || spec.AllowFindingSeverityChanges, gated,
		fmt.Sprintf("count=%d allowed=%t", severityChanges, spec.AllowFindingSeverityChanges)))

	result.Status = scenarioStatus(result.Checks, result.Gates)
	return result
}

// ParseManifest decodes and validates a versioned parity manifest. The caller owns
// reading it so this package stays independent of filesystem persistence.
func ParseManifest(b []byte) (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, fmt.Errorf("validate manifest: %w", err)
	}
	return manifest, nil
}

// validateManifest rejects unsupported, ambiguous, or path-escaping scenarios.
func validateManifest(manifest Manifest) error {
	if manifest.Version != 1 {
		return fmt.Errorf("unsupported version %d", manifest.Version)
	}
	if len(manifest.Scenarios) == 0 {
		return errors.New("at least one scenario is required")
	}
	knownKinds := kindSet([]scandiff.EntityKind{
		scandiff.KindDomain, scandiff.KindIP, scandiff.KindService, scandiff.KindEndpoint,
		scandiff.KindCertificate, scandiff.KindFinding, scandiff.KindNetblock,
	})
	knownPhases := map[string]bool{"active": true, "exploit": true, "passive": true}
	seen := make(map[string]struct{}, len(manifest.Scenarios))
	for _, scenario := range manifest.Scenarios {
		if scenario.Name == "" || scenario.Name == "." || scenario.Name == ".." || filepath.Base(scenario.Name) != scenario.Name || filepath.IsAbs(scenario.Name) {
			return fmt.Errorf("scenario name %q must be one relative directory name", scenario.Name)
		}
		if _, ok := seen[scenario.Name]; ok {
			return fmt.Errorf("duplicate scenario %q", scenario.Name)
		}
		seen[scenario.Name] = struct{}{}
		if len(scenario.ExpectedPhases) == 0 {
			return fmt.Errorf("scenario %q requires at least one expected phase", scenario.Name)
		}
		if !sort.StringsAreSorted(scenario.ExpectedPhases) {
			return fmt.Errorf("scenario %q expectedPhases must be sorted", scenario.Name)
		}
		for _, phase := range scenario.ExpectedPhases {
			if !knownPhases[phase] {
				return fmt.Errorf("scenario %q has unknown phase %q", scenario.Name, phase)
			}
		}
		for _, kind := range append(append([]scandiff.EntityKind{}, scenario.AllowCoverageAdded...), scenario.AllowCoverageRemoved...) {
			if !knownKinds[kind] {
				return fmt.Errorf("scenario %q has unknown coverage kind %q", scenario.Name, kind)
			}
		}
	}
	return nil
}

// providerGates evaluates configured candidate providers against operational data.
func providerGates(op scandiff.OpDelta, providers []string) []ProviderGate {
	if len(providers) == 0 {
		return nil
	}
	if !op.Available {
		return []ProviderGate{{Provider: strings.Join(providers, ","), Reason: "tool-event comparison unavailable"}}
	}
	byName := make(map[string]scandiff.ProviderOpDelta, len(op.Providers))
	for _, provider := range op.Providers {
		byName[provider.Provider] = provider
	}
	var gates []ProviderGate
	for _, name := range providers {
		provider, ok := byName[name]
		switch {
		case !ok || provider.BCalls == 0:
			gates = append(gates, ProviderGate{Provider: name, Reason: "candidate made no calls"})
		case provider.BFailed > 0:
			gates = append(gates, ProviderGate{Provider: name, Reason: fmt.Sprintf("candidate failed %d of %d calls", provider.BFailed, provider.BCalls)})
		}
	}
	return gates
}

// findingSeverityChanges counts existing finding identities whose severity moved.
func findingSeverityChanges(diffs []scandiff.EventDiff) int {
	count := 0
	for _, diff := range diffs {
		if diff.Type != "FindingRaised" || diff.Class != scandiff.Changed {
			continue
		}
		for _, change := range diff.Changes {
			if change.Name == "severity" {
				count++
				break
			}
		}
	}
	return count
}

// check creates a pass/fail assertion result.
func check(name string, passed bool, detail string) CheckResult {
	status := CheckFail
	if passed {
		status = CheckPass
	}
	return CheckResult{Name: name, Status: status, Detail: detail}
}

// contentCheck turns a failing content assertion into skipped under a provider gate.
func contentCheck(name string, passed, gated bool, detail string) CheckResult {
	if !passed && gated {
		return CheckResult{Name: name, Status: CheckSkipped, Detail: "provider gate active; " + detail}
	}
	return check(name, passed, detail)
}

// scenarioStatus gives failures priority, then provider inconclusiveness.
func scenarioStatus(checks []CheckResult, gates []ProviderGate) ScenarioStatus {
	for _, result := range checks {
		if result.Status == CheckFail {
			return StatusFail
		}
	}
	if len(gates) > 0 {
		return StatusInconclusive
	}
	return StatusPass
}

// summarize counts corpus outcomes.
func summarize(scenarios []ScenarioResult) Summary {
	summary := Summary{Total: len(scenarios)}
	for _, scenario := range scenarios {
		switch scenario.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusInconclusive:
			summary.Inconclusive++
		}
	}
	return summary
}

// kindSet makes manifest allowance lookup explicit and cheap.
func kindSet(kinds []scandiff.EntityKind) map[scandiff.EntityKind]bool {
	out := make(map[scandiff.EntityKind]bool, len(kinds))
	for _, kind := range kinds {
		out[kind] = true
	}
	return out
}

// equalStrings compares already ordered string slices.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// errorDetail preserves the reason for a failed check or its success explanation.
func errorDetail(err error, success string) string {
	if err != nil {
		return err.Error()
	}
	return success
}

// presence renders a stable present/missing token.
func presence(present bool) string {
	if present {
		return "present"
	}
	return "missing"
}
