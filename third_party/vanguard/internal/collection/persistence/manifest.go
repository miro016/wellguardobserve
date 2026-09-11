package persistence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/buildid"
	"github.com/velgard-sk/vanguard/internal/collection/config"
)

// manifestRenameAttempts and manifestRenameDelay bound the atomic-replace retry
// used by Save on hosts where another process can briefly hold the destination.
const (
	manifestRenameAttempts = 50
	manifestRenameDelay    = 20 * time.Millisecond
)

// CollectionStatus is how a collection ended. It exists because an attempt that did
// not finish must still be visible: a collection that failed or was interrupted has
// partial streams, and pretending the attempt never happened would leave half-written
// events in a directory nothing describes.
type CollectionStatus string

const (
	// StatusRunning is written before any tool starts and means the collector either
	// is still running or died without recording an outcome. Nothing repairs it
	// later: a collection directory is claimed once, so a run that never reported a
	// terminal status stays running forever, and its evidence is read as partial.
	StatusRunning CollectionStatus = "running"
	// StatusSucceeded means every phase the collection ran completed cleanly and no
	// tool reported lost work.
	StatusSucceeded CollectionStatus = "succeeded"
	// StatusDegraded means the collection ran to a conclusion and wrote its streams
	// cleanly, but at least one tool reported collection work it attempted and lost.
	// The evidence it did collect is kept and is exactly as trustworthy as it looks;
	// what is missing is described by the health summary.
	StatusDegraded CollectionStatus = "degraded"
	// StatusFailed means the collector ran to a conclusion and reported an error.
	StatusFailed CollectionStatus = "failed"
	// StatusInterrupted means the collector was cancelled and recorded that before
	// exiting.
	StatusInterrupted CollectionStatus = "interrupted"
)

// Manifest is manifest.json: the one authority for what a collection is.
//
// A collection directory holds one collection, produced by one invocation, so the
// manifest describes that invocation directly. There is no ledger of attempts and
// no sequence number: a run that failed leaves its own directory saying so, and the
// retry is a new collection somewhere else.
//
// It makes the collection self-describing on the filesystem: which collector build
// produced it, when it started, when it ended, how it ended, which phases it was
// asked to run, and which configuration documents it ran with. None of that requires
// decoding the event stream, so an analyst can identify a downloaded collection with
// cat.
type Manifest struct {
	// ScanID is the run identity, the same one the event stream carries.
	ScanID string `json:"scanID"`
	// Root is the scan root (estate) every discovery started from.
	Root string `json:"root"`
	// Status is the outcome. It is StatusRunning from the moment the collection
	// starts until it reaches a terminal state.
	Status CollectionStatus `json:"status"`
	// Phases is the phase set the collection was asked to run, by name. It states
	// what was attempted; whether it finished is Status, not this field.
	Phases []string `json:"phases"`
	// StartedAt is the UTC instant the collection began, stamped before any tool
	// ran. It dates the collection.
	StartedAt time.Time `json:"startedAt"`
	// CompletedAt is the UTC instant the collection reached its terminal status. It
	// is zero while it is running, and omitzero keeps the field out of the file
	// entirely then, so nobody reads year 1 as a completion time.
	CompletedAt time.Time `json:"completedAt,omitzero"`
	// Engagement is the path, relative to the collection root, of the verbatim
	// engagement snapshot the collection ran with.
	Engagement string `json:"engagement"`
	// Profile is the path, relative to the collection root, of the verbatim
	// scan-profile snapshot it ran with.
	Profile string `json:"profile"`
	// Collector is the identity of the program that produced the collection: its
	// name and the one opaque version identifier its caller chose. It is the same
	// value the ScanEnvironmentRecorded event carries, because both are written from
	// the identity the collection was created with rather than resolved twice.
	Collector buildid.Identity `json:"collector"`
	// Health is the collection-health summary, present only when a tool reported
	// lost work. It is what makes a degraded collection readable without decoding
	// the tool stream: which problem, from which tool and component, how many times.
	// A clean collection carries none.
	Health *CollectionHealth `json:"health,omitempty"`
}

// CollectionHealth summarizes the collection work the run attempted and lost. It is
// a count, not a log: the per-event evidence is the tool stream, and duplicating
// targets, error text, or timestamps here would create a second account of the same
// events that could disagree with the first.
type CollectionHealth struct {
	// Total is the number of health-bearing tool events observed, counting repeats.
	Total int `json:"total"`
	// Problems are the distinct problem identities and their counts, sorted by code,
	// tool, then component. The order is part of the format: two runs that lost the
	// same work write the same bytes.
	Problems []HealthProblemCount `json:"problems"`
}

// HealthProblemCount is one problem identity and how many events reported it.
type HealthProblemCount struct {
	// Code is the stable lower-case dotted identity owned by the producing tool.
	Code string `json:"code"`
	// Tool is the tool that reported it.
	Tool string `json:"tool"`
	// Component is the provider or module inside that tool, when it named one.
	Component string `json:"component,omitempty"`
	// Count is the number of events that reported this identity. It is positive.
	Count int `json:"count"`
}

// NewManifest builds the running manifest of a collection: its identity, the phase
// set it was asked to run, its start, the configuration snapshots it ran with, and
// the collector that produced it. The caller saves it before any tool starts and
// closes it with [Manifest.Complete].
func NewManifest(scanID, root string, phases config.PhaseSet, started time.Time,
	engagement, profile string, collector buildid.Identity) *Manifest {
	return &Manifest{
		ScanID:     scanID,
		Root:       root,
		Status:     StatusRunning,
		Phases:     phases.Names(),
		StartedAt:  started.UTC(),
		Engagement: engagement,
		Profile:    profile,
		Collector:  collector,
	}
}

// Complete moves the collection to a terminal status, recording the optional
// collection-health summary in the same transition.
//
// Status and summary are set together, and there is deliberately no second setter
// for the summary alone: the two describe one outcome, and a collection whose status
// and health disagree is worse than one that has neither.
func (m *Manifest) Complete(status CollectionStatus, completed time.Time, health *CollectionHealth) error {
	switch status {
	case StatusSucceeded, StatusDegraded, StatusFailed, StatusInterrupted:
	case StatusRunning:
		return fmt.Errorf("complete collection: %q is not a terminal status", status)
	default:
		return fmt.Errorf("complete collection: unknown terminal status %q", status)
	}
	m.Status = status
	m.CompletedAt = completed.UTC()
	m.Health = health
	if err := validateHealth(m); err != nil {
		return fmt.Errorf("complete collection: %w", err)
	}
	return nil
}

// LoadManifest reads the collection manifest under root. The boolean reports whether
// a manifest existed: a missing file is (nil, false, nil), an unwritten destination,
// not an error. A present-but-unreadable or malformed manifest is an error naming
// exactly what was wrong, because the alternative is projecting a collection whose
// shape is not the one this build understands. The manifest carries no format
// version: a collection this build cannot read is replaced rather than converted.
func LoadManifest(root string) (*Manifest, bool, error) {
	path := manifestPath(root)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read collection manifest: %w", err)
	}
	if err := rejectExecutionLedger(b); err != nil {
		return nil, true, fmt.Errorf("collection manifest %s: %w", path, err)
	}
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return nil, true, fmt.Errorf("parse collection manifest %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, true, fmt.Errorf("parse collection manifest %s: trailing content: %w", path, err)
	}
	if m.ScanID == "" || m.Root == "" {
		return nil, true, fmt.Errorf("collection manifest %s names no scanID or root", path)
	}
	if err := validateManifest(&m); err != nil {
		return nil, true, fmt.Errorf("collection manifest %s is not the current structure: %w", path, err)
	}
	return &m, true, nil
}

// rejectExecutionLedger reports the one malformed shape worth naming: the resumable
// collection format, whose manifest carried an array of executions against one
// directory. It is reported as unsupported rather than as an unknown field, because
// the difference matters to whoever holds the collection - the bytes are readable,
// this build simply does not implement the model they describe, and nothing here
// converts them.
func rejectExecutionLedger(b []byte) error {
	var probe struct {
		Executions []json.RawMessage `json:"executions"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil
	}
	if len(probe.Executions) == 0 {
		return nil
	}
	return errors.New("records an executions array: that is the resumable multi-execution format, " +
		"which this build does not read and does not convert")
}

// validateManifest enforces the invariants the writer maintains. Accepting missing
// or contradictory fields would turn malformed collection metadata into apparently
// valid provenance.
func validateManifest(m *Manifest) error {
	if strings.TrimSpace(m.ScanID) == "" || strings.TrimSpace(m.Root) == "" {
		return errors.New("scanID and root must be non-empty")
	}
	if m.StartedAt.IsZero() || !isUTC(m.StartedAt) {
		return errors.New("startedAt must be set in UTC")
	}
	if err := validatePhaseNames("phases", m.Phases); err != nil {
		return err
	}
	if strings.TrimSpace(m.Engagement) == "" || strings.TrimSpace(m.Profile) == "" {
		return errors.New("the manifest must name its engagement and profile snapshots")
	}
	// A collection is evidence, and evidence whose producer cannot be named can be
	// neither reproduced nor blamed for a defect. The collector refuses to start
	// without both halves, so a manifest missing either was not written by a
	// collection this build understands.
	if strings.TrimSpace(m.Collector.Name) == "" || !m.Collector.Identified() {
		return errors.New("the collector must name itself and the version it ran")
	}
	return validateStatus(m)
}

// validateStatus checks the outcome against its timing and its health summary.
func validateStatus(m *Manifest) error {
	switch m.Status {
	case StatusRunning:
		if !m.CompletedAt.IsZero() {
			return errors.New("the collection is running but has completedAt")
		}
		if m.Health != nil {
			return errors.New("the collection is running but carries a health summary")
		}
		return nil
	case StatusSucceeded, StatusDegraded, StatusFailed, StatusInterrupted:
		if m.CompletedAt.IsZero() || !isUTC(m.CompletedAt) {
			return fmt.Errorf("completedAt must be set in UTC for status %q", m.Status)
		}
		if m.CompletedAt.Before(m.StartedAt) {
			return errors.New("completedAt precedes startedAt")
		}
		return validateHealth(m)
	default:
		return fmt.Errorf("unknown status %q", m.Status)
	}
}

// validateHealth enforces the pairing between a terminal status and its health
// summary. The two are written in one transition and must stay consistent: a
// succeeded collection that carried problems would claim work it never finished, and
// a degraded collection without a summary would claim a loss it cannot describe.
func validateHealth(m *Manifest) error {
	health := m.Health
	if m.Status == StatusSucceeded && health != nil && (health.Total > 0 || len(health.Problems) > 0) {
		return errors.New("the collection succeeded but reports collection problems")
	}
	if m.Status == StatusDegraded && (health == nil || health.Total <= 0 || len(health.Problems) == 0) {
		return errors.New("the collection is degraded but describes no collection problem")
	}
	if health == nil {
		return nil
	}
	sum := 0
	var prev HealthProblemCount
	for i, problem := range health.Problems {
		if strings.TrimSpace(problem.Code) == "" || strings.TrimSpace(problem.Tool) == "" {
			return fmt.Errorf("health problem %d names no code or tool", i+1)
		}
		if problem.Count <= 0 {
			return fmt.Errorf("health problem %q has a non-positive count", problem.Code)
		}
		if i > 0 && !healthProblemLess(prev, problem) {
			return errors.New("health problems must be unique and sorted by code, tool, then component")
		}
		prev = problem
		sum += problem.Count
	}
	if sum != health.Total {
		return fmt.Errorf("health problem counts sum to %d but total is %d", sum, health.Total)
	}
	return nil
}

// healthProblemLess is the canonical health-problem order, and therefore also the
// uniqueness test: equal rows are not less than each other.
func healthProblemLess(a, b HealthProblemCount) bool {
	if a.Code != b.Code {
		return a.Code < b.Code
	}
	if a.Tool != b.Tool {
		return a.Tool < b.Tool
	}
	return a.Component < b.Component
}

// validatePhaseNames requires the closed phase vocabulary in canonical order. A
// canonical array makes the manifest deterministic and rejects duplicates instead of
// silently collapsing them into a set on the way out.
func validatePhaseNames(field string, names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("%s must not be empty", field)
	}
	canonical := config.PhaseSetFromNames(names).Names()
	if !slices.Equal(names, canonical) {
		return fmt.Errorf("%s %v must contain only known phases once each in canonical order", field, names)
	}
	return nil
}

// isUTC checks the offset rather than the location name because JSON timestamps
// preserve an offset, not Go's time.Location pointer.
func isUTC(at time.Time) bool {
	_, offset := at.Zone()
	return offset == 0
}

// Save writes the manifest to manifest.json atomically (write to a temp
// file, then rename). The atomic rename keeps a crash mid-write from leaving a
// truncated manifest, which matters because both transitions rewrite the whole file
// and one of them happens just before the collector does real work. The collection
// directory is created if it does not exist.
func (m *Manifest) Save(root string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal collection manifest: %w", err)
	}
	dst := manifestPath(root)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create collection dir %s: %w", filepath.Dir(dst), err)
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write collection manifest temp: %w", err)
	}
	if err := replaceManifest(tmp, dst); err != nil {
		cleanupErr := os.Remove(tmp)
		if errors.Is(cleanupErr, os.ErrNotExist) {
			cleanupErr = nil
		}
		return fmt.Errorf("replace collection manifest: %w", errors.Join(err, cleanupErr))
	}
	return nil
}

// replaceManifest retries the atomic rename briefly. A status reader, antivirus,
// or indexer can transiently block replacement on Windows even though both paths
// are valid and on the same filesystem.
func replaceManifest(from, to string) error {
	var err error
	for range manifestRenameAttempts {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(manifestRenameDelay)
	}
	return err
}
