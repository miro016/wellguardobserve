package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/buildid"
)

var _ DomainEvent = ScanStarted{}
var _ DomainEvent = ScanEnvironmentRecorded{}
var _ DomainEvent = ScanCompleted{}

// ScanStarted marks the beginning of a scan run.
type ScanStarted struct {
	EventMeta
	// RootTarget is the domain the scan was launched against.
	RootTarget string
}

// At returns the capture time recorded in the event envelope.
func (e ScanStarted) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ScanStarted) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable description.
func (e ScanStarted) String() string { return "scan started for " + e.RootTarget }

func (ScanStarted) isDomainEvent() {}

// BuildIdentity identifies the actor that produced an execution: its name and the
// one version identifier its caller chose. It is an alias, not a copy, of the
// shared build identity: the capture manifest records the same value on the
// filesystem, and an alias makes it impossible for the event-stream provenance and
// the manifest provenance of one execution to drift apart.
//
// The version is whatever the caller supplied. A Vanguard command supplies its own
// release; an embedding application supplies whatever its release process uses to
// name a build, which may be a composite naming both itself and Vanguard. Nothing
// here parses it.
type BuildIdentity = buildid.Identity

// RuntimeIdentity identifies external executables used by enabled scanners.
type RuntimeIdentity struct {
	NmapPath      string
	NmapVersion   string
	PythonPath    string
	PythonVersion string
	SslyzeVersion string
}

// EnvironmentSnapshot identifies a dated or content-addressed embedded data set.
type EnvironmentSnapshot struct {
	Name     string
	Version  string
	Released string
	Count    int
	Digest   string
}

// ModuleVersion identifies a build dependency whose behavior affects results.
type ModuleVersion struct {
	Path    string
	Version string
}

// ScanEnvironmentRecorded captures the reproducibility inputs for one execution.
// It is emitted exactly once immediately after ScanStarted.
type ScanEnvironmentRecorded struct {
	EventMeta
	// Actor is the program that ran the collection, as it was identified by whoever
	// started it: a Vanguard command when the collector is one, and the embedding
	// application otherwise. Its version is the caller's opaque identifier for the
	// build, and it is never empty, because a collection refuses to start without one.
	Actor BuildIdentity
	// Runtime is the external executables the enabled scanners resolved.
	Runtime RuntimeIdentity
	// Snapshots is the dated or content-addressed embedded data sets that were in
	// effect.
	Snapshots []EnvironmentSnapshot
	// Modules is the build dependencies whose behavior affects results.
	Modules []ModuleVersion
	// ConfigSHA256 is the digest of the exact engagement and profile the execution
	// ran with, engagement first.
	ConfigSHA256 string
}

// At returns the capture time recorded in the event envelope.
func (e ScanEnvironmentRecorded) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ScanEnvironmentRecorded) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable description.
func (e ScanEnvironmentRecorded) String() string { return "scan environment recorded" }

func (ScanEnvironmentRecorded) isDomainEvent() {}

// ScanCompleted marks the end of a scan run.
type ScanCompleted struct {
	EventMeta
	// RootTarget is the domain the scan was launched against.
	RootTarget string
	// Duration is the total elapsed time of the scan.
	Duration time.Duration
}

// At returns the capture time recorded in the event envelope.
func (e ScanCompleted) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ScanCompleted) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable description.
func (e ScanCompleted) String() string {
	return fmt.Sprintf("scan completed for %s in %s", e.RootTarget, e.Duration.Round(time.Millisecond))
}

func (ScanCompleted) isDomainEvent() {}
