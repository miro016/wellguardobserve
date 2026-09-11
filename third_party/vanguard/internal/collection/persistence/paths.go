package persistence

import "path/filepath"

// The collection tree this package reads and writes. Every name is joined below the
// exact collection directory the caller supplied: this package inserts no enclosing
// component of its own, so a collection directory is the root of its own data and
// can be moved anywhere without changing what any of these joins mean.
const (
	eventsDir   = "events"
	configsDir  = "configs"
	toolsDir    = "tools"
	netauditDir = "netaudit"

	eventsLog    = "events.jsonl"
	manifestName = "manifest.json"
	toolingLog   = "tooling.jsonl"
	readmeName   = "README.md"

	engagementSnapshot  = "engagement.yaml"
	scanProfileSnapshot = "scan-profile.yaml"
)

// eventsDirPath returns the directory holding the domain-event log and its
// per-type splits.
func eventsDirPath(dir string) string {
	return filepath.Join(dir, eventsDir)
}

// eventsLogPath returns the canonical, ordered, versioned domain-event log: the
// source of truth for everything folded back out of a collection.
func eventsLogPath(dir string) string {
	return filepath.Join(eventsDirPath(dir), eventsLog)
}

// eventsTypePath returns the per-type split for typeName. The splits are a
// human-friendly convenience mirror of the canonical log, never a second authority.
func eventsTypePath(dir, typeName string) string {
	return filepath.Join(eventsDirPath(dir), "events_"+typeName+".jsonl")
}

// manifestPath returns the collection manifest: the single authority for a
// collection's identity, outcome, and provenance.
func manifestPath(dir string) string {
	return filepath.Join(dir, manifestName)
}

// EventsLogPath names the canonical domain-event log of the collection at dir.
// It is exported for readers outside this package that must report the exact file
// they could not use; nothing outside this package opens the collection's streams
// by rebuilding a path, because a writer is free to change where the bytes live.
func EventsLogPath(dir string) string {
	return eventsLogPath(dir)
}

// EventsDir names the directory holding the canonical domain-event log and its
// per-type splits, for a reader that inspects the splits themselves rather than
// folding the canonical stream.
func EventsDir(dir string) string {
	return eventsDirPath(dir)
}

// SnapshotsDir returns the collection's configuration snapshot tree. Readers need
// it to confirm that a manifest-recorded snapshot path stays inside the collection;
// they do not rebuild the individual file names, which are this package's to change.
func SnapshotsDir(dir string) string {
	return filepath.Join(dir, configsDir)
}

// EngagementSnapshotPath returns the engagement snapshot [SaveSnapshots] wrote. It
// is the fallback for a reader working on a directory whose manifest is missing or
// unreadable and which therefore names no snapshot path of its own.
func EngagementSnapshotPath(dir string) string {
	return filepath.Join(SnapshotsDir(dir), engagementSnapshot)
}

// ToolLogDir returns the directory holding the canonical tool-event log and the
// per-tool text logs.
func ToolLogDir(dir string) string {
	return filepath.Join(dir, toolsDir)
}

// ToolLogPath returns the canonical, ordered, interleaved tool/system-event log:
// the stream every tool sink appends its envelopes to.
func ToolLogPath(dir string) string {
	return filepath.Join(ToolLogDir(dir), toolingLog)
}

// ToolTextLogPath returns the per-tool human-readable text log for tool. It sits
// beside the canonical log and carries the same events in the plain form an
// operator reads while a scan runs.
func ToolTextLogPath(dir, tool string) string {
	return filepath.Join(ToolLogDir(dir), "tool_"+tool+".log")
}

// NetAuditDir returns the directory holding the collection's packet capture: one
// immutable set, written directly below it. The captures are written by the external
// capture wrapper rather than by this package; it names the bucket because the
// bucket is part of the collection layout this package documents.
func NetAuditDir(dir string) string {
	return filepath.Join(dir, netauditDir)
}
