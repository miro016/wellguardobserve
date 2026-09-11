package persistence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
)

// ValidateCollection checks that a directory is a collection this build can read,
// and returns its manifest. It is the pre-flight a projection runs before touching a
// destination, so a collection that cannot be projected costs nothing and leaves
// every directory involved alone.
//
// It inspects the collection root directly: manifest.json, events/events.jsonl, the
// two configuration snapshots the manifest names in configs/, the optional
// tool-event log, and the optional packet evidence. Nothing else is required, and no
// path component is inserted - the supplied directory is the collection.
//
// It opens nothing for writing and acquires nothing. A collection is finished
// evidence, so validating one confers no right to add to it and never blocks another
// reader.
//
// Every failure names the collection and the exact input path. A projector is usually
// pointed at a corpus, so "something was missing" is not an answer an analyst can act
// on: the useful report is which collection, and which file in it.
func ValidateCollection(capture string) (*collection.Manifest, error) {
	fail := func(format string, args ...any) (*collection.Manifest, error) {
		return nil, fmt.Errorf("collection %s: %s", capture, fmt.Sprintf(format, args...))
	}

	_, manifest, err := collection.OpenCollection(capture)
	if err != nil {
		return fail("%v", err)
	}

	// The tool-event log is optional - a collection whose tools wrote nothing has
	// none, and the signals and data-quality reports then omit their operational
	// input - but a log that exists must be a file, not a directory left behind by a
	// bad download.
	if f, _, err := collection.ReadToolLog(capture); err != nil {
		return fail("%v", err)
	} else if f != nil {
		if err := f.Close(); err != nil {
			return fail("close tool-event log %s: %v", collection.ToolLogPath(capture), err)
		}
	}

	if err := validateCaptureEvidence(capture); err != nil {
		return nil, fmt.Errorf("collection %s: %w", capture, err)
	}
	return manifest, nil
}

// validateCaptureEvidence checks that recognized packet files and sidecars are
// files, not directories. A capture directory holding only capture.log or
// capture.meta.txt is valid: capture is best-effort, and the projected audit must
// report the packet evidence as absent instead of blocking every other artifact.
// Corrupt and unsupported packet bytes likewise remain model data handled by the
// network-audit projection. A collection with no netaudit tree at all is valid too:
// nothing pre-creates one, so its absence means no capture was taken.
func validateCaptureEvidence(capture string) error {
	dir := netauditDirPath(capture)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("read packet-capture directory %s: %w", dir, err)
	}
	names := append(slices.Clone(captureFileNames), captureLog, captureMeta)
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return fmt.Errorf("inspect packet-capture input %s: %w", path, statErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("packet-capture input %s is not a regular file", path)
		}
	}
	return nil
}
