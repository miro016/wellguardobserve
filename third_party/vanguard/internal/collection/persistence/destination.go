package persistence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// prepareFresh makes dir usable as the root of a new collection, or refuses and
// leaves it exactly as it was.
//
// The rule is deliberately small: a missing directory is created, an existing one
// must be a real, empty directory, and anything else - a file, a symlink standing in
// for the root, a directory with contents - is an error. Nothing is deleted,
// renamed, backed up, or merged. A caller that wants to replace disposable output
// empties or chooses its destination before calling, because only the caller knows
// whether the bytes already there are disposable.
//
// The emptiness check is not a lock. Two processes can both pass it and then
// interleave their writes; exclusive ownership of a collection directory remains the
// caller's responsibility.
func prepareFresh(dir string) (string, error) {
	dir, err := cleanDestination(dir)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create collection directory %s: %w", dir, err)
		}
		return dir, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect collection directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("collection directory %s is a symlink; supply the directory itself", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("collection destination %s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read collection directory %s: %w", dir, err)
	}
	if len(entries) > 0 {
		return "", fmt.Errorf("collection directory %s is not empty; a collection directory is claimed once, "+
			"so collecting again means naming another destination", dir)
	}
	return dir, nil
}

// openCollection checks that dir holds a collection this build can read, and returns
// its manifest. It writes nothing and acquires nothing: a reader is one of many, and
// a collection is finished evidence, so a rejected collection leaves every byte where
// it was and names the exact path that failed.
//
// It is stricter than "there is something here": it requires the manifest, the
// canonical event log, and the two configuration snapshots the manifest records. A
// directory with contents but no manifest is an error rather than an empty
// collection, because the difference between "nothing was collected" and "this is
// not a collection" is exactly what a reader needs to be told.
func openCollection(dir string) (string, *Manifest, error) {
	dir, err := cleanDestination(dir)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", nil, fmt.Errorf("open collection %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", nil, fmt.Errorf("open collection %s: not a directory", dir)
	}

	manifest, existed, err := LoadManifest(dir)
	if err != nil {
		return "", nil, fmt.Errorf("open collection %s: %w", dir, err)
	}
	if !existed {
		return "", nil, fmt.Errorf("open collection %s: no collection manifest at %s", dir, manifestPath(dir))
	}
	if err := requireRegular(eventsLogPath(dir), "canonical event log"); err != nil {
		return "", nil, fmt.Errorf("open collection %s: %w", dir, err)
	}
	eventsInCollection, err := LoadEvents(dir)
	if err != nil {
		return "", nil, fmt.Errorf("open collection %s: canonical event log %s is unreadable: %w", dir, eventsLogPath(dir), err)
	}
	if err := validateEventIdentity(eventsInCollection, manifest); err != nil {
		return "", nil, fmt.Errorf("open collection %s: canonical event log %s: %w", dir, eventsLogPath(dir), err)
	}
	if err := validateSnapshots(dir, manifest); err != nil {
		return "", nil, fmt.Errorf("open collection %s: %w", dir, err)
	}
	return dir, manifest, nil
}

// validateEventIdentity binds the canonical stream to its manifest: a ScanStarted in
// the log must name the same scan and root the manifest does.
//
// A stream with no start is accepted unless the collection claims to have concluded.
// A process can die between saving its running manifest and emitting ScanStarted,
// and that collection is still readable as the partial evidence it is; one that
// recorded a conclusion cannot have skipped its own opening event.
//
// More than one start is tolerated and checked the same way. One invocation emits
// one, so a second means a corrupt or concatenated log, and the useful response is
// to hold every start to the same identity rather than to guess which is real.
func validateEventIdentity(eventsInCollection []events.DomainEvent, manifest *Manifest) error {
	starts := 0
	for _, raw := range eventsInCollection {
		started, ok := events.AsValue(raw).(events.ScanStarted)
		if !ok {
			continue
		}
		starts++
		if started.ScanID != manifest.ScanID || started.RootTarget != manifest.Root {
			return fmt.Errorf("ScanStarted names scanID %q and root %q, manifest names scanID %q and root %q",
				started.ScanID, started.RootTarget, manifest.ScanID, manifest.Root)
		}
	}
	if starts == 0 && (manifest.Status == StatusSucceeded || manifest.Status == StatusDegraded) {
		return errors.New("contains no ScanStarted event")
	}
	return nil
}

// validateSnapshots requires the manifest-recorded engagement and profile snapshots
// to be regular files inside the collection's configs/ tree. A collection whose
// recorded inputs are missing cannot be reproduced or judged, and a malformed
// manifest must not make a reader inspect an unrelated host path.
func validateSnapshots(dir string, manifest *Manifest) error {
	snapshots := SnapshotsDir(dir)
	info, err := os.Lstat(snapshots)
	if err != nil {
		return fmt.Errorf("inspect configuration snapshot tree %s: %w", snapshots, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("configuration snapshot tree %s is not a directory", snapshots)
	}
	for _, relative := range []string{manifest.Engagement, manifest.Profile} {
		if relative == "" {
			return errors.New("the manifest records no config snapshot path")
		}
		path := filepath.Clean(filepath.Join(dir, filepath.FromSlash(relative)))
		inside, err := filepath.Rel(snapshots, path)
		if err != nil || inside == "." || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
			return fmt.Errorf("config snapshot %q resolves outside %s", relative, snapshots)
		}
		if err := requireRegular(path, "config snapshot"); err != nil {
			return err
		}
	}
	return nil
}

// requireRegular reports why path cannot be used as what it is meant to be, or nil
// when it is a regular file. A directory or a symlink where a stream belongs is the
// signature of a broken copy, and reporting it here is cheaper than discovering it
// halfway through a read.
func requireRegular(path, what string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s %s is missing: %w", what, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s is not a regular file", what, path)
	}
	return nil
}

// cleanDestination rejects a blank path and returns the cleaned form every other
// check and join in this package works from, so one spelling of a destination
// cannot pass a check that another spelling would fail.
func cleanDestination(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("collection directory is mandatory")
	}
	return filepath.Clean(dir), nil
}
