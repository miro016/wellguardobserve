package persistence

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeSnapshot writes b into the collection's configs/ tree under name, verbatim
// (comments and formatting preserved) so it serves as the audit record the
// configuration claims to be. The bytes are never re-marshalled or normalized: what
// the operator supplied is what the collection keeps. It creates the tree first, so a
// snapshot writer needs no directory setup from its caller. It returns the written
// path relative to the collection root, in slash form, which is what the manifest
// records.
func writeSnapshot(b []byte, dir, name string) (string, error) {
	snapshots := SnapshotsDir(dir)
	if err := os.MkdirAll(snapshots, 0o755); err != nil {
		return "", fmt.Errorf("create config snapshot dir %s: %w", snapshots, err)
	}
	dst := filepath.Join(snapshots, name)
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return "", fmt.Errorf("write config snapshot %s: %w", dst, err)
	}
	return filepath.ToSlash(filepath.Join(configsDir, name)), nil
}

// SaveSnapshots writes the engagement and scan-profile documents into the
// collection's configs/ tree as engagement.yaml and scan-profile.yaml, and returns
// both collection-relative paths in slash form so the manifest records them. They
// are the collection's one configuration pair: a collection is produced by one
// invocation, so there is one engagement and one profile to keep, and every reader
// resolves them from the manifest rather than by rebuilding a name.
//
// Both are written verbatim, and the tree is created if it does not exist.
//
// It takes bytes rather than paths because the documents a collection ran with may
// never have been files, and because the bytes that were validated are then
// provably the bytes that were recorded.
func SaveSnapshots(engagementYAML, profileYAML []byte, dir string) (engagement, profile string, err error) {
	engagement, err = writeSnapshot(engagementYAML, dir, engagementSnapshot)
	if err != nil {
		return "", "", err
	}
	profile, err = writeSnapshot(profileYAML, dir, scanProfileSnapshot)
	if err != nil {
		return "", "", err
	}
	return engagement, profile, nil
}
