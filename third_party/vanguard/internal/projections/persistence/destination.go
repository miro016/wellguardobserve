package persistence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PrepareDestination makes dir usable as the root of one projection and returns the
// cleaned path every writer below then works from. It is the first filesystem
// decision a build makes, taken before a single artifact is rendered, so a
// destination that cannot be used costs nothing.
//
// The rule is the collection half's rule, stated again here because the two phases
// answer to different callers and their errors belong to different vocabularies: a
// missing directory is created, an existing one must be a real, empty directory, and
// a file, a symlink standing in for the root, or a directory with contents is
// refused. Nothing is deleted, renamed, backed up, staged, or swapped. A caller that
// wants to replace a previous projection empties or chooses the destination first,
// because only the caller knows whether those bytes are disposable.
//
// collectionDir is the source this build reads. It is checked against the
// destination rather than merely remembered: a projection that wrote into its own
// input - or into a parent of it - would destroy or contaminate the only evidence
// there is, and it would do so after the read that made the artifacts look correct.
// Equal roots and either containing the other are all refused.
//
// The emptiness check is not a lock. Two builds can both pass it and then interleave
// their writes; exclusive ownership of a destination stays the caller's.
func PrepareDestination(collectionDir, dir string) (string, error) {
	source, err := cleanRoot(collectionDir, "collection directory")
	if err != nil {
		return "", err
	}
	dst, err := cleanRoot(dir, "projection destination")
	if err != nil {
		return "", err
	}
	if err := requireDisjoint(source, dst); err != nil {
		return "", err
	}
	if err := makeEmptyDir(dst, "projection destination", "a build"); err != nil {
		return "", err
	}
	return dst, nil
}

// prepareOutput makes dir usable as the destination of one multi-collection
// operation - a diff, a corpus parity report, a corpus signal report - and returns
// the cleaned path the writers then work from.
//
// It is [PrepareDestination]'s rule for an operation that has no single collection to
// be checked against: the destination must be missing or an empty directory, nothing
// is deleted to make room, and it must be disjoint from every root the operation
// reads, so a comparison can never write into one of the sides it is comparing. Each
// such operation names its own destination, because two of them sharing one directory
// would make the second fail the emptiness check for no reason the operator asked
// for.
func prepareOutput(dir string, sources ...string) (string, error) {
	dst, err := cleanRoot(dir, "output directory")
	if err != nil {
		return "", err
	}
	for _, src := range sources {
		source, err := cleanRoot(src, "input directory")
		if err != nil {
			return "", err
		}
		if err := requireDisjoint(source, dst); err != nil {
			return "", err
		}
	}
	if err := makeEmptyDir(dst, "output directory", "this report"); err != nil {
		return "", err
	}
	return dst, nil
}

// makeEmptyDir creates dst when it is missing and otherwise insists it is a real,
// empty directory. what names the directory in an error and needs is what the error
// says required it, so the two callers keep their own vocabulary.
func makeEmptyDir(dst, what, needs string) error {
	info, err := os.Lstat(dst)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return fmt.Errorf("create %s %s: %w", what, dst, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s %s: %w", what, dst, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s is a symlink; supply the directory itself", what, dst)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %s is not a directory", what, dst)
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		return fmt.Errorf("read %s %s: %w", what, dst, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s %s is not empty; %s needs a missing or empty destination "+
			"(empty it, or choose another, before writing again)", what, dst, needs)
	}
	return nil
}

// requireDisjoint refuses a destination that is the collection, contains it, or sits
// inside it. Each of those turns a build into an edit of its own source, and the
// first two would delete or bury evidence that nothing regenerates.
func requireDisjoint(source, dst string) error {
	if strings.EqualFold(source, dst) || source == dst {
		return fmt.Errorf("destination %s is the collection it reads; output is written beside its source, never into it", dst)
	}
	if within(dst, source) {
		return fmt.Errorf("destination %s is inside the collection %s; a collection holds evidence only", dst, source)
	}
	if within(source, dst) {
		return fmt.Errorf("destination %s contains the collection %s it reads; preparing it would destroy the source", dst, source)
	}
	return nil
}

// within reports whether path sits below root. It is a lexical test on cleaned,
// absolute paths: enough to catch the mistakes a caller actually makes, and honest
// about being no defence against a symlink that leaves the tree.
func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// cleanRoot rejects a blank path and returns the absolute, cleaned form the checks
// above compare, so two spellings of one directory cannot pass a test that the other
// would fail.
func cleanRoot(dir, what string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("%s is mandatory", what)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve %s %s: %w", what, dir, err)
	}
	return filepath.Clean(abs), nil
}
