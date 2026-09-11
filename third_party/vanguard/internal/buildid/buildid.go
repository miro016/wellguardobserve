package buildid

import (
	"errors"
	"fmt"
	"strings"
)

// Identity is the identity of the actor that ran one stage: the name it reports
// itself under, and the version identifier its caller chose for the build. It is
// written verbatim into the capture manifest, the projected manifest, and the
// ScanEnvironmentRecorded domain event, so its JSON field names are part of those
// on-disk formats.
type Identity struct {
	// Name is the program that ran, for example "vanguard-collect" or an embedding
	// application's own command name. It is supplied by the caller rather than read
	// from os.Args, so a renamed or symlinked executable still reports the program it
	// implements.
	Name string `json:"name"`
	// Version is the caller's identifier for the build that ran. It is opaque: a
	// release tag, a commit, a composite naming a host and a Vanguard release, or any
	// other stable string the caller's release process understands. Vanguard records
	// it and compares it, and never parses, splits, or normalizes it.
	//
	// It is empty only where the stage's own policy allows an unidentified actor,
	// which is projection and not collection.
	Version string `json:"version,omitempty"`
}

// ErrUnidentified reports an actor that carries no version identifier, so nothing
// on disk could later say which build produced the result.
var ErrUnidentified = errors.New("no version identifier was supplied for the build")

// Current builds the identity of an actor that must be identifiable, and fails
// when it is not. It is the collection rule: a capture is evidence, and evidence
// whose producer cannot be named can be neither reproduced nor blamed for a
// defect. Callers resolve it before opening a sink or starting a tool, so an
// unidentified build writes nothing and contacts nothing.
func Current(name, version string) (Identity, error) {
	id := Identity{Name: name, Version: version}
	if err := validate(id); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// Unvalidated builds the identity of an actor that need not be identifiable. It is
// the projection rule: a rebuild folds material a capture already holds, so
// recording "built by an unidentified projector" is worth more than refusing to
// rebuild a report.
func Unvalidated(name, version string) Identity {
	return Identity{Name: name, Version: version}
}

// Identified reports whether this identity names a version at all. It is the one
// question business logic asks about the value itself; everything else treats it
// as opaque.
func (id Identity) Identified() bool {
	return strings.TrimSpace(id.Version) != ""
}

// validate enforces the two rules that make an identity worth recording: the actor
// is named, and the build it ran is named. Whitespace-only values are treated as
// absent, but a value that passes is stored exactly as the caller supplied it.
func validate(id Identity) error {
	if strings.TrimSpace(id.Name) == "" {
		return errors.New("build identity: no actor name supplied")
	}
	if !id.Identified() {
		return fmt.Errorf("build identity for %s: %w", id.Name, ErrUnidentified)
	}
	return nil
}
