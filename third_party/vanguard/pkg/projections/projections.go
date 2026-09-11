package projections

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/velgard-sk/vanguard/internal/buildid"
	"github.com/velgard-sk/vanguard/internal/projections/persistence"
)

// Options is everything one projection build needs.
type Options struct {
	// CollectionDir is the collection to project: the exact directory the collector
	// wrote. It is required, and nothing in it is ever written.
	CollectionDir string
	// DestinationDir is the exact directory the artifacts are written into. It is
	// required, and it is independent of CollectionDir: Vanguard derives no output
	// path from an input path, so a host may put a projection wherever its own
	// storage policy says.
	//
	// It must be missing or empty. Nothing already there is deleted, renamed, or
	// merged, and a destination that is the collection, sits inside it, or contains it
	// is refused - each of those would turn a build into an edit of its own source.
	// Preparing a disposable destination is the caller's job, because only the caller
	// knows whether those bytes matter.
	DestinationDir string
	// ApplicationName is the name recorded as the projector in the projection
	// manifest, for example the embedding program's command name. It is required and
	// is a name the caller chooses rather than os.Args[0], so a renamed or symlinked
	// executable still reports the program it implements.
	ApplicationName string
	// Version is the identifier recorded beside ApplicationName: the caller's answer
	// to "which build produced this tree". It is opaque, stored verbatim, and never
	// parsed here, so a caller may supply its own release, a Vanguard release, a
	// commit, or a composite naming several of those.
	//
	// It is optional, unlike a collection's. A rebuild folds material the capture
	// already holds and creates no evidence of its own, so an unidentified projector
	// is recorded honestly rather than refused.
	Version string
}

// Builder builds one projection. It is created by [New] and runs exactly once.
type Builder struct {
	collectionDir  string
	destinationDir string
	// projector is the identity recorded for this build, fixed when the builder was
	// created so every artifact of one build is attributed to one actor. It may carry
	// no version, and is then recorded as unidentified rather than refused.
	projector buildid.Identity
	// started guards the single-run rule. One instance owns one destination for the
	// length of one build, and a second build against it would find the directory the
	// first one filled.
	started atomic.Bool
}

// New validates the options and prepares one build. It performs no I/O: an invalid
// option is rejected before the collection is opened or the destination is looked at.
//
// It does not require the caller to identify its build: a rebuild folds material
// the capture already holds, so an unidentified projector is recorded honestly
// rather than refused.
func New(options Options) (*Builder, error) {
	if strings.TrimSpace(options.CollectionDir) == "" {
		return nil, errors.New("projections: CollectionDir is required")
	}
	if strings.TrimSpace(options.DestinationDir) == "" {
		return nil, errors.New("projections: DestinationDir is required")
	}
	if strings.TrimSpace(options.ApplicationName) == "" {
		return nil, errors.New("projections: ApplicationName is required; it names the projector in the projection manifest")
	}
	return &Builder{
		collectionDir:  options.CollectionDir,
		destinationDir: options.DestinationDir,
		projector:      buildid.Unvalidated(options.ApplicationName, options.Version),
	}, nil
}

// Run writes the collection's artifacts into the destination and returns when they
// are complete, or the error that stopped it. A projection is a pure function of the
// collection, so a failed or cancelled build is recovered by running another one into
// a fresh destination.
//
// The collection is validated first, and one that is incomplete or malformed is
// reported with the exact input path that is wrong, before the destination is
// touched. The destination is then checked: it must be missing or empty, and it must
// not be, contain, or sit inside the collection. Nothing is ever deleted to make room.
//
// Cancellation is observed between build steps rather than inside them, so a fold
// already running may finish; what it cannot do is write the projection manifest,
// which is what marks a projection complete. A destination without one is an
// unfinished build.
//
// One builder runs once. A second call, or a concurrent one, is refused rather than
// allowed to write two builds into one destination.
func (b *Builder) Run(ctx context.Context) error {
	if !b.started.CompareAndSwap(false, true) {
		return errors.New("projections: this builder has already been run; create another for another build")
	}
	return persistence.Build(ctx, b.collectionDir, b.destinationDir, b.projector)
}
