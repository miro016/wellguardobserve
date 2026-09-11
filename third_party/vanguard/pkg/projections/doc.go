// Package projections is the public API for Vanguard's projection stage: it builds
// one collection's complete set of artifacts, offline, from the streams that
// collection already holds. It is the embeddable form of what the
// vanguard-projections build command does.
//
// # Using it
//
// One build is one [Builder]:
//
//	builder, err := projections.New(projections.Options{
//		CollectionDir:   collection,  // the exact collection to read
//		DestinationDir:  destination, // the exact directory to write, missing or empty
//		ApplicationName: "example-analyst-console",
//	})
//	if err != nil {
//		return err
//	}
//	return builder.Run(ctx)
//
// A corpus is one builder per collection. There is no corpus operation here, because
// the order, whether a broken collection stops the rest, where each destination goes,
// and what gets reported are the calling application's policy rather than this
// package's.
//
// # Offline by construction
//
// A build reads one collection and writes one destination. It contacts no target, no
// provider, and no VM, and it writes nothing into the collection. That is not a
// promise made in prose only: this package links no collection tool and no
// orchestration code, so a rebuild cannot reach a target even if a future refactor
// tried to make it. It is what lets an analyst rebuild reports on their own machine
// from collections whose engagements authorized traffic that must never be repeated
// there.
//
// The companion package for the other stage is
// github.com/velgard-sk/vanguard/pkg/collect. Neither package imports the other,
// and they exchange no Go value: the collection directory on disk is the whole
// contract between them.
//
// # What is in this API, and what is not
//
// Public here: building one collection's complete set of artifacts ([Builder]).
//
// Deliberately not public: individual artifacts, report models, folds, detectors,
// entities, and what the destination is called inside. There is no per-artifact
// build, by design - everything is written together, so a destination is never a
// mixture of two rule versions. Collection comparison (diff), corpus parity, and
// corpus tool-health signals remain command-only features of vanguard-projections in
// this cut.
//
// # Ownership and mutation rules
//
// A [Builder] runs once against one pair of directories: a second Run, or a
// concurrent one, is refused. Separate instances may build separate collections
// concurrently; two builds must never share one destination.
//
// A build deletes nothing. The destination must be missing or empty, and it must not
// be, contain, or sit inside the collection - each of those would turn a build into
// an edit of its own source. Replacing a previous projection is the caller's move,
// made by emptying or choosing the destination first, because only the caller knows
// whether those bytes are disposable. A projection is a pure function of a collection
// this package never writes, so a superseded one is reproducible rather than
// precious.
//
// What that leaves is one honest signal instead of an atomicity guarantee. The
// projection manifest is written last, so its presence is the claim that everything
// beside it is complete; a build that fails or is cancelled leaves a destination
// without one. Validation runs before the destination is prepared, so a collection
// that cannot be projected at all creates nothing.
//
// What the destination holds - which buckets, which file names - is private. A caller
// names two directories and gets the artifacts.
//
// # Cancellation
//
// Cancellation is the caller's, through the context passed to [Builder.Run], and it
// is observed between steps rather than inside them: before the collection is
// validated, between artifact families, and before the completion manifest. A fold
// already running finishes before the next check sees the cancellation, which costs a
// stopping caller a little work and keeps every fold a pure function of the
// collection it reads.
//
// What cancellation cannot do is leave a destination that claims to be complete.
// Whichever checkpoint observes it, the manifest is not written, so the next reader
// can tell an interrupted build from a finished one.
//
// # Nothing is printed
//
// A build writes files and returns an error. It writes to no process stream, so an
// embedding application decides what its own users see and when.
//
// # Provenance
//
// A projection records who produced it as one identity: Options.ApplicationName
// and Options.Version, both supplied by the caller and both stored verbatim. The
// version is opaque here exactly as it is for a collection - the caller may supply
// its own release, a Vanguard release, a commit, or a composite naming several -
// and nothing in this package parses it.
//
// Unlike a collection, a build with no version is recorded as unidentified rather
// than refused: a projection folds material the collection already holds and invents
// no evidence, so refusing an offline rebuild would cost an operator the report and
// protect nothing.
//
// # Stability
//
// This API is experimental and may change between commits. Pin a module version or
// a commit.
package projections
