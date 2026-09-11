// Package persistence is the projection phase's filesystem. It is the only
// projection package that opens a collection file or writes a projection file:
// everything below it folds decoded values or renders bytes, and everything above it
// is a caller naming two directories.
//
// # Two explicit roots, and they are never the same tree
//
// [Build] reads the collection at one root and writes every artifact below another.
// Both are the caller's, both are exact, and neither is derived from the other. This
// package inserts no enclosing component - there is no projected/ bucket and no
// capture parent - so a projection directory is complete and movable, and a
// collection is only ever read.
//
// [PrepareDestination] enforces the separation before a single artifact is rendered.
// A destination that is the collection, sits inside it, or contains it is refused,
// because each of those turns a build into an edit of its own source - and it would
// do so after the read that made the artifacts look correct. What survives that check
// must then be a missing directory (which is created) or a real, empty one. Nothing
// is deleted, renamed, backed up, staged, or swapped: a caller that wants to replace
// a previous projection empties or chooses the destination first, because only the
// caller knows whether those bytes are disposable.
//
// # Reading a collection
//
// [ValidateCollection] is the pre-flight, run before the destination is touched: it
// checks the collection root, its manifest, its canonical event log, the two config
// snapshots the manifest names, and its packet evidence, and returns the validated
// manifest or an error naming the collection and the exact input path. It opens
// nothing for writing: a collection is finished evidence, so reading one confers no
// right to add to it. A projector is usually
// pointed at a corpus, so "something was missing" is not an answer an analyst can act
// on; which collection, and which file in it, is.
//
// The persisted collection format is consumed through
// internal/collection/persistence, which owns it, rather than copied. This package
// therefore has no decoder of its own for events or manifests, and no way to drift
// from the writer. The dependency is one-way and enforced: collection persistence
// knows nothing about projections.
//
// Corpus signals and parity use the same boundary. This package discovers their
// collection inputs, opens tool and domain streams, and reconciles parity splits;
// toolsignals and parityreport receive values and perform no filesystem I/O.
//
// [SourceHealth] maps a validated collection manifest into the projection-owned
// collection verdict once per build. [Build] hands the same value to every artifact
// and to the projection manifest, so the report, the attack surface, and the manifest
// state one outcome rather than three derivations of it. Nothing derives a collection
// status from the tool log, the phase list, or the packet evidence: the collection
// manifest is the sole persisted authority for it.
//
// # Writing artifacts
//
// Every bucket name and every file name lives in artifacts.go, in this one package.
// An adapter that also knew a file name would be a second authority on where an
// artifact lands, and the first rename would leave a reader looking for a file nobody
// writes. There is no exported path helper either, because a caller that rebuilt a
// path would become that second authority by another route.
//
// Each writer creates the bucket it writes into and no other, so an empty bucket in a
// finished projection means the writer that owns it ran and produced nothing, rather
// than that the shape was laid out in advance.
//
// The artifacts of one build are the entity snapshots, the operator report and its
// issue, temporal-anomaly, and threat-scenario ledgers, the decoded network-audit
// view, the data-quality report, the tool-health signals, both graph renderings, the
// generated README, and the projection manifest. [WriteDiff], [WriteParity], and
// [WriteCorpusSignals] write the artifacts that belong to more than one collection,
// and they take their destination explicitly for the same reason: no single build
// produces them, so no single collection can be asked where they go.
//
// # Completion is a file, not a status
//
// The projection manifest is the last write of a build. Its presence is the claim
// that everything before it succeeded, so a build that fails or is cancelled leaves a
// destination without one - which is exactly how a partial projection is recognized.
// There is no staging directory and no swap: the destination was empty when the build
// started, so an unfinished one is discarded by emptying it and building again.
//
// # Offline and deterministic
//
// A build contacts no target, no provider, and no VM. It folds bytes the collection
// already holds, so the same collection reproduces the same artifacts, with the sole
// exception of the manifest's own timestamp. That is what makes a projection
// disposable and a collection precious.
//
// A collection-ingestion problem yields a failed or inconclusive network-audit
// section rather than an abandoned report; only an inability to write a file, or a
// collection that fails validation, stops a build.
package persistence
