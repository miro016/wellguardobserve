// Package persistence is the collection phase's filesystem. Every Go read and
// write that creates, reads, or describes a collection happens here, and nothing
// here knows what a projection is.
//
// # The collection directory
//
// A collection directory is the exact directory its caller named. This package
// inserts no enclosing component: there is no capture parent, no collected/ bucket,
// and no projected/ sibling. Everything a collection consists of is joined directly
// below the supplied root - manifest.json, README.md, configs/, events/, tools/,
// and the wrapper-written netaudit/ - so a collection directory is complete,
// movable, and meaningful on its own. A host that wants collections grouped under a
// corpus root gets that by choosing the paths it passes, which is a storage policy
// rather than something this package can decide for it.
//
// The joins live in paths.go and are private wherever they can be. A caller that
// wants the manifest calls [LoadManifest], a caller that wants the event stream
// calls [LoadEvents] or opens a [Sink], and a caller that wants the tool log calls
// [ReadToolLog]. The few exported path helpers - [EventsLogPath], [ManifestPath],
// [SnapshotsDir], [ToolLogPath] and their neighbours - exist so a reader can name
// the exact file it could not use, not so it can open one behind this package's
// back.
//
// # One directory, one collection
//
// [PrepareFresh] accepts only a missing or empty destination. It creates a missing
// one and rejects everything else - a file, a symlink standing in for the root, a
// directory with contents - without deleting, renaming, backing up, or merging
// anything. A destination it refuses is left byte for byte as it was found, so a
// caller that pointed the collector at the wrong directory loses nothing. There is
// no second way in: nothing here reopens a collection to add to it, so collecting
// again means naming another destination.
//
// [OpenCollection] is the read side, and it is held to a stricter standard than
// "there is something here": it requires the manifest, the canonical event log, and
// the two configuration snapshots the manifest records. A directory with contents
// but no manifest is an error rather than an empty collection, because a reader
// needs to be told the difference between "nothing was collected" and "this is not a
// collection". It writes nothing and confers no right to write.
//
// Neither check is a lock. Two processes can both pass and then interleave their
// writes; exclusive ownership of a collection directory stays the caller's
// responsibility. The deployed network-audit wrapper meets that responsibility by
// holding an atomic sibling claim from before collector startup through packet-capture
// publication, while a direct caller must provide its own serialization.
//
// # What this package writes
//
//   - [Sink] appends every domain event to the canonical, ordered, versioned
//     events/events.jsonl and mirrors it into the per-type splits. It folds nothing
//     and renders nothing.
//   - [Manifest] is manifest.json, the single authority for a collection's identity,
//     phases, outcome, and provenance. [NewManifest] describes the run before any
//     tool starts and [Manifest.Complete] closes it with a terminal status and its
//     optional health summary, so a collection that died is visible as an attempt
//     rather than absent.
//   - [SaveSnapshots] writes the verbatim operator input the run used into configs/,
//     and returns the collection-relative paths the manifest records.
//   - [OpenToolLogs] and [OpenToolTextLog] open the canonical tool-event stream and
//     the per-tool text logs. The envelope encoding, correlation, and folds over
//     those bytes belong to internal/collection/tooleventlog, which owns the format
//     and no longer owns any path.
//   - The generated README.md, written from the embedded copy this build carries, so
//     the layout documentation in a collection is always the one written by the
//     build that actually collected into it.
//
// Each writer creates the directory it writes into and no other, so an empty bucket
// in a finished collection means the writer that owns it ran and produced nothing,
// rather than that the shape was laid out in advance.
//
// # Durability is not best-effort at the closing boundary
//
// [Sink] keeps writing after a failure - a broken per-type split must not cost the
// canonical log its copy of the same event - but it remembers the first per-type
// open, per-type encode, canonical encode, and canonical write failure and reports
// them all from [Sink.Close]. A collection whose streams reported any of those did
// not record everything it observed and must not be called succeeded; the collector
// treats [Sink.Close] as its durability barrier for exactly that reason.
//
// Manifest transitions replace the JSON atomically and briefly retry transient
// Windows sharing violations, so a reader cannot observe a partial rewrite and a
// short-lived antivirus or indexing handle does not abort a collection.
//
// # The wire contract
//
// The versioned envelope ({version, type, data}) produced by [EncodeEvent] and
// decoded by [DecodeEvent] stays here because it is the contract the collector
// writes. Decoding dispatches on the type tag through the event registry
// (internal/collection/events), so new event types need no change to the codec.
// Anything that reads a collection later - including a projection - consumes this
// read-only contract through [LoadEvents] rather than copying a decoder.
//
// # What this package deliberately does not do
//
// It folds nothing. [LoadEvents] returns raw events in arrival order because the
// meaning of a fold belongs to the phase doing it: a projection folds them into
// artifacts, a health check folds them into an assessment. Keeping the fold out is
// what lets this package promise it imports no projection component - a promise the
// package's own architecture test enforces rather than only asserts here.
//
// It also does not write the packet captures under netaudit/. Those are finished by
// an external wrapper after the collector process exits, because only something
// outside the process can stop a capture of that process. The wrapper receives the
// exact collection destination and writes netaudit/ below it; this package names the
// bucket, documents it, and reads nothing from it.
package persistence
