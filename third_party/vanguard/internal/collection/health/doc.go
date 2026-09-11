// Package health folds the health-bearing tool events of one live collection run
// into a single bounded assessment.
//
// # What it is for
//
// A tool that could not complete work it attempted emits an event implementing
// [github.com/velgard-sk/vanguard/internal/collection/tooleventlog.HealthEvent].
// Those events already reach the per-tool text log and the canonical structured
// tool stream, but nothing turned them into an answer to the only question an
// operator asks while a run is still going: did this collection actually lose
// anything? [Monitor] is that answer. It observes events as they are emitted,
// notifies the caller the first time each distinct problem identity appears, and
// carries a running count that the collector reads once the orchestrator returns.
//
// # What it deliberately is not
//
// The monitor is a fold, not a model. It does not replay a capture, reconstruct
// scheduled work, know which tools were enabled, or decide what a run should have
// produced. It counts what producers reported and nothing else, so a tool that
// stays silent about a loss is a producer bug fixed in that tool's events, not a
// gap this package tries to infer.
//
// It is also not a log. Nothing observed is retained beyond the problem identity
// and its count: no raw event, no event attributes, no error body, no target, no
// timestamp. The per-event detail lives in the tool streams that were written
// before the monitor ever saw the event.
//
// # Bounds
//
// Producer output is untrusted input here. Every stored field is truncated, the
// number of distinct identities is capped ([MaxIdentities]), and the two reserved
// codes absorb what does not fit: [CodeInvalidEvent] for an event that reported a
// problem without a code or a tool, and [CodeOverflow] for identities beyond the
// cap. Monitor memory is therefore constant no matter how badly a tool misbehaves.
//
// # Ordering
//
// Tool events arrive from concurrent workers, so live notification order is
// arrival order and is not reproducible. [Monitor.Assessment] sorts its rows by
// code, tool, and component, so everything persisted or returned to a caller is
// deterministic regardless of how the run interleaved.
//
// The package depends on the tool-event contract and the standard library only. It
// reads no file, opens no connection, and knows nothing of configuration,
// orchestration, persistence, or projections.
package health
