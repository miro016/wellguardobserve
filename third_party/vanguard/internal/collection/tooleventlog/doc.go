// Package tooleventlog provides the EventSink interface and Sink implementation
// for tool actors. Tools emit typed events that are logged to a file via slog
// and optionally forwarded to a live consumer.
//
// Each tool defines its own event structs in an events.go file that implement
// the Event interface. The Sink handles both file logging and live notification.
// Events that prove attempted collection work was lost may additionally implement
// [HealthEvent]. The optional interface exposes a stable, bounded [HealthProblem]
// without requiring a consumer to parse event names, levels, attributes, or log
// text. Most events intentionally do not implement it: target behavior, clean
// empty results, configured limits, policy decisions, and recovered retries are
// not collector failures.
//
// # Structured tool events
//
// Beyond the human-friendly per-tool text log, tool events are persisted as a
// structured, correlated, replayable stream that sits alongside the domain-event
// stream. PersistSink decorates the text Sink: for every event it writes a
// versioned ToolEventEnvelope (see envelope.go) to one shared canonical log
// (the collection's tools/tooling.jsonl, all tools interleaved in arrival order) and then forwards the
// raw event to the wrapped sink, so the per-tool log and any live consumer keep
// working unchanged.
//
// The envelope carries the correlation needed to reconstruct what a provider did
// and on whose behalf, offline from the persisted stream alone: a monotonic
// per-scan sequence, the ScanID, the tool, the level, the recon phase, the
// target (domain/host/IP/URL), and a per-invocation correlation id (CorrID). Tool
// code stays pure: none of these are known to the tool, they ride the context into
// PersistSink.Emit. The orchestrator stamps them with WithScan, WithTarget, and
// WithCorrID (see context.go) around each tool invocation; the target falls back
// to the well-known attribute keys when the context does not carry it.
//
// # Where the stream lives is not this package's business
//
// This package owns the envelope format, the correlation, the sinks, and the folds
// over a stream. It owns no path and opens no file. Which directory a collection
// keeps its tool logs in, and what they are called, belongs to
// internal/collection/persistence, which hands the sinks a writer and hands
// ReplayTooling a reader.
//
// That is why the folds take an io.Reader: a stream is a stream whether it came from
// a collection on disk, a test buffer, or a downloaded copy, and a package that
// cannot name a path cannot drift away from the writer.
//
// # The audit join (CorrID)
//
// CorrID ties every tool event of one tool call together and, crucially, to the
// domain events the orchestrator derives from that call's result: the orchestrator
// stamps the same id onto events.EventMeta.ToolCorrID. So a finding in
// the collection's canonical domain-event log can be joined back to the exact
// provider response in its canonical tool-event log that produced it. The id is set after the domain event's
// EventID is computed, so it never affects event identity.
//
// # Tooling read model
//
// ReplayTooling folds a persisted tool-event stream into ToolingStats (replay.go), the operational
// half of the data-quality report: per tool, counts by level, error
// categories, rate-limit hits, empty-result count, and call latency (the span from
// first to last event sharing a CorrID). It is reconstructed from the persisted
// stream alone, like the domain read models.
//
// An empty result and a failed call are deliberately distinct. A completion event
// whose result count is zero (censys "hits", wappalyzer "matches", ...) is an honest
// empty: the call worked and the target has nothing. A completion flagged degraded
// is not - the call reached nothing, so it counts as a failure rather than making
// the target look uninteresting. Tools therefore report a count on every completion,
// including the ones that matched nothing, so a replay can tell the two apart
// without guessing.
//
// That last sentence is a requirement on tools, not a description, and the count must
// be a key the classifier knows (replay.go, connectivityCountKeys and
// resultCountKeys). A completion carrying no recognised count is treated as
// productive - the right default for a whois or asn lookup that simply succeeded - so
// a tool whose count key is missing from those lists scores as perfectly reliable no
// matter how often it fails, and fails silently in the flattering direction. When
// adding an active probe, put its "how many of my fetches succeeded" count on the
// connectivity list.
//
// Two attributes outrank every result count, because they answer the question the
// counts are a proxy for. A completion carrying "accounted" says how much of the
// requested work it actually settled, and is judged on that: the port scanner's
// UDP pass returns a verdict for every port it probed - open, silent, refused, or
// filtered - and only the first is a service, so its open count is zero on most
// healthy hosts. Reading that as "the probe reached nothing", which is the right
// reading for a TCP connect sweep, would make every quiet host a failed call. A
// completion carrying "partial" true says it returned real evidence and then
// failed before finishing, and is a failed call however much it managed to return:
// without that, the evidence would outrank the loss, and a pass that covered half
// its ports would be indistinguishable from one that covered them all.
//
// This live, bounded accounting is not the same job as the offline tool-signal
// analysis over the same log. Replay answers "did this call work", cheaply and
// while the run is happening; the richer cross-event diagnostics belong to the
// projection stage and are never folded back into the manifest after the fact.
//
// # Writing is not best-effort at the execution boundary
//
// A tool actor cannot react usefully to a full disk, so neither PersistSink nor the
// text Sink stops it: both keep the actor running so whatever evidence can still be
// written is written. Both remember their first failure instead - envelope encode
// and canonical write in PersistSink, the text handler's write in Sink - and report
// it from PersistSink.Err, which joins the wrapped sink's. The execution's sink
// setup collects those at its close barrier, where a reported failure prevents a
// succeeded capture. Silence there is the claim being made: every tool event the
// scan observed reached both persisted forms.
package tooleventlog
