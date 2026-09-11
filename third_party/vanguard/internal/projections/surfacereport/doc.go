// Package surfacereport is the attack-surface contraction and its page: [Contract]
// contracts an already folded facts graph with
// github.com/velgard-sk/vanguard/internal/projections/attacksurface, and [RenderHTML]
// returns the self-contained page with the contracted graph embedded in it.
//
// It opens no file and knows no path. Writing the three renderings belongs to
// internal/projections/persistence, which is also what keeps this package from
// disagreeing with the writer about where its artifacts land.
//
// It deliberately loads no event stream of its own either. A build folds a
// collection once and hands the same graph to the facts renderer and to this
// contraction; a loader here would make it possible for the two artifacts to come
// out of two different folds of one collection.
//
// # Why the artifacts live beside the facts graph
//
// The three files go into the graphs bucket, never the reports one. The surface is
// the contracted analyst view of the facts graph rather than another operator report,
// so it belongs beside the complete graph it was contracted from, not picked out of a
// folder of a dozen unrelated files. Nothing in either bucket is evidence: the
// collection's canonical event log remains the source of truth, and deleting a whole
// projection costs nothing but a regeneration.
//
// # One fold, two artifacts
//
// The facts graph and the attack surface are folded from the same event log, so the
// caller passes the graph it already has to Contract rather than letting
// each report decode the log again. Neither writer ever reads the other's output:
// the surface is contracted from the facts graph in memory, not from the written facts.json,
// so a stale or missing facts file cannot change what the surface says.
//
// # A refused write
//
// Write validates the contracted graph before it writes anything. A dangling edge, a
// duplicate identity, a lost finding, or an asset type with no contraction rule would
// make the HTML view disagree with its own JSON and would hide data the scan collected,
// so the whole write fails with the offending subjects named rather than leaving a
// quietly wrong artifact behind. The event log is untouched, so a fixed contraction
// regenerates from it.
//
// # The collection verdict is passed in, never read
//
// [Contract] takes the build's already mapped collection-health summary and compacts
// it into the attack-surface graph's own source block. It is passed in for the same
// reason the facts graph is: this package folds nothing, and this artifact must state
// the same verdict as the operator report rather than a second reading of the
// collection manifest. Nil means the caller had no manifest, and the artifacts then
// state nothing about source completeness.
package surfacereport
