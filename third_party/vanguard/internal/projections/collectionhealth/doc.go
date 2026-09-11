// Package collectionhealth holds the projection-owned copy of one collection's
// outcome: what the collection was asked to do, how it ended, and exactly what
// collection work it lost.
//
// # Why the value is copied rather than re-derived
//
// the collection manifest is the sole persisted authority for a collection outcome.
// A projection must state that verdict rather than reconstruct a weaker one from
// tool-event names, log prose, or a phase list, because two derivations of one truth
// eventually disagree and the reader has no way to tell which is wrong. So the
// mapping happens once, in the package that already validated the manifest, and
// every artifact family renders the same [Summary] value.
//
// The package is a leaf on purpose. It imports no persistence package and knows
// nothing about filesystem paths, tool events, or capture layout, so the pure
// projection packages that render it stay deterministic functions of explicit
// inputs and no import cycle is possible between the manifest owner and the
// renderers.
//
// # What it deliberately does not carry
//
// A summary carries source identity, collection status, the phase set that was
// attempted, the health total, and the exact problem rows. It carries no targets, no raw error
// strings, no response bodies, no credentials, and no tool-event attributes: the
// per-event evidence is the capture's tool stream, and duplicating it here would
// create a second account of the same events that could drift from the first.
//
// # Its relationship to the rest of the output
//
// Collection health, target issues, tool-health diagnostics, and packet-capture
// health are separate concepts. A collection loss says the scan may not have seen
// something; it never changes a target's severity, risk score, or finding count, and
// it never becomes a fact in the asset graph. Facts are assertions derived from
// domain events; source completeness is metadata about the acquisition that
// produced them.
//
// [Summary] values are built through [New], which validates every invariant the
// manifest already enforces and clones every slice, so a renderer cannot be handed
// a summary that contradicts itself and cannot mutate the one it was given.
package collectionhealth
