// Package buildid is the shared vocabulary for "which build produced this
// output": the name of the actor that ran a stage, and one opaque version
// identifier its caller chose for that build.
//
// It exists so one value answers that question everywhere it is asked. A
// collection run records its identity twice, in two different places, for two
// different readers:
//
//   - the collection manifest records it as a filesystem-level provenance field,
//     readable with cat and without decoding an event stream;
//   - the ScanEnvironmentRecorded domain event records it inside the event stream,
//     beside the runtime and embedded-data identities that only matter when a
//     result is being reproduced.
//
// A projection run records the projector's identity the same way in
// the projection manifest. All of them are the one [Identity] value the stage was
// given when it was created, so the manifest and the event stream of one execution
// cannot disagree.
//
// # The version is the caller's, not Vanguard's
//
// This package constructs nothing. It does not read Go build information, look for
// a linker-populated variable, search for Vanguard among a host's dependencies, or
// prescribe a format. It takes the finished string and stores it.
//
// That boundary exists because only the caller knows what the answer should be.
// For a Vanguard command the answer is the Vanguard build, and
// internal/apps/buildversion is the policy the first-party CLI applies. For an
// application that embeds the collection or projection package, the running
// executable is that application, and its release describes the host rather than
// the collection code that produced the capture. Such a host may legitimately want
// to record its own release, a Vanguard release, a composite such as
// "host=v9.8.7;vanguard=v0.5.0", a commit, or something else entirely. Vanguard
// cannot pick correctly on its behalf, so it does not try.
//
// [Identity.Version] is therefore opaque. It is recorded verbatim, compared as a
// whole, and never split, trimmed, or normalized. A whitespace-only value counts
// as absent for the emptiness check, and a value that passes that check is stored
// exactly as it was supplied.
//
// # Why an unidentified build is fatal to a collection
//
// A capture is evidence. A capture whose collector cannot be named is evidence
// that cannot be reproduced, re-judged, or blamed for a defect, and it is
// indistinguishable on disk from one that can. [Current] therefore returns
// [ErrUnidentified], rather than a placeholder, when no version was supplied.
// Collection resolves its identity before it opens a sink or starts a tool, so an
// unidentified build fails before it writes anything or touches a target.
//
// Projection is the exception and takes [Unvalidated] instead. It writes no
// evidence: every projection artifact is a fold of a collection, rebuildable
// at any time from a capture that already names its collector. Refusing to rebuild
// a report because the projector was launched with "go run", which stamps nothing
// at all, would cost an operator the report and protect nothing.
//
// The package is a leaf: it imports only the standard library, so both the event
// vocabulary and the persistence layer can depend on it without a cycle.
package buildid
