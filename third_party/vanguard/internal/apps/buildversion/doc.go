// Package buildversion constructs the version identifier that Vanguard's own
// command binaries hand to the collection and projection stages.
//
// It is application policy, not a domain concept. Vanguard's business logic asks
// only "which build produced this output" and records whatever single string the
// caller supplies. How that string is assembled is the caller's decision, and this
// package is the decision the first-party CLI makes, shared by
// vanguard-collect and vanguard-projections so the two commands identify
// themselves the same way.
//
// # The identifier
//
// [Resolve] returns one string. It never returns a structure, never validates
// against collection or projection rules, and never inspects anything but the
// running main executable. The empty string is a legitimate result: it means this
// build can be identified by nothing at all, and it is then the stage's own policy
// that decides what to do about it - collection refuses to start, projection
// records the build as unidentified and rebuilds the report anyway.
//
// # Fallback order
//
// The release string the command owns wins whenever the build supplied one. A
// release build stamps it at link time:
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/vanguard-collect
//
// The variable belongs to the command's main package, which is what makes it a
// per-binary value rather than a global shared by every program that ever links
// Vanguard.
//
// With no release value, the Go build information the toolchain stamped into the
// executable is consulted, in this order:
//
//  1. the main module's version, when it names anything. For a build from a
//     repository this is often a version the toolchain synthesized from the
//     nearest tag and the revision, which already identifies the source and is
//     therefore a perfectly good answer. Older toolchains, and repositories with
//     no tags, report "(devel)" instead; that names nothing and is skipped;
//  2. the VCS revision, with "+dirty" appended when the working tree carried
//     uncommitted changes at build time. The marker matters because a revision
//     alone would claim the source is reproducible when it is not;
//  3. nothing, which is the empty string.
//
// # Why an embedding application does not use this
//
// This package looks at the main executable, and for an application that imports
// Vanguard the main executable is that application. Its release and its revision
// describe the host, not the collection code that produced a capture, so guessing
// on its behalf would produce a confidently wrong answer.
//
// An embedding host therefore owns its own policy and passes the finished string
// through the public stage options. It may pass its own release, a Vanguard
// release, a composite such as "host=v9.8.7;vanguard=v0.5.0", a commit, or any
// other stable identifier its release process understands. Vanguard stores that
// value verbatim and never parses it.
//
// The package is a standard-library-only leaf. It links no Vanguard code, so
// nothing below the application layer can come to depend on how the CLI happens to
// name itself.
package buildversion
