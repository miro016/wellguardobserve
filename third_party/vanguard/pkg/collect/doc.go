// Package collect is the public API for Vanguard's collection stage: it contacts
// targets and providers under one engagement and writes an immutable collection
// directory. It is the embeddable form of what the vanguard-collect command does,
// for a Go application that wants to run a collection itself.
//
// # Using it
//
// One collection is one [Collector]:
//
//	collector, err := collect.New(collect.Options{
//		EngagementYAML:  engagement, // the exact authorized engagement document
//		ProfileYAML:     profile,    // the exact scan profile document
//		Credentials:     collect.Credentials{Shodan: shodanKey},
//		DestinationDir:  destination, // the exact directory this collection is
//		ApplicationName: "example-scanner",
//		Progress:        os.Stdout, // nil for a silent run
//	})
//	if err != nil {
//		return err
//	}
//	return collector.Run(ctx)
//
// A run contacts the targets and providers the engagement authorizes. Vanguard
// enforces the scope that engagement declares; establishing that the engagement is
// authorized in the first place is the calling application's responsibility.
//
// # The stage boundary is the collection directory
//
// [Options.DestinationDir] is the collection, not a parent of one. Vanguard inserts
// no directory component of its own, so the source streams, the metadata that makes
// the directory readable and attributable, and the exact configuration the run used
// all land directly below the path the caller named. A host that wants collections
// grouped under a corpus root gets that by choosing the paths it passes.
//
// Nothing derived is written here, and no Go value is handed to the projection
// stage. That directory on disk is the entire contract between the two stages, which
// is what lets a collection run on a scan VM and a projection run on an analyst host,
// days later, with no shared process and no shared types. A projection is written to
// a destination of its own; it is never placed inside a collection unless a caller
// names such a path.
//
// # The destination is never taken by force
//
// A run accepts only a missing or empty destination, and creates a missing one.
// Nothing already there is deleted, renamed, backed up, or merged, and a refused
// destination is left exactly as it was found - so an application that pointed
// Vanguard at the wrong directory loses nothing. Preparing disposable output is the
// caller's job, because only the caller knows which bytes are disposable.
//
// There is no option that accepts a non-empty destination. A collection directory
// records one collection, so collecting again means naming another directory: an
// earlier collection, however it ended, stays exactly as its run left it.
//
// The destination check is not a lock. One collection directory belongs to one run
// at a time, and keeping it that way stays the caller's responsibility.
//
// The companion package for the other stage is
// github.com/velgard-sk/vanguard/pkg/projections. Neither package imports the
// other, on purpose: an application may embed either stage alone.
//
// # What is in this API, and what is not
//
// Public here: running one collection ([Collector]), and the collection-runtime
// preflight a deployment uses to prove a machine can collect ([Preflight]).
//
// Deliberately not public: individual tools, domain events, entities, findings,
// collection layout helpers, and the batch runner. Collection comparison (diff), corpus
// parity, and corpus tool-health signals also remain command-only features of
// vanguard-projections in this cut; their report models are large and no embedding
// consumer needs them yet. The whole-stage operation is the unit this API exposes,
// so the internals stay free to change.
//
// # Inputs are values, not process state
//
// Configuration is accepted as the exact YAML bytes of an engagement and a scan
// profile, so an application can load them from a file, a database, an embedded
// resource, or an API without writing temporary files. Those exact bytes are what
// gets validated, hashed into the run's provenance, and snapshotted into the
// collection.
//
// Credentials are explicit data ([Credentials]). This package never reads the
// process environment on its own; [CredentialsFromEnv] exists for callers who want
// the command's environment convention and is opt-in.
//
// Progress is an optional [io.Writer]. A nil writer makes a run silent, which is
// the default an embedded library should have. Progress text is for humans and its
// wording is not stable; the collection's event streams are the machine-readable
// result.
//
// The library installs no signal handlers and never calls os.Exit. Cancellation is
// the caller's, through the context passed to Run: it stops the runtime checks, the
// tools, and the orchestrator, and the collection keeps everything it had already
// durably written. A write that fails on the caller's progress writer is reported
// rather than swallowed, so a stream that went quiet is never mistaken for a quiet
// scan.
//
// # Collection health
//
// Tools report the work they attempted and lost as typed health-bearing events. A
// run folds those live: the first occurrence of each distinct problem identity is
// printed as a "[degraded]" progress line while the run is still going, repeats are
// counted, and the closing summary states the totals. The fold is bounded and holds
// no event payload; the per-event detail is in the collection's tool streams, which are
// written before progress ever describes a problem.
//
// That one fold decides three things at once, so they cannot disagree: the
// execution's manifest status and its stored health summary, and the error [Run]
// returns. A run that finished and wrote its collection cleanly but lost collection
// work returns a [DegradedError] carrying a [HealthSummary]; its execution is
// recorded as degraded and contributes no phases, so re-running the same collection
// against the same directory retries exactly the incomplete work.
//
// Degradation is not failure and is not silently tolerated either. What was
// collected is in the collection and is trustworthy; whether a partial estate is
// acceptable for this engagement is the caller's policy, and Vanguard's job is to
// state accurately what happened.
//
// A problem identity is a code, a tool, and a component, and the component is what
// keeps two failures of one tool apart. The port scanner runs two transports, so a
// lost TCP sweep and a lost UDP pass both report portscan.runtime_failed and are
// told apart by the component "udp-nmap" - which matters because an operator
// repairs them differently: the UDP one is usually an nmap binary that lost its
// raw-socket capability to a package upgrade.
//
// What counts as lost work is narrow on purpose. A pass that ran and found nothing
// lost nothing: a UDP pass that covered every port and confirmed no service is a
// healthy pass, and so is one whose ports were all silent, refused, or filtered.
// Those are facts about the target and are recorded as coverage, in the event
// stream, not as health. A pass that returned real evidence and then failed is
// degraded and keeps its evidence: the services it confirmed are in the collection,
// and the phase stays incomplete so the next run retries it. A profile that never
// enabled a pass has lost nothing either, and a missing runtime is not degradation
// at all - it fails preflight, before any collection starts, so no manifest ever
// claims a degraded scan that never ran.
//
// The outcome precedence is fixed: a cancelled run is interrupted, a run or stream
// error is failed, lost collection work is degraded, and anything else is
// succeeded. Stream errors count: the event and tool sinks keep writing after a
// failure so evidence is preserved, but they remember what failed, and an execution
// whose streams reported an error is never called succeeded.
//
// # Complete and interrupted runs
//
// A collection directory records one run over the engagement's scan root, collecting
// every phase the profile enables.
//
// The execution opens its manifest entry before the first tool starts and closes it
// on every exit path: succeeded once the event and tool streams have closed cleanly,
// failed on an error, interrupted when the context was cancelled. Only a succeeded
// execution records its phases as executed, so a crash or a cancellation leaves a
// collection that says plainly it did not finish what it attempted, rather than one
// claiming the work was done. A collection whose collector died keeps its running
// entry: the material it wrote is readable, and the work is repeated by collecting
// again into a new directory.
//
// # Ownership and mutation rules
//
// [New] copies the YAML byte slices it is given, so a caller may reuse or modify
// its buffers afterwards. A [Collector] runs once: a second Run, or a concurrent
// one, is refused rather than allowed to corrupt a collection. Concurrent collections
// are supported through separate instances writing separate collection directories;
// two collections must never share one directory. An [io.Writer] supplied for
// progress stays the caller's: this package writes to it during a run and never
// closes it.
//
// # Provenance
//
// A collection records who produced it as one identity: Options.ApplicationName and
// Options.Version, both supplied by the caller. [New] fails when either is missing,
// before anything is contacted, because a collection nobody can attribute is evidence
// nobody can reproduce.
//
// The version is the caller's. Vanguard neither constructs nor interprets it: it is
// stored verbatim in the collection manifest and in the environment event, and
// compared as a whole. An embedding application therefore decides what "which build
// produced this" means for its own releases - its own version, a Vanguard version, a
// commit, or a composite naming more than one:
//
//	Version: "v9.8.7"
//	Version: "host=v9.8.7;vanguard=v0.5.0"
//
// Neither is a format Vanguard owns; both are recorded exactly as written. Guessing
// on the caller's behalf would be wrong in the case that matters, because for an
// embedding application the running executable is the host, and the host's release
// says nothing about which collection code produced the collection.
//
// # Stability
//
// This API is experimental and may change between commits. Pin a module version or
// a commit.
package collect
