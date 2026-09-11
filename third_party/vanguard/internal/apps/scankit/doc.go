// Package scankit implements the collection-bootstrap subsystem a collection runs
// on. It is the composition root of one collection, kept separate from
// whoever starts one so the decisions it makes - which sinks, which terminal tooling
// - can be tested without a front-end.
//
// Its caller is the public collection stage (pkg/collect), which the
// vanguard-collect command is in turn a command-line wrapper over. Presentation
// belongs to that caller: this package writes to no process stream.
//
// # Collection only
//
// This package wires configuration, orchestration, event persistence, tool logs,
// and terminal collection tooling. It renders nothing. No projection report adapter
// appears in its imports, and none may be added: a collection that could write a
// derived artifact would put projection output on a scan VM, where there is no
// projector to reproduce it and no reason for it to exist.
//
// The one in-memory read model it does touch is a collection decision, not an
// artifact: [RecordExecutionEnvironment] reads the embedded KEV catalogue for the
// environment event. It does not reach disk.
//
// # One collection, one invocation
//
// A collection directory holds exactly one collection, described directly by the
// collection manifest (persistence.Manifest, stored as the collection's
// manifest.json): its identity, the phases the profile enables, its start, its
// outcome. The scan root comes from the engagement file, the scan ID is minted for
// the run, and the destination was empty when the run claimed it.
//
// Nothing here reopens a directory, reads a prior collection, or plans work from
// one. A collection that failed, was interrupted, or lost work is repeated by
// collecting again into a new destination, which leaves the earlier material exactly
// as its run left it. Regenerating read models and reports is exclusively the host
// projector's job.
//
// # External Runtime
//
// [ResolveRuntime] runs the read-only external-dependency checks the goscans tool
// needs (nmap with its forced NSE scripts, and the pinned SSLyze when the TLS module
// is on). Those checks execute commands, which is why they live here with the other
// startup work rather than inside config, which stays a pure decode-and-check. They
// run under the caller's context, so a cancelled collection stops them too, and each
// command still carries its own shorter deadline. They judge the machine and not the
// secrets: credentials are the caller's to supply and to check
// (config.ScanProfile.ValidateAPIKeys), which is what lets a read-only deployment
// check prove a machine is ready without being handed one.
// A disabled goscans tool resolves nothing, so a passive scan needs none of it
// installed. A portscan-only profile still resolves nmap and its version, without
// applying GoScans-specific script checks.
//
// A profile that enables tools.portscan.udp adds one more check, and it is the
// single documented exception to the rule that preflight sends no packet: it asks
// the resolved nmap to scan one UDP port on 127.0.0.1. nmap reports insufficient
// privilege by refusing the scan type at runtime, not through any flag, version, or
// file attribute, so the question cannot be answered without asking it. The
// exception is bounded on every axis - the loopback address only, one port, one
// host, its own nmap host timeout, its own command deadline, and no output file -
// and it runs as the collection user without sudo, because a check that passed as a
// privileged account would prove nothing about what a scan can execute.
//
// The probe also settles the one argv decision that cannot come from a document.
// nmap decides it is unprivileged from its effective UID, so a binary holding
// cap_net_raw as a file capability can refuse a scan it is able to run; the plain
// invocation is tried first and the --privileged form only after a refusal, and
// which one worked is recorded in [UDPRuntime] for the scan to build from. An
// enabled UDP pass that cannot be performed fails here, hard: there is no downgrade
// and no silent skip, because a capture that quietly dropped the transport it was
// configured for would read as a clean UDP result.
//
// What the checks resolved comes back as an [ExternalRuntime] and is not decoration:
// it is the absolute paths and versions actually found on this machine, which differ
// from what the file named more often than is comfortable. [RecordExternalRuntime]
// puts it into the actor configuration. [RecordExecutionEnvironment] additionally
// hashes the selected config and collects module, runtime, and embedded-data
// identities for the canonical ScanEnvironmentRecorded domain event. The collector
// identity - the actor name and the one opaque version its caller chose - is passed
// in rather than resolved there: the same value is written into the collection
// manifest, and taking one already-resolved identity is what makes the two
// provenance records of a run identical by construction. It hashes the exact
// configuration bytes the run was given rather than re-reading a path, so the digest
// describes what ran and matches the snapshots [SaveConfigSnapshots] writes.
//
// # Sink and Tool Wiring
//
// [OpenCollectionSink] creates the collection's event sink, the one construction
// path there is: the destination was empty when the run claimed it, so the stream
// starts at the beginning.
//
// [WireToolSinks] opens per-tool log files in the tools/ subdirectory and connects them
// to the orchestration configuration, alongside a shared tooling.jsonl envelope log.
// It accepts an optional notification callback so interactive front-ends can mirror live
// tool events in their UI. A log is opened only for an enabled tool, so the presence of
// the collection's tools/tool_<tool>.log is itself the record of what the run was configured to do.
// crt.sh and Censys are mode-driven rather than flag-driven, and every non-disabled
// mode opens the normal log: an embedded-cache run records its cache hits and misses
// in the same tool stream as a service run, so the log still answers what the run was
// configured to do and where its data came from.
// Its closer reports every file-close error; collection cannot be marked succeeded
// until both the tool logs and the domain-event sink close cleanly.
//
// # Running
//
// [RunOrchestrator] invokes the scan engine over the engagement's scan root.
//
// # Recording the collection
//
// The manifest is written twice, and that is deliberate. [StartCollection] writes it
// as running - with the run identity, the phase set, the UTC start, the
// [SaveConfigSnapshots] paths, and the collector identity - before any tool runs, so
// a collector that dies leaves an explainable collection rather than one that claims
// the attempt never happened. [CompleteCollection] rewrites it with its terminal
// status and its health summary, so a failed, interrupted, or degraded collection
// states plainly that it did not finish what it attempted.
package scankit
