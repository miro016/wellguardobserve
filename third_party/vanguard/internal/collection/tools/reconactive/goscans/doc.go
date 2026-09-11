// Package goscans integrates the Siemens GoScans scan modules as one isolated,
// active-phase tool.
//
// GoScans is a collection of Go scan libraries, not an executable. This package
// owns the actor that drives them: lifecycle, concurrency, temporary storage,
// bounds, redaction, and events. The parts that are separable live beside it, so
// each can be read and tested on its own:
//
//   - the upstream subpackage is the only importer of GoScans, and the only place
//     upstream constructors are called;
//   - the plan subpackage decides what to probe, as a pure function of one
//     discovery result;
//   - the probes subpackage holds the reviewed, embedded web enumeration corpus;
//   - the preflight subpackage performs the read-only external dependency checks.
//
// The tool owns its own nmap invocation, its own SSLyze interpreter, its own
// temporary storage, and its own events. It deliberately duplicates traffic that
// the port scanner, HTTPS probe, and detection stage already send: two independent
// observations of the same service are worth more than one, and keeping the tools
// separate is what makes the comparison meaningful.
//
// This is active reconnaissance: it sends traffic to the target. It must only be
// run when the active phase is explicitly enabled.
//
// # Request scope
//
// The crawler and enumerator follow HTTP redirects inside upstream code that has no
// pre-dial authorization hook. Upstream checks its own notion of scope only after a
// redirected response arrives, which is too late for an engagement boundary.
// Vanguard therefore does not run those two modules with the live upstream
// implementation. [Config] validation fails closed when either module is enabled
// without an explicitly supplied alternate [upstream.Upstream], and production
// orchestration disables both modules and records the resulting coverage gap.
// Banner, TLS, SSH, and discovery remain available because they do not contain that
// uninspectable redirect loop. Third-party code under vendor is never modified to
// add a private policy seam.
//
// Config.AllowUnscopedWebModules is the one way past that refusal, for a caller
// that has been asked for the crawler's coverage with a mandate wide enough to
// cover wherever a crawl leads. It only lifts the validation refusal; it changes
// nothing about what upstream does, and it does not make the traffic scoped. The
// caller that sets it takes on the duty of applying its boundary to the results
// instead - in Vanguard that is the orchestration switch
// tools.goscans.ignore_http_scope, which records the override, checks every fetched
// endpoint against the engagement scope afterwards, and marks and reports the ones
// the policy would have refused.
//
// Hard engagement exclusions are enforced before the actor is built, not here: the
// orchestrator filters every target IP against scope.ip_ranges.exclude and every
// virtual host against scope.domains.exclude before constructing the target list, so
// no excluded address or name ever reaches a GoScans argument or subprocess. An
// exclusion is a hard deny the out-of-scope HTTP override cannot relax: whenever
// either exclusion list is non-empty, orchestration withholds the webcrawler and
// webenum modules even with the override enabled (they still have no pre-dial
// exclusion boundary) and records that as a coverage gap. The actor receives an
// already-filtered snapshot and needs no exclusion format of its own.
//
// # Runtime provenance
//
// Config.Runtime carries what the startup dependency check resolved on this
// machine, and ScanStarted reports it beside the vendored upstream release the
// binary was built against. Neither is enforced here - the check that fails a wrong
// version already ran before the actor was built - and an empty Runtime simply means
// nobody resolved one, which is normal in a test.
//
// It is reported because a result is only as reproducible as what measured it. A
// weak-cipher finding is a statement by one SSLyze version, and an open port is a
// statement by one nmap; a configured path resolves through PATH to whatever is
// installed on the day, which is not always what the profile author had in mind.
//
// # Pipeline
//
// [New] takes an immutable configuration snapshot and a fixed list of
// scope-approved targets, validates both, and returns an [Actor]. [Actor.Run] then
// starts the targets in address order, up to MaxParallelTargets at once, and for
// each one:
//
//  1. runs GoScans discovery with this tool's own nmap executable and arguments;
//  2. sorts the discovered hosts and their services by transport, port, and tunnel,
//     so the same discovery output always yields the same plan;
//  3. reports the services and NSE script output before any subordinate work
//     starts;
//  4. builds subordinate jobs from that discovery result and nothing else, using
//     the selection tables in the plan subpackage;
//  5. runs the jobs through one bounded worker pool and reports a result or a typed
//     error for each;
//  6. reports a per-target summary with attempted, succeeded, failed, and skipped
//     counts.
//
// Discovery may be scoped. A target can carry the ports another tool already found
// open on that host, and the scan is then aimed at exactly those instead of sweeping
// its own default range, which is what stops the same host being swept twice in one
// scan. An operator's own port argument always wins: appending a second one would
// leave nmap to settle the conflict at runtime, so a configured range disables the
// scoping rather than competing with it.
//
// Scoping trades coverage for time and the trade is only free when the supplying
// tool's range is at least as wide as the one given up. A target with no port set is
// swept in full, which is the safe reading of silence: a host nothing else reached
// must still be looked at properly, because an empty port set and an unswept host
// are indistinguishable afterwards. Every scan reports which of the two it was, so a
// later reader can tell a scoped result from a full one - a scoped scan can only
// find what it was pointed at, so "nothing else was open" is a claim only the full
// sweep is entitled to make.
//
// Targets overlap because they are independent: a target is one address, and nothing
// one target learns feeds another. Without overlap the run is paced by its slowest
// hosts while the rest of the budget sits idle, which is the difference between a
// stage that dominates a scan and one that does not.
//
// Three bounds hold at once, and none of them multiply. MaxConcurrency is the
// tool-wide ceiling on subordinate jobs in flight and is the run's traffic bound
// however the targets arrange themselves; MaxConcurrencyPerHost bounds jobs against
// one address, so a generous tool-wide budget never becomes pressure on a single
// host; MaxParallelTargets bounds how many targets are assessed at once. The run
// summary reports the tool-wide ceiling next to the highest number of jobs actually
// in flight, so the bound a configuration promised can be checked against the bound
// the run observed.
//
// # Ordering
//
// The plan is deterministic and the event order within one target is too: the same
// discovery output always yields the same jobs in the same order. Across targets it
// is not, and nothing downstream may depend on it. TargetStarted is the exception,
// and deliberately so: it is emitted from the dispatch loop rather than from the
// target's own goroutine, so the order targets are started in is still the address
// order the snapshot fixed. TargetCompleted carries no such guarantee, because
// completion order is whatever the hosts decide.
//
// The whole run is bounded by the caller's context. Orchestration is what applies
// the tool's configured timeout to it, because expiring that timeout is a coverage
// decision - the approved hosts it never reached went unassessed - and recording
// that belongs with the other stage-level coverage reporting rather than here. On
// cancellation the actor stops starting work and waits out what is already in
// flight, because an abandoned target would leave a live nmap or SSLyze child
// process behind and race the removal of the temporary tree.
//
// Module selection keys on the service transport as well as the port. That gate is
// load bearing rather than defensive: upstream banner accepts "udp" and dials it,
// while the TLS, SSH, and web modules dial "tcp" unconditionally, so a table keyed
// on port alone would probe a UDP service with TCP-shaped traffic or record silence
// as a result. Discovery is TCP only today, and the configuration refuses an nmap
// UDP technique, because upstream discovery keeps only ports in state "open" while
// nmap reports an unanswered UDP port as "open|filtered".
//
// # What the events carry
//
// The events are the only output, so anything upstream reports that is worth having
// has to be on one. Discovery contributes a host profile (the names and addresses
// the host answers for, the ordered OS candidates, the MAC address when the scanner
// shares the host's segment, the uptime estimate, the up-reason, and the traceroute
// path), one service event per service carrying the full nmap fingerprint, and the
// NSE script output as bounded evidence. The TLS module contributes the whole SSLyze
// assessment: the accepted suites with their algorithms and strengths, the presented
// certificate chains with each certificate's role and validity, the protocol
// settings, the elliptic curves, and the issue flags.
//
// The three Known flags on the TLS event are load bearing rather than decorative.
// Upstream returns settings, issues, and curves as pointers that are nil when SSLyze
// produced no such section, and a nil section means "not tested". Without the flags
// an empty issue list would be indistinguishable from a clean server, which is
// exactly the mistake a TLS report must not make.
//
// The TLS module also reconciles the server names it got results for against the
// ones it asked about. Upstream runs a full handshake per name, then discards any
// result matching one it already collected and any result with no ciphers or no
// chains, without distinguishing the two and without saying which name it dropped -
// and it walks its scanners out of a map, so the name it keeps changes between runs
// of the same scan. Each result therefore carries the names it is known to cover:
// its own name when every name came back separately, and none at all on any short
// count. The short count is never resolved by guessing, because the two reasons
// upstream drops a result mean opposite things - a duplicate says the missing names
// measured like the survivor, an empty result says they were not measured - and it
// reports neither. Upstream compares the trust-store list as part of equality, so a
// certificate covering the virtual hosts but not the address cannot deduplicate its
// address result against a name result at all; on such a service every short count
// is loss, and the survivor is the address measurement. A short count also emits
// TLSNamesUnreported, so a socket assessed under two names and reported under one
// does not read as complete.
//
// One name upstream reports is generated rather than observed, and is dropped here.
// A wildcard certificate name is expanded into the base name the certificate really
// covers, which is kept, and a "wildcard." sample of that base, which exists only to
// drive upstream's own wildcard detection and names no host. Vanguard has no such
// consumer, and forwarding the sample would put a host that does not exist into the
// inventory as live evidence, because discovery is an active probe. The sample is
// identified by the pair upstream always emits together, a "wildcard." prefix whose
// remainder is another of the host's names, so a real host carrying that label on its
// own survives.
//
// Two properties of an accepted suite are derived here rather than carried across,
// and both are noted on the fields themselves so a reader comparing an event against
// raw scanner output is not surprised.
//
// A suite's key exchange, and with it whether the suite provides forward secrecy, is
// read from the suite's IANA name instead of from the scanner's classification. The
// scanner resolves the key exchange through a static suite table keyed by suite
// identifier, and such a table can disagree with the name it holds: one shipped
// table types most ECDHE suites as static ECDH, which reports every affected suite
// as lacking forward secrecy when it provides it. A name cannot disagree with
// itself. A TLS 1.3 suite names no key exchange because the version negotiates it
// separately and always ephemerally, so the protocol answers for it, and a name that
// states no key exchange at all leaves the scanner's own answer standing, because an
// unreadable name is not evidence the scanner was wrong.
//
// The suite list is also deduplicated on protocol and name. Upstream keys its suite
// table by OpenSSL name and keeps every entry sharing one, so a single negotiated
// suite can come back several times; counting the copies reports one weakness as
// several, both in the suite total and in the evidence naming the weak suites. The
// same name under two protocol versions is two real acceptances and stays two.
//
// A few upstream fields are deliberately kept in the tool log alone, and say so on
// their own field comments: a service's device type, OS flavor, detection method,
// and TTL have no domain consumer, and inventing a projection for them would be a
// read model nothing reads. Nothing is dropped silently.
//
// # Isolation boundary
//
// The tool takes no result, client, or cache from another Vanguard tool, and hands
// none back. Enabling or disabling another active tool cannot change this one's
// target plan, arguments, module decisions, event sequence, or payloads for the
// same passive input, and the reverse holds too. The only permitted input to the
// banner, TLS, SSH, crawler, and enumeration modules is this tool's own discovery
// result; passive inventory may seed target addresses and virtual host names, and
// that is all.
//
// Everything the actor learns leaves as a sealed [Event]. There is no result object
// to read afterwards, so an observation that is not on an event did not happen as
// far as the rest of the system is concerned.
//
// # Failure and cancellation
//
// Invalid configuration or an invalid target fails in [New], before any traffic.
// A discovery failure fails that target and blocks its subordinate work, because
// there is nothing left to select from. A subordinate module failure marks the
// target partial, reports its own error, and leaves unrelated modules running.
// Cancellation stops scheduling immediately and returns the context error, and the
// run summary is still reported.
//
// [ModuleSetupFailed], [ModuleTimeout], [ModuleFailed], and [FilesystemError]
// implement [tooleventlog.HealthEvent] because they identify scanner-side loss of
// configured work. Every non-cancellation failed target or job emits one of these
// granular events before it contributes to [ScanCompleted]. The aggregate therefore
// remains health-neutral and cannot double count those failures. [JobSkipped],
// target-owned empty results, cleanup warnings, and cancellation remain outside the
// collection-health contract.
//
// One cancellation cost is unavoidable at the pinned upstream revision: discovery
// and banner collection have no context, so a cancellation arriving mid-module is
// recorded and then waited out. Draining is slower than returning, but returning
// would leave a live nmap child process with nobody to reap it. The full list of
// upstream behavior that shapes this actor lives with the code that touches it, in
// the upstream subpackage documentation.
//
// # Files
//
// The actor creates one temporary root per run and removes it on success, failure,
// and cancellation. Per-job subdirectories live inside it, and nothing is written
// outside it. Response bodies are never stored: an event carries a redacted,
// capped excerpt, the original byte count, and a digest of the raw bytes.
package goscans
