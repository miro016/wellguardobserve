// Package portscan provides an active-phase port scanner built on the
// projectdiscovery naabu library with nmap-based service detection.
//
// The Client scans a list of ports on a single IP with naabu (an unprivileged
// TCP connect scan) and, when a nmap command is configured, has naabu run nmap
// against the open ports to fingerprint the service, product, version, and CPEs.
// It also derives a truncated banner from the nmap fingerprint (the raw
// ServiceFP probe response when nmap could not match the service, the assembled
// product/version/extra-info otherwise) so downstream consumers have a raw
// service string to corroborate a build against. It surfaces the coarse OS
// family nmap's service detection attaches per port (OSType) as well; the
// orchestrator folds those into a host OS guess. Note this is a service-detection
// hint, not nmap's privileged -O OS fingerprint, which naabu does not expose on
// the connect-scan result path.
// Config.RatePerSecond is naabu's per-host probe rate. Host concurrency belongs
// to the orchestrator, which uses a separate limiter so aggregate egress is the
// configured rate multiplied by the configured host concurrency.
// It returns the open ports in ascending order and emits granular system events
// (ScanStarted, PortOpen, ServiceBannerDiscovered, PermissionDenied,
// NetworkUnreachable, ScanThrottled, ScanCompleted, ScanError) so the orchestrator
// can translate them into domain events and surface them in tool logs. ScanCompleted
// provides standardized quantitative metrics (total scanned, open, closed, filtered,
// timeout counts, and degraded flag). Granular error events distinguish socket
// permission issues and routing failures from generic errors, and ScanThrottled
// reports when consecutive timeouts suggest rate limiting or stateful filtering.
// [PermissionDenied] and [ScanError] implement [tooleventlog.HealthEvent] because
// they identify a local scanner failure that prevented configured work. Closed or
// filtered ports, target unreachability, throttling, scope rejection, and the
// aggregate [ScanCompleted] event remain health-neutral target or policy outcomes.
//
// nmap is a hard dependency of this tool even though naabu itself treats it as
// optional: the apps verify nmap is installed (config.Config.ValidateExternalTools)
// before starting and refuse to run the scan when it is missing.
//
// IPv6 targets get the nmap -6 flag added to the configured command automatically
// (nmapCommandFor): nmap needs -6 to scan an IPv6 address and naabu does not add
// it, so without it naabu still finds the open IPv6 ports but nmap returns no
// service/product/version for them. The configured nmap_command therefore stays a
// single IPv4/IPv6-agnostic string; the tool adapts it per target. New validates
// the configured command against a narrow allowlist of service-detection flags so
// typos fail before naabu starts instead of silently producing an empty nmap pass.
//
// Reachable is a companion to Scan: a TCP-layer tiebreaker for the ambiguous
// "zero open ports" outcome (a connect scan cannot tell a closed port from a
// filtered one), so a caller can tell a reachable-but-empty host from one that is
// down or filtered and record a coverage gap instead of a false clean result.
//
// # The UDP pass
//
// ScanUDP is a second, independent pass over the same target, run by invoking
// nmap directly with -sU rather than through naabu: naabu keeps one global UDP
// payload, discards silence, and carries no per-port state, so it cannot express
// the only answer a UDP probe usually has. It is not a mode of Scan and not a
// fallback for it. It is never skipped because no TCP port answered, its result
// never seeds a TCP follow-up, and a client with Config.UDP.Enabled false opens no
// UDP socket, starts no -sU process, and leaves the naabu invocation, its results,
// and its events exactly as they were.
//
// The caller owns host concurrency and runs the two passes sequentially inside one
// host's slot; this client owns the per-host rate, the per-port timeout, retries,
// and the port-count cap. The nmap executable is not looked up here: Config.UDP
// carries the absolute path collection preflight resolved and proved able to open
// a raw socket, together with whether that nmap needs --privileged on this
// machine, so the binary that was checked is the binary that runs.
//
// Four states come back and none of them is collapsed. Only "open" - a confirmed
// positive response - is a service and becomes a UDPPortOpen event with
// Protocol "udp". "open|filtered" is silence: the probe went out and nothing came
// back, which may be a service that answers only a protocol-correct payload or a
// filter, and is coverage rather than either a service or a clean negative.
// "closed" is an ICMP port-unreachable, which proves the host is up. "filtered" is
// an explicit rejection in the path. Every non-open port keeps nmap's reason
// string in the tool stream, because "no-response" and "port-unreach" are
// different facts and a capture that kept only the state could not tell them
// apart afterwards. A state string outside those four abandons the pass with
// bounded raw context (UDPParsingError): reading an unknown state as closed would
// turn an upstream output change into a confident false statement about a
// customer's attack surface.
//
// nmap folds a run of same-state ports into an aggregate count rather than listing
// each one. UDPResult.Collapsed keeps those groups, so UDPResult.Accounted can say
// how many of the requested ports actually came back with a verdict; without it a
// pass could report one open port out of eight and silently lose the other seven.
//
// A pass that produced evidence and then failed returns that evidence together
// with a *UDPPartialError, so the caller can publish the services that were
// confirmed and separately record the coverage that was lost. A pass that failed
// outright returns no result at all - nothing is fabricated - and cancellation
// returns the context error after emitting its terminal event.
//
// A successful exit status is not proof of coverage either. When the parsed
// result accounts for a different number of ports than were requested - fewer
// (truncated or malformed output) or more (a document that is not the pass this
// code built) - the evidence is kept, the completion is marked partial, and the
// pass returns a *UDPAccountingError so the caller degrades collection and the
// active phase stays retryable rather than checkpointing coverage that never
// happened.
//
// Health is deliberately narrow. UDPScanError, UDPPermissionDenied, and
// UDPParsingError are health-bearing under the component "udp-nmap", because each
// means configured work was lost. A completed pass is healthy however little it
// found: zero open ports, an all-ambiguous result, and a host that refused every
// port are target outcomes and coverage facts, not scanner failures. A cancelled
// pass is not health-bearing either, because the capture manifest is the authority
// on what an interrupted run collected.
//
// The vendored nmap wrapper stays inside this package: the invocation is built in
// one adapter (udp_nmap.go), and nmap.Run, nmap.Port, and nmap.Option appear in no
// event, no configuration, and no cross-package signature. An upstream change
// therefore breaks that adapter and its contract test rather than the collection
// contract. The contract test and every mapping test run from recorded nmap XML,
// so they need no nmap binary, no privileges, and no network.
//
// This is active reconnaissance: it sends traffic to the target. It must only be
// run when the active phase is explicitly enabled.
//
// Config.Allow is the shared request authorizer the orchestrator injects. Scan,
// ScanUDP, and Reachable validate the target IP through it before any engine runs
// - before a naabu runner is constructed, an nmap argument list is built, a child
// process exists, a reachability dial is made, or a started-scan event is emitted
// - so a hard-excluded or unapproved address sends no traffic and starts no scan
// on either transport. A denied target emits a typed TargetRejected and the scan
// returns a *scopecheck.RejectedError; this is a policy decision, never an
// unreachable or clean-negative result, so Reachable's false must not be read as
// coverage. The outer scheduler remains the primary boundary; this check is defense
// in depth for programmatic calls. Both transports share the one authorizer: there
// is no UDP-specific exclusion list to keep in step with the TCP one. A nil Allow
// permits every valid target, for standalone and test callers.
package portscan
