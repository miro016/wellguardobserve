// Package scopecheck defines the shared, policy-neutral vocabulary used to
// authorize target-facing HTTP requests.
//
// Tools normalize a request destination and call an injected [Allow] function
// before sending traffic. The package deliberately owns no engagement policy,
// event emission, HTTP client, or mutable scan state. Those decisions remain with
// the orchestrator, while standalone tools can omit the callback and retain their
// existing behavior.
//
// Request contexts may carry an [Origin] describing the scheduler-approved host
// that produced a derived request. Its depth is discovery-edge depth, not DNS label
// depth. A negative depth means the origin is known but cannot authorize a newly
// referenced DNS name by depth.
//
// The package also provides the hard traffic-boundary primitives every active tool
// reuses. [Exclusions] is a compiled, immutable, policy-neutral set of out-of-scope
// domain names (exact name plus subdomains) and canonical CIDR prefixes; it only
// matches, never decides which names or prefixes are excluded (the orchestrator
// supplies those from the engagement config). [PolicyDialer] enforces that set at
// dial time: it resolves a hostname once, drops every excluded answer, and connects
// to an allowed literal address, so a second resolver lookup cannot reintroduce an
// excluded address between the check and the connection. A destination whose every
// resolved answer is excluded is refused with a typed [RejectedError] before any
// socket is opened, never as a dial timeout. That error carries the denied addresses
// in [RejectedError.ResolvedIPs]: the name itself is in scope, so only they identify
// the rule that fired, and a caller emitting a typed rejection event would otherwise
// record just the host it was probing. A nil *Exclusions excludes nothing, so
// a standalone tool or unit test may leave the boundary unset. [WithRejectionSink]
// lets orchestration audit each denied literal or DNS answer, including excluded
// answers in an otherwise allowed mixed result.
package scopecheck
