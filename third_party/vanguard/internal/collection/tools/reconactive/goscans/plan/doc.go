// Package plan decides what the goscans tool will probe, and in what order.
//
// It is pure: given one discovery result it returns the subordinate jobs to run
// and the skips to record, with no clock, no network, and no filesystem. That is
// what makes the tool's isolation testable. The promise is that the same passive
// input yields the same plan no matter which other Vanguard tools are enabled, and
// a pure function of the discovery result is the only way to keep it.
//
// # Selection
//
// A service is classified by transport, nmap service name, nmap tunnel attribute,
// and the operator's additive port lists, in that order of authority. The tunnel
// attribute matters as much as the name: nmap describes a TLS-wrapped HTTP service
// as name "http" with tunnel "ssl", so a table reading the name alone would call an
// HTTPS service cleartext and probe it in the clear.
//
// The transport gate is load bearing rather than defensive. The upstream banner
// module accepts "udp" and dials it, while the TLS, SSH, and web modules dial "tcp"
// unconditionally, so a table keyed on port alone would either send TCP-shaped
// traffic at a UDP service or record silence as a result. A non-TCP service is
// therefore skipped by every module, and the skip is recorded rather than dropped.
//
// # Ordering and caps
//
// Services are sorted by transport, port, and tunnel before selection, and jobs and
// skips are sorted by target, transport, port, and module afterwards, because nmap
// promises no order and an unstable plan would make two runs of the same target
// look different. Services beyond the per-host cap are skipped with their own
// reason, so a capped host is visibly capped rather than quietly short.
package plan
