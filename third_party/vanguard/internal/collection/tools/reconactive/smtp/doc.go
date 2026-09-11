// Package smtp performs active SMTP STARTTLS reconnaissance against a domain's MX
// hosts.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Probe], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome. Probe
// resolves the domain's MX records, connects to each SMTP service, reads the
// banner, sends EHLO, checks for STARTTLS support, upgrades the connection to TLS
// when available, and extracts certificate metadata from the negotiated session,
// returning a [Result] of per-host [MXProbeResult] values.
//
// Name resolution goes through the configured DNS server ([Config.ResolverAddr],
// wired from the dnsinfo resolver), for both the MX lookup and the per-MX-host
// dial, so active resolution matches the passive phase rather than diverging via
// the OS default resolver. An empty ResolverAddr falls back to the system
// resolver. The MX lookup stays behind an injectable seam ([MXResolver]) for
// tests.
//
// Lifecycle and operational events report detailed execution progress and health:
//   - ProbeStarted (with MX servers count) and ProbeCompleted bracket every probe.
//     ProbeCompleted reports total servers, successful/failed probes, STARTTLS
//     support count, and a Degraded flag if any MX host failed or timed out.
//   - SMTPCapabilitiesDiscovered logs enumerated EHLO extensions and authentication
//     mechanisms (e.g. PLAIN, LOGIN).
//   - Granular operational error events (ConnectionTimeout, ConnectionRejected,
//     BannerFetchFailed, StartTLSFailed, and TLSCertificateError) pinpoint specific
//     transport and protocol failures without failing the scan.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into MxTlsDiscovered (per-MX STARTTLS
// posture) and CertificateDiscovered (the negotiated MX leaf certificate). When
// every MX host's TCP/25 connect timed out, [Result.EgressLikelyBlocked] reports
// the signature of a blocked outbound-25 egress (common on cloud runners), which
// lets the orchestrator record an explicit coverage gap instead of a silent empty
// posture. A refused or later-stage failure proves port 25 was reachable and so
// does not count.
//
// [Config.Allow] and [Config.Exclusions] are the hard traffic boundary. The input
// mail domain is authorized before its MX lookup and before ProbeStarted, so an
// excluded domain triggers no DNS or SMTP traffic. Every returned MX hostname is
// checked against explicit domain exclusions (the engagement root/include boundary
// is not applied to an MX provider, so an allowed domain may delegate mail
// externally, while a named exclusion is a hard deny), and each retained MX hostname
// is resolved once through the shared policy dialer, which drops excluded addresses
// and dials only an allowed literal while keeping the hostname for TLS SNI. A refused
// MX destination sends no banner, EHLO, STARTTLS, or QUIT byte; it is recorded as a
// granular MXTargetRejected event with MXProbeResult.PolicyRejected set, does not
// suppress the evidence collected from the domain's allowed MX hosts, and
// participates in neither the mail posture nor [Result.EgressLikelyBlocked] - a
// policy rejection is never a target weakness or a runner egress failure. Each
// rejected MX name or resolved address is also reported through the context's
// scopecheck rejection sink, including partial MX sets where an allowed host remains
// usable, so orchestration can audit the exact destination and matched rule.
// [Result.PolicyLimited] reports the all-MX-excluded case so the orchestrator raises
// a scope decision rather than a clean or blocked mail posture. A nil Allow and nil
// Exclusions keep the standalone behavior; production injects both.
package smtp
