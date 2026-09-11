// Package https performs active HTTPS reconnaissance against endpoints on port 443.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Probe] or concurrent
// batch inspection via [Client.ProbeEndpoints], emitting typed [tooleventlog.Event]
// values (see events.go) to an EventSink for operational observability.
// [Client.ProbeCertificate] is a separate one-handshake preflight used only to
// corroborate a provider-only IP against an in-scope certificate DNS SAN. It never
// performs the protocol sweep or HTTPS request made by Probe.
//
// The client emits comprehensive system events:
//   - Lifecycle and summary: ProbeStarted, ProbeCompleted (standardized metrics
//     with TotalEndpoints, HandshakeSuccess, HandshakeFailed, and Degraded flags).
//   - Discovery: TLSPostureDiscovered (emits target endpoint, negotiated TLS
//     version, cipher suite, HSTS presence, and certificate SAN count).
//   - Granular operational failures: TLSHandshakeTimeout, CertificateExpired,
//     CertificateChainInvalid, ProtocolNegotiationFailed, ConnectionRefused, DNSResolutionFailed,
//     and unclassified fallbacks TLSInfoFailed, HeadersFetchFailed, and ProbeFailed.
//
// Probe opens live HTTPS connections to enumerate supported TLS protocol versions
// (marking old-protocol risk and recording negotiated ciphers), inspects the full
// peer certificate chain, captures leaf certificate metadata and the negotiated
// remote endpoint, and fetches the HSTS policy and common security headers from
// the HTTPS endpoint, returning a [Result].
//
// [Result.ChainValidation] is the verdict on the certificate chain the server
// actually served, built only from the certificates it sent. Passing those as
// intermediates is what makes the verdict mean what it says: without them every
// deployment whose chain needs an intermediate fails with "signed by unknown
// authority" about a root the trust store holds, blaming the target for the
// prober's empty pool. With them, a failure is a real deployment fault - an
// intermediate the server never sent, an issuer no trust store holds, or a name the
// certificate does not cover. Nil means no handshake completed and the chain was
// never judged, which must never be read as a trusted one.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into TlsPostureDiscovered (TLS-version
// support, HSTS, and the chain verdict) and CertificateDiscovered (the live leaf
// certificate).
//
// [Result.Reachable] distinguishes a live probe from a total dial failure. When
// every TLS handshake and the HTTPS GET fail (port closed, host unreachable, DNS
// miss), Probe still returns a [Result] (with no error) but with Reachable false:
// the all-unsupported versions and absent HSTS are then a coverage gap, not a
// clean posture.
// Result.RedirectTrail records decisions made by the security-header HTTP GET;
// TLS-version and certificate handshakes cannot redirect. The GET checks every
// initial and redirect destination through Config.Allow before traffic is sent.
// Its transport derives TLS SNI from each request host, so an allowed cross-host
// redirect cannot retain the original target's server name.
// HeadersComplete distinguishes observed missing headers from an intentionally
// incomplete header request.
//
// [Config.ResolverAddr] points name resolution at a specific DNS server so active
// resolution matches the passive phase, removing the divergence where the passive
// phase resolves a name the active probe then fails to look up. Empty uses the
// system resolver.
//
// [Config.Exclusions] is the hard traffic boundary enforced on every connection the
// actor opens: the first certificate handshake, each protocol-version handshake, the
// security-header GET and its redirects, and the provider certificate preflight. All
// of them dial through one shared resolver-aware policy dialer that resolves a
// hostname once, drops every excluded resolved address, and connects only to an
// allowed literal, while the original name is kept as tls.Config.ServerName (SNI) and
// the HTTP Host header. The initial target is authorized before the first handshake
// (previously only the header GET was), and ProbeCertificate rechecks both its literal
// address and SNI server name at the tool boundary as defense in depth behind the
// orchestrator's provider gate. An
// excluded initial target or an all-excluded resolution is a typed policy rejection
// (a "https: target rejected" event), which short-circuits the version sweep and
// header request rather than producing false unsupported-version, invalid-chain, or
// unreachable evidence; it is never a TLS or DNS failure. Every refused initial,
// resolved, redirect, SNI, or provider-preflight destination is also reported through
// the context's scopecheck rejection sink, allowing orchestration to audit the exact
// destination and matched rule even when another allowed address succeeds. Ambient proxies are
// disabled on the header transport so a process proxy cannot reach a rejected
// destination. A nil Exclusions excludes nothing, for standalone use; production
// injects the engagement exclusions.
package https
