package https

import (
	"log/slog"
	"time"
)

const toolName = "https"

// CertificatePreflightStarted is emitted before the single TLS handshake used to
// corroborate ownership of a provider-only address.
type CertificatePreflightStarted struct {
	Address    string
	ServerName string
}

// ToolName returns the tool identifier.
func (CertificatePreflightStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertificatePreflightStarted) EventName() string { return "https: certificate preflight started" }

// EventLevel returns the log severity.
func (CertificatePreflightStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertificatePreflightStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("address", e.Address), slog.String("server_name", e.ServerName)}
}

// CertificatePreflightCompleted is emitted after a successful certificate
// preflight. DNSNames is the bounded evidence returned to the orchestrator.
type CertificatePreflightCompleted struct {
	Address    string
	ServerName string
	DNSNames   []string
}

// ToolName returns the tool identifier.
func (CertificatePreflightCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertificatePreflightCompleted) EventName() string {
	return "https: certificate preflight completed"
}

// EventLevel returns the log severity.
func (CertificatePreflightCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertificatePreflightCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("address", e.Address),
		slog.String("server_name", e.ServerName),
		slog.Int("dns_names", len(e.DNSNames)),
	}
}

// ProbeStarted is emitted when an HTTPS probe begins for a target and port.
type ProbeStarted struct {
	Target string
	Port   int
}

// ToolName returns the tool identifier.
func (ProbeStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeStarted) EventName() string { return "https: probe started" }

// EventLevel returns the log severity.
func (ProbeStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("target", e.Target), slog.Int("port", e.Port)}
}

// TLSPostureDiscovered is emitted when TLS posture and security headers are extracted.
type TLSPostureDiscovered struct {
	Target     string
	TLSVersion string
	Cipher     string
	HasHSTS    bool
	SANCount   int
}

// ToolName returns the tool identifier.
func (TLSPostureDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TLSPostureDiscovered) EventName() string { return "https: posture discovered" }

// EventLevel returns the log severity.
func (TLSPostureDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSPostureDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("tls_version", e.TLSVersion),
		slog.String("cipher", e.Cipher),
		slog.Bool("hsts", e.HasHSTS),
		slog.Int("san_count", e.SANCount),
	}
}

// TLSHandshakeTimeout is emitted when a TLS handshake times out connecting to server.
type TLSHandshakeTimeout struct {
	Target  string
	Timeout time.Duration
}

// ToolName returns the tool identifier.
func (TLSHandshakeTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TLSHandshakeTimeout) EventName() string { return "https: handshake timeout" }

// EventLevel returns the log severity.
func (TLSHandshakeTimeout) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSHandshakeTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Duration("timeout", e.Timeout),
	}
}

// CertificateExpired is emitted when peer SSL certificate has expired.
type CertificateExpired struct {
	Target   string
	NotAfter time.Time
	Subject  string
}

// ToolName returns the tool identifier.
func (CertificateExpired) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertificateExpired) EventName() string { return "https: certificate expired" }

// EventLevel returns the log severity.
func (CertificateExpired) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertificateExpired) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Time("not_after", e.NotAfter),
		slog.String("subject", e.Subject),
	}
}

// CertificateChainInvalid is emitted when the certificate chain the server served
// does not validate: no path to a trusted root could be built from it, or the name
// probed is not one the certificate covers, or a certificate in it has expired.
//
// It is deliberately not called "untrusted root". The usual cause is an incomplete
// deployment - the server did not send the intermediate that links its leaf to a
// root the trust store already holds - and naming the root would point at the one
// part of the chain that is fine.
type CertificateChainInvalid struct {
	Target string
	Issuer string
	Err    error
}

// ToolName returns the tool identifier.
func (CertificateChainInvalid) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (CertificateChainInvalid) EventName() string { return "https: certificate chain did not validate" }

// EventLevel returns the log severity.
func (CertificateChainInvalid) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CertificateChainInvalid) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("issuer", e.Issuer),
		slog.Any("error", e.Err),
	}
}

// ProtocolNegotiationFailed is emitted when server rejects TLS protocol version or cipher suite.
type ProtocolNegotiationFailed struct {
	Target     string
	OfferedVer string
	Err        error
}

// ToolName returns the tool identifier.
func (ProtocolNegotiationFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProtocolNegotiationFailed) EventName() string { return "https: protocol negotiation failed" }

// EventLevel returns the log severity.
func (ProtocolNegotiationFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProtocolNegotiationFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("offered_ver", e.OfferedVer),
		slog.Any("error", e.Err),
	}
}

// ConnectionRefused is emitted when TCP connection is refused before TLS handshake.
type ConnectionRefused struct {
	Target string
	Port   int
}

// ToolName returns the tool identifier.
func (ConnectionRefused) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionRefused) EventName() string { return "https: connection refused" }

// EventLevel returns the log severity.
func (ConnectionRefused) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionRefused) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Int("port", e.Port),
	}
}

// DNSResolutionFailed is emitted when target hostname fails DNS lookup before TLS connection.
type DNSResolutionFailed struct {
	Target string
	Err    error
}

// ToolName returns the tool identifier.
func (DNSResolutionFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSResolutionFailed) EventName() string { return "https: DNS resolution failed" }

// EventLevel returns the log severity.
func (DNSResolutionFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSResolutionFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Any("error", e.Err),
	}
}

// TLSInfoFailed is emitted when the leaf certificate / chain could not be
// retrieved and error cannot be subclassified.
type TLSInfoFailed struct {
	Target string
	Err    error
}

// ToolName returns the tool identifier.
func (TLSInfoFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TLSInfoFailed) EventName() string { return "https: tls info failed" }

// EventLevel returns the log severity.
func (TLSInfoFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSInfoFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("target", e.Target), slog.Any("error", e.Err)}
}

// HeadersFetchFailed is emitted when the HTTPS GET for security headers / HSTS failed.
type HeadersFetchFailed struct {
	Target string
	Err    error
}

// RedirectFollowed is emitted after a header-request redirect passes policy.
type RedirectFollowed struct {
	Target  string
	FromURL string
	ToURL   string
	Status  int
	Hop     int
}

// ToolName returns the tool identifier.
func (RedirectFollowed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectFollowed) EventName() string { return "https: redirect followed" }

// EventLevel returns the log severity.
func (RedirectFollowed) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured redirect fields.
func (e RedirectFollowed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target), slog.String("from_url", e.FromURL),
		slog.String("to_url", e.ToURL), slog.Int("status", e.Status), slog.Int("hop", e.Hop),
	}
}

// RedirectRejected is emitted when policy denies a header-request redirect.
type RedirectRejected struct {
	Target  string
	FromURL string
	ToURL   string
	Status  int
	Hop     int
	Reason  string
}

// ToolName returns the tool identifier.
func (RedirectRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectRejected) EventName() string { return "https: redirect rejected" }

// EventLevel returns the log severity.
func (RedirectRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured redirect fields and policy reason.
func (e RedirectRejected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target), slog.String("from_url", e.FromURL),
		slog.String("to_url", e.ToURL), slog.Int("status", e.Status),
		slog.Int("hop", e.Hop), slog.String("reason", e.Reason),
	}
}

// RedirectLimitReached is emitted before a header redirect would exceed the cap.
type RedirectLimitReached struct {
	Target string
	URL    string
	Limit  int
}

// ToolName returns the tool identifier.
func (RedirectLimitReached) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectLimitReached) EventName() string { return "https: redirect limit reached" }

// EventLevel returns the log severity.
func (RedirectLimitReached) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the target, rejected URL, and configured cap.
func (e RedirectLimitReached) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("target", e.Target), slog.String("url", e.URL), slog.Int("limit", e.Limit)}
}

// ToolName returns the tool identifier.
func (HeadersFetchFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HeadersFetchFailed) EventName() string { return "https: headers fetch failed" }

// EventLevel returns the log severity.
func (HeadersFetchFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HeadersFetchFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("target", e.Target), slog.Any("error", e.Err)}
}

// ProbeFailed is emitted when the probe cannot run at all or fails without classification.
type ProbeFailed struct {
	Target string
	Err    error
}

// ToolName returns the tool identifier.
func (ProbeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeFailed) EventName() string { return "https: probe failed" }

// EventLevel returns the log severity.
func (ProbeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("target", e.Target), slog.Any("error", e.Err)}
}

// ProbeCompleted is emitted when an HTTPS probe finishes, summarizing inspection metrics.
type ProbeCompleted struct {
	Target           string
	TotalEndpoints   int
	HandshakeSuccess int
	HandshakeFailed  int
	Degraded         bool
}

// ToolName returns the tool identifier.
func (ProbeCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeCompleted) EventName() string { return "https: probe completed" }

// EventLevel returns the log severity.
func (ProbeCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Int("endpoints", e.TotalEndpoints),
		slog.Int("succeeded", e.HandshakeSuccess),
		slog.Int("failed", e.HandshakeFailed),
		slog.Bool("degraded", e.Degraded),
	}
}

// TargetRejected is emitted when the hard exclusion policy denies an HTTPS target
// before any socket opens: an excluded initial domain, literal, provider-preflight
// SNI name, or a hostname whose every resolved address is excluded. It is a policy decision, distinct from a
// TLS handshake failure, a DNS resolution failure, or an unreachable host, so a
// reader must not treat it as unsupported-version, invalid-chain, or unreachable
// evidence. ResolvedIP names the excluded address when the rejection was decided
// after resolution and is empty for a domain-rule or literal rejection.
type TargetRejected struct {
	Target     string
	ResolvedIP string
	// ResolvedIPs names every excluded address behind a hostname denied because all
	// of its answers are excluded. Target is then the in-scope name being probed, so
	// these addresses are the only record of which rule actually fired; without them
	// an audit cannot reconcile the rejection to the IP exclusion that caused it.
	// Empty for a domain-rule, literal, or single-address rejection.
	ResolvedIPs []string
	Reason      string
}

// ToolName returns the tool identifier.
func (TargetRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TargetRejected) EventName() string { return "https: target rejected" }

// EventLevel returns the log severity.
func (TargetRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TargetRejected) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{slog.String("target", e.Target)}
	if e.ResolvedIP != "" {
		attrs = append(attrs, slog.String("resolved_ip", e.ResolvedIP))
	}
	if len(e.ResolvedIPs) > 0 {
		attrs = append(attrs, slog.Any("resolved_ips", e.ResolvedIPs))
	}
	return append(attrs, slog.String("reason", e.Reason))
}
