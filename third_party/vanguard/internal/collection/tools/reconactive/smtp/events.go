package smtp

import (
	"log/slog"
	"time"
)

const toolName = "smtp"

// ProbeStarted is emitted when an SMTP STARTTLS probe begins for a domain.
type ProbeStarted struct {
	Domain         string
	MXServersCount int
}

// ToolName returns the tool identifier.
func (ProbeStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeStarted) EventName() string { return "smtp: probe started" }

// EventLevel returns the log severity.
func (ProbeStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("mx_servers_count", e.MXServersCount),
	}
}

// MxProbed is emitted for each MX host probed, with its STARTTLS outcome.
type MxProbed struct {
	Domain   string
	Host     string
	StartTLS bool
}

// ToolName returns the tool identifier.
func (MxProbed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (MxProbed) EventName() string { return "smtp: mx probed" }

// EventLevel returns the log severity.
func (MxProbed) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e MxProbed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("host", e.Host),
		slog.Bool("starttls", e.StartTLS),
	}
}

// MxProbeFailed is emitted when a single MX host could not be probed. Other MX
// hosts are still attempted.
type MxProbeFailed struct {
	Domain string
	Host   string
	Err    string
}

// ToolName returns the tool identifier.
func (MxProbeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (MxProbeFailed) EventName() string { return "smtp: mx probe failed" }

// EventLevel returns the log severity.
func (MxProbeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e MxProbeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("host", e.Host),
		slog.String("error", e.Err),
	}
}

// ProbeCompleted is emitted when the SMTP probe finishes, summarising STARTTLS
// coverage across the domain's MX hosts.
type ProbeCompleted struct {
	Domain            string
	MXHosts           int
	StartTLSHosts     int
	TotalMxServers    int
	SuccessfulProbes  int
	FailedProbes      int
	StartTLSSupported int
	Degraded          bool
}

// ToolName returns the tool identifier.
func (ProbeCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeCompleted) EventName() string { return "smtp: probe completed" }

// EventLevel returns the log severity.
func (ProbeCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("mx_hosts", e.MXHosts),
		slog.Int("starttls_hosts", e.StartTLSHosts),
		slog.Int("probed", e.TotalMxServers),
		slog.Int("succeeded", e.SuccessfulProbes),
		slog.Int("failed", e.FailedProbes),
		slog.Int("starttls_supported", e.StartTLSSupported),
		slog.Bool("degraded", e.Degraded),
	}
}

// ProbeFailed is emitted when the probe cannot proceed (empty domain, MX lookup
// failure, or no MX records). It is fatal to the probe but non-fatal to the scan.
type ProbeFailed struct {
	Domain string
	Err    string
}

// ToolName returns the tool identifier.
func (ProbeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeFailed) EventName() string { return "smtp: probe failed" }

// EventLevel returns the log severity.
func (ProbeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("error", e.Err),
	}
}

// SMTPCapabilitiesDiscovered is emitted when EHLO capabilities and authentication methods are enumerated.
//
//nolint:revive // named specifically per specification
type SMTPCapabilitiesDiscovered struct {
	MXHost      string
	AuthMethods []string
	Extensions  []string
}

// ToolName returns the tool identifier.
func (SMTPCapabilitiesDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SMTPCapabilitiesDiscovered) EventName() string { return "smtp: capabilities discovered" }

// EventLevel returns the log severity.
func (SMTPCapabilitiesDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SMTPCapabilitiesDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("mx_host", e.MXHost),
		slog.Any("auth_methods", e.AuthMethods),
		slog.Any("extensions", e.Extensions),
	}
}

// ConnectionTimeout is emitted when TCP dial or SMTP read/write operations exceed the timeout.
type ConnectionTimeout struct {
	MXHost  string
	Port    string
	Timeout time.Duration
}

// ToolName returns the tool identifier.
func (ConnectionTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionTimeout) EventName() string { return "smtp: connection timeout" }

// EventLevel returns the log severity.
func (ConnectionTimeout) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("mx_host", e.MXHost),
		slog.String("port", e.Port),
		slog.Duration("timeout", e.Timeout),
	}
}

// ConnectionRejected is emitted when server refuses connection with negative status (5xx/4xx) on connect.
type ConnectionRejected struct {
	MXHost  string
	Port    string
	Code    int
	Message string
}

// ToolName returns the tool identifier.
func (ConnectionRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionRejected) EventName() string { return "smtp: connection rejected" }

// EventLevel returns the log severity.
func (ConnectionRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionRejected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("mx_host", e.MXHost),
		slog.String("port", e.Port),
		slog.Int("code", e.Code),
		slog.String("message", e.Message),
	}
}

// BannerFetchFailed is emitted when socket opens but initial 220 banner cannot be read or is invalid.
type BannerFetchFailed struct {
	MXHost string
	Err    error
}

// ToolName returns the tool identifier.
func (BannerFetchFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (BannerFetchFailed) EventName() string { return "smtp: banner fetch failed" }

// EventLevel returns the log severity.
func (BannerFetchFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e BannerFetchFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("mx_host", e.MXHost),
		slog.Any("error", e.Err),
	}
}

// StartTLSFailed is emitted when STARTTLS command fails or handshake errors.
type StartTLSFailed struct {
	MXHost string
	Err    error
}

// ToolName returns the tool identifier.
func (StartTLSFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (StartTLSFailed) EventName() string { return "smtp: STARTTLS failed" }

// EventLevel returns the log severity.
func (StartTLSFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e StartTLSFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("mx_host", e.MXHost),
		slog.Any("error", e.Err),
	}
}

// TLSCertificateError is emitted when STARTTLS negotiation fails specifically due to certificate errors.
type TLSCertificateError struct {
	MXHost string
	Issuer string
	Err    error
}

// ToolName returns the tool identifier.
func (TLSCertificateError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TLSCertificateError) EventName() string { return "smtp: TLS certificate error" }

// EventLevel returns the log severity.
func (TLSCertificateError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSCertificateError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("mx_host", e.MXHost),
		slog.String("issuer", e.Issuer),
		slog.Any("error", e.Err),
	}
}

// TargetRejected is emitted when a hard exclusion denies the input mail domain
// before its MX lookup and before ProbeStarted claims active work. It is a policy
// decision, distinct from a lookup or network failure, and no MX traffic follows.
type TargetRejected struct {
	Domain string
	Reason string
}

// ToolName returns the tool identifier.
func (TargetRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TargetRejected) EventName() string { return "smtp: target rejected" }

// EventLevel returns the log severity.
func (TargetRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TargetRejected) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("reason", e.Reason)}
}

// MXTargetRejected is emitted when a hard exclusion denies one MX destination before
// any banner, EHLO, STARTTLS, or QUIT byte is sent: the MX hostname matched a domain
// exclusion, or every resolved MX address matched an IP exclusion. It is a policy
// decision, distinct from a dial timeout, a connection refusal, or a STARTTLS
// failure, so a reader must not treat it as a mail weakness or a blocked egress. One
// rejected MX never suppresses the evidence collected from the domain's allowed MX
// hosts. ResolvedIP names the excluded address when the rejection followed resolution
// and is empty for a hostname or literal rule.
type MXTargetRejected struct {
	Domain     string
	Host       string
	ResolvedIP string
	Reason     string
}

// ToolName returns the tool identifier.
func (MXTargetRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (MXTargetRejected) EventName() string { return "smtp: mx target rejected" }

// EventLevel returns the log severity.
func (MXTargetRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e MXTargetRejected) EventAttrs() []slog.Attr {
	attrs := []slog.Attr{slog.String("domain", e.Domain), slog.String("host", e.Host)}
	if e.ResolvedIP != "" {
		attrs = append(attrs, slog.String("resolved_ip", e.ResolvedIP))
	}
	return append(attrs, slog.String("reason", e.Reason))
}
