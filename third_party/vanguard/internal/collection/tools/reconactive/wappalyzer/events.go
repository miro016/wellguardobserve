package wappalyzer

import "log/slog"

const toolName = "wappalyzer"

// ProbeStarted is emitted when a fingerprint probe begins for a domain. It brackets
// every probe together with ProbeCompleted.
type ProbeStarted struct {
	Domain string
	// URL is the first URL that will be requested (the HTTPS form).
	URL string
}

// ToolName returns the tool identifier.
func (ProbeStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeStarted) EventName() string { return "wappalyzer: probe started" }

// EventLevel returns the log severity.
func (ProbeStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("url", e.URL)}
}

// ProbeCompleted is emitted when a fingerprint probe finishes, successfully or not.
// Matches lets a replay tell a clean empty result (probe worked, nothing matched)
// from a failure, which is why it is reported even when Degraded is true.
type ProbeCompleted struct {
	Domain     string
	FinalURL   string
	StatusCode int
	// Matches is the number of technologies identified.
	Matches int
	// BodyBytes is how many response body bytes were read, after the cap.
	BodyBytes int
	// Redirects is how many redirect hops were followed.
	Redirects int
	// Degraded is true when no response was fingerprinted. Both schemes may have
	// failed, or a final policy outcome such as rejected redirect may have stopped
	// fallback.
	Degraded bool
}

// ToolName returns the tool identifier.
func (ProbeCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeCompleted) EventName() string { return "wappalyzer: probe completed" }

// EventLevel returns the log severity.
func (ProbeCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("final_url", e.FinalURL),
		slog.Int("status", e.StatusCode),
		slog.Int("matches", e.Matches),
		slog.Int("body_bytes", e.BodyBytes),
		slog.Int("redirects", e.Redirects),
		slog.Bool("degraded", e.Degraded),
	}
}

// RedirectFollowed is emitted for each redirect hop the probe follows, so the path
// from the requested URL to the fingerprinted one is auditable.
type RedirectFollowed struct {
	Domain  string
	FromURL string
	ToURL   string
	Status  int
	// Hop is the 1-based index of this redirect within the attempt.
	Hop int
}

// ToolName returns the tool identifier.
func (RedirectFollowed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectFollowed) EventName() string { return "wappalyzer: redirect followed" }

// EventLevel returns the log severity.
func (RedirectFollowed) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RedirectFollowed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("from_url", e.FromURL),
		slog.String("to_url", e.ToURL),
		slog.Int("status", e.Status),
		slog.Int("hop", e.Hop),
	}
}

// RedirectLimitReached is emitted when a redirect chain exceeds MaxRedirects. The
// attempt ends there; it is a bounded-probe outcome, not an unclassified failure.
type RedirectLimitReached struct {
	Domain string
	URL    string
	Limit  int
}

// ToolName returns the tool identifier.
func (RedirectLimitReached) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectLimitReached) EventName() string { return "wappalyzer: redirect limit reached" }

// EventLevel returns the log severity.
func (RedirectLimitReached) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RedirectLimitReached) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("url", e.URL),
		slog.Int("limit", e.Limit),
	}
}

// RedirectRejected is emitted when request policy denies a redirect destination.
type RedirectRejected struct {
	Domain  string
	FromURL string
	ToURL   string
	Status  int
	Hop     int
	Reason  string
}

// ToolName returns the tool identifier.
func (RedirectRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectRejected) EventName() string { return "wappalyzer: redirect rejected" }

// EventLevel returns the log severity.
func (RedirectRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RedirectRejected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("from_url", e.FromURL),
		slog.String("to_url", e.ToURL),
		slog.Int("status", e.Status),
		slog.Int("hop", e.Hop),
		slog.String("reason", e.Reason),
	}
}

// TechnologyDiscovered is emitted once per identified technology, in the same sorted
// order as the returned result.
type TechnologyDiscovered struct {
	Domain     string
	URL        string
	TechName   string
	Version    string
	Categories []string
	CPEs       []string
}

// ToolName returns the tool identifier.
func (TechnologyDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TechnologyDiscovered) EventName() string { return "wappalyzer: technology discovered" }

// EventLevel returns the log severity.
func (TechnologyDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TechnologyDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("url", e.URL),
		slog.String("tech_name", e.TechName),
		slog.String("version", e.Version),
		slog.Any("categories", e.Categories),
		slog.Any("cpes", e.CPEs),
	}
}

// RateLimited is emitted when the target returns HTTP 429. The probe still returns a
// result when the body read succeeds: a 429 body often still carries CDN and WAF
// signatures worth recording.
type RateLimited struct {
	Domain     string
	URL        string
	StatusCode int
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "wappalyzer: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("url", e.URL),
		slog.Int("status_code", e.StatusCode),
	}
}

// DNSResolutionFailed is emitted when the probe could not resolve the target name.
type DNSResolutionFailed struct {
	Domain string
	URL    string
	Err    error
}

// ToolName returns the tool identifier.
func (DNSResolutionFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSResolutionFailed) EventName() string { return "wappalyzer: dns resolution failed" }

// EventLevel returns the log severity.
func (DNSResolutionFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSResolutionFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("url", e.URL), slog.Any("error", e.Err)}
}

// ConnectionTimeout is emitted when an attempt exceeded the configured timeout.
type ConnectionTimeout struct {
	Domain  string
	URL     string
	Timeout string
}

// ToolName returns the tool identifier.
func (ConnectionTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionTimeout) EventName() string { return "wappalyzer: connection timeout" }

// EventLevel returns the log severity.
func (ConnectionTimeout) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("url", e.URL), slog.String("timeout", e.Timeout)}
}

// ConnectionRefused is emitted when the target actively refused the connection: the
// name resolves but nothing is listening on that scheme's port.
type ConnectionRefused struct {
	Domain string
	URL    string
}

// ToolName returns the tool identifier.
func (ConnectionRefused) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionRefused) EventName() string { return "wappalyzer: connection refused" }

// EventLevel returns the log severity.
func (ConnectionRefused) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionRefused) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("url", e.URL)}
}

// TLSHandshakeFailed is emitted when the TLS handshake itself failed. Certificate
// validity is not a cause: the probe does not verify certificates, so this means a
// protocol-level failure such as a version mismatch or a reset mid-handshake.
type TLSHandshakeFailed struct {
	Domain string
	URL    string
	Err    error
}

// ToolName returns the tool identifier.
func (TLSHandshakeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TLSHandshakeFailed) EventName() string { return "wappalyzer: tls handshake failed" }

// EventLevel returns the log severity.
func (TLSHandshakeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSHandshakeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("url", e.URL), slog.Any("error", e.Err)}
}

// BodyReadFailed is emitted when the response arrived but its body could not be read
// to completion. Nothing is fingerprinted from a partial read.
type BodyReadFailed struct {
	Domain string
	URL    string
	// BytesRead is how many bytes arrived before the read failed.
	BytesRead int
	Err       error
}

// ToolName returns the tool identifier.
func (BodyReadFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (BodyReadFailed) EventName() string { return "wappalyzer: body read failed" }

// EventLevel returns the log severity.
func (BodyReadFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e BodyReadFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("url", e.URL),
		slog.Int("bytes_read", e.BytesRead),
		slog.Any("error", e.Err),
	}
}

// ProbeFailed is the fallback for an error none of the granular events classify, and
// for the whole probe giving up after both schemes failed. It is fatal to the probe
// and non-fatal to the scan.
type ProbeFailed struct {
	Domain string
	URL    string
	Err    error
}

// ToolName returns the tool identifier.
func (ProbeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeFailed) EventName() string { return "wappalyzer: probe failed" }

// EventLevel returns the log severity.
func (ProbeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.String("url", e.URL), slog.Any("error", e.Err)}
}
