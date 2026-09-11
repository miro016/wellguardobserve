package httpprobe

import (
	"log/slog"
	"time"
)

const toolName = "httpprobe"

// ProbeStarted is emitted when an HTTP probe begins for a URL or batch of URLs.
type ProbeStarted struct {
	Target string
	URL    string
	Ports  []int
}

// ToolName returns the tool identifier.
func (ProbeStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeStarted) EventName() string { return "httpprobe: probe started" }

// EventLevel returns the log severity.
func (ProbeStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.Any("ports", e.Ports),
	}
}

// ProbeSucceeded is emitted when an HTTP probe receives a response.
type ProbeSucceeded struct {
	Target        string
	URL           string
	FinalURL      string
	StatusCode    int
	Server        string
	ContentLength int64
}

// ToolName returns the tool identifier.
func (ProbeSucceeded) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeSucceeded) EventName() string { return "httpprobe: probe succeeded" }

// EventLevel returns the log severity.
func (ProbeSucceeded) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeSucceeded) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.String("final_url", e.FinalURL),
		slog.Int("status_code", e.StatusCode),
		slog.String("server", e.Server),
		slog.Int64("content_length", e.ContentLength),
	}
}

// ProbeFailed is emitted when an HTTP probe cannot reach the URL and error cannot be subclassified.
type ProbeFailed struct {
	URL string
	Err error
}

// ToolName returns the tool identifier.
func (ProbeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeFailed) EventName() string { return "httpprobe: probe failed" }

// EventLevel returns the log severity.
func (ProbeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("url", e.URL), slog.Any("error", e.Err)}
}

// RedirectFollowed is emitted when an intermediate HTTP redirect hop is traversed.
type RedirectFollowed struct {
	Target  string
	FromURL string
	ToURL   string
	Status  int
	// Hop is the one-based redirect position.
	Hop int
}

// ToolName returns the tool identifier.
func (RedirectFollowed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectFollowed) EventName() string { return "httpprobe: redirect followed" }

// EventLevel returns the log severity.
func (RedirectFollowed) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RedirectFollowed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("from_url", e.FromURL),
		slog.String("to_url", e.ToURL),
		slog.Int("status", e.Status),
		slog.Int("hop", e.Hop),
	}
}

// RedirectRejected is emitted when request policy denies a redirect destination.
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
func (RedirectRejected) EventName() string { return "httpprobe: redirect rejected" }

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

// ConnectionTimeout is emitted when an active probe times out connecting or reading headers.
type ConnectionTimeout struct {
	Target  string
	URL     string
	Timeout time.Duration
}

// ToolName returns the tool identifier.
func (ConnectionTimeout) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionTimeout) EventName() string { return "httpprobe: connection timeout" }

// EventLevel returns the log severity.
func (ConnectionTimeout) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.Duration("timeout", e.Timeout),
	}
}

// DNSResolutionFailed is emitted when target hostname fails DNS lookup before HTTP connection.
type DNSResolutionFailed struct {
	Target string
	Err    error
}

// ToolName returns the tool identifier.
func (DNSResolutionFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (DNSResolutionFailed) EventName() string { return "httpprobe: DNS resolution failed" }

// EventLevel returns the log severity.
func (DNSResolutionFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DNSResolutionFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Any("error", e.Err),
	}
}

// ConnectionRefused is emitted when target port actively refused connection (closed).
type ConnectionRefused struct {
	Target string
	URL    string
	Port   int
}

// ToolName returns the tool identifier.
func (ConnectionRefused) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ConnectionRefused) EventName() string { return "httpprobe: connection refused" }

// EventLevel returns the log severity.
func (ConnectionRefused) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ConnectionRefused) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.Int("port", e.Port),
	}
}

// TLSHandshakeFailed is emitted when TLS negotiation failed during an HTTPS probe.
type TLSHandshakeFailed struct {
	Target string
	URL    string
	Err    error
}

// ToolName returns the tool identifier.
func (TLSHandshakeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TLSHandshakeFailed) EventName() string { return "httpprobe: TLS handshake failed" }

// EventLevel returns the log severity.
func (TLSHandshakeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSHandshakeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.Any("error", e.Err),
	}
}

// RateLimited is emitted when upstream web server returned HTTP 429 rate limit.
type RateLimited struct {
	Target     string
	URL        string
	StatusCode int
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "httpprobe: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.Int("status_code", e.StatusCode),
	}
}

// WAFBlocked is emitted when Web Application Firewall challenge or block page is detected.
type WAFBlocked struct {
	Target  string
	URL     string
	WAFName string
}

// ToolName returns the tool identifier.
func (WAFBlocked) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (WAFBlocked) EventName() string { return "httpprobe: WAF blocked" }

// EventLevel returns the log severity.
func (WAFBlocked) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e WAFBlocked) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.String("url", e.URL),
		slog.String("waf_name", e.WAFName),
	}
}

// ProbeCompleted is emitted when reachability probing completes for a target or batch.
type ProbeCompleted struct {
	Target           string
	TotalProbes      int
	SuccessfulProbes int
	FailedProbes     int
	Timeouts         int
	Degraded         bool
}

// ToolName returns the tool identifier.
func (ProbeCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeCompleted) EventName() string { return "httpprobe: probe completed" }

// EventLevel returns the log severity.
func (ProbeCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("target", e.Target),
		slog.Int("probed", e.TotalProbes),
		slog.Int("succeeded", e.SuccessfulProbes),
		slog.Int("failed", e.FailedProbes),
		slog.Int("timeouts", e.Timeouts),
		slog.Bool("degraded", e.Degraded),
	}
}
