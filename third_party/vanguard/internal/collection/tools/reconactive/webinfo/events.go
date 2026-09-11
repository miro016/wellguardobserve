package webinfo

import "log/slog"

const toolName = "webinfo"

// ProbeStarted is emitted when a web-info probe begins for a domain.
type ProbeStarted struct {
	Domain    string
	UrlsCount int
}

// ToolName returns the tool identifier.
func (ProbeStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeStarted) EventName() string { return "webinfo: probe started" }

// EventLevel returns the log severity.
func (ProbeStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("urls_count", e.UrlsCount),
	}
}

// ProbeCompleted is emitted when a web-info probe finishes, summarising the HTTP
// outcome and detected stack.
type ProbeCompleted struct {
	Domain            string
	FinalURL          string
	StatusCode        int
	CMS               string
	Technologies      int
	TotalUrls         int
	SuccessfulFetches int
	FailedFetches     int
	Timeouts          int
	// PolicyRejections counts requests stopped before network traffic and is not a
	// timeout or server failure.
	PolicyRejections int
	Degraded         bool
}

// ToolName returns the tool identifier.
func (ProbeCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeCompleted) EventName() string { return "webinfo: probe completed" }

// EventLevel returns the log severity.
func (ProbeCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("final_url", e.FinalURL),
		slog.Int("status", e.StatusCode),
		slog.String("cms", e.CMS),
		slog.Int("technologies", e.Technologies),
		slog.Int("total_urls", e.TotalUrls),
		slog.Int("successful_fetches", e.SuccessfulFetches),
		slog.Int("failed_fetches", e.FailedFetches),
		slog.Int("timeouts", e.Timeouts),
		slog.Int("policy_rejections", e.PolicyRejections),
		slog.Bool("degraded", e.Degraded),
	}
}

// PageFetchFailed is emitted when the page GET (used for stack detection) failed.
// The HTTP probe result is still returned, but no stack is detected.
type PageFetchFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (PageFetchFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PageFetchFailed) EventName() string { return "webinfo: page fetch failed" }

// EventLevel returns the log severity.
func (PageFetchFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PageFetchFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.Any("error", e.Err)}
}

// ProbeFailed is emitted when the HTTP probe could not reach the domain over
// either HTTPS or HTTP. It is fatal to the probe but non-fatal to the scan.
type ProbeFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (ProbeFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProbeFailed) EventName() string { return "webinfo: probe failed" }

// EventLevel returns the log severity.
func (ProbeFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProbeFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.Any("error", e.Err)}
}

// TechnologyDiscovered is emitted when a web framework, CMS, library, or server is detected.
type TechnologyDiscovered struct {
	URL      string
	TechName string
	Category string
	Version  string
}

// ToolName returns the tool identifier.
func (TechnologyDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TechnologyDiscovered) EventName() string { return "webinfo: technology discovered" }

// EventLevel returns the log severity.
func (TechnologyDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TechnologyDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("url", e.URL),
		slog.String("tech_name", e.TechName),
		slog.String("category", e.Category),
		slog.String("version", e.Version),
	}
}

// RateLimited is emitted when the target server returns an HTTP 429 status code.
type RateLimited struct {
	URL        string
	StatusCode int
}

// ToolName returns the tool identifier.
func (RateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RateLimited) EventName() string { return "webinfo: rate limited" }

// EventLevel returns the log severity.
func (RateLimited) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("url", e.URL),
		slog.Int("status_code", e.StatusCode),
	}
}

// WAFBlocked is emitted when a WAF challenge or firewall block page is detected.
type WAFBlocked struct {
	URL        string
	StatusCode int
	WAFName    string
}

// ToolName returns the tool identifier.
func (WAFBlocked) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (WAFBlocked) EventName() string { return "webinfo: waf blocked" }

// EventLevel returns the log severity.
func (WAFBlocked) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e WAFBlocked) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("url", e.URL),
		slog.Int("status_code", e.StatusCode),
		slog.String("waf_name", e.WAFName),
	}
}

// RedirectLoopDetected is emitted when an HTTP redirect chain exceeds the maximum hop threshold.
type RedirectLoopDetected struct {
	URL       string
	HopsCount int
}

// RedirectFollowed is emitted after a redirect destination passes request policy.
type RedirectFollowed struct {
	FromURL string
	ToURL   string
	Status  int
	Hop     int
}

// ToolName returns the tool identifier.
func (RedirectFollowed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectFollowed) EventName() string { return "webinfo: redirect followed" }

// EventLevel returns the log severity.
func (RedirectFollowed) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured redirect fields.
func (e RedirectFollowed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("from_url", e.FromURL), slog.String("to_url", e.ToURL),
		slog.Int("status", e.Status), slog.Int("hop", e.Hop),
	}
}

// RedirectRejected is emitted when request policy denies a redirect destination.
type RedirectRejected struct {
	FromURL string
	ToURL   string
	Status  int
	Hop     int
	Reason  string
}

// ToolName returns the tool identifier.
func (RedirectRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectRejected) EventName() string { return "webinfo: redirect rejected" }

// EventLevel returns the log severity.
func (RedirectRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured redirect fields and policy reason.
func (e RedirectRejected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("from_url", e.FromURL), slog.String("to_url", e.ToURL),
		slog.Int("status", e.Status), slog.Int("hop", e.Hop), slog.String("reason", e.Reason),
	}
}

// ToolName returns the tool identifier.
func (RedirectLoopDetected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (RedirectLoopDetected) EventName() string { return "webinfo: redirect loop detected" }

// EventLevel returns the log severity.
func (RedirectLoopDetected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e RedirectLoopDetected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("url", e.URL),
		slog.Int("hops_count", e.HopsCount),
	}
}

// HTMLParseError is emitted when the DOM parser fails to tokenize malformed HTML response bodies.
type HTMLParseError struct {
	URL     string
	Snippet string
	Err     error
}

// ToolName returns the tool identifier.
func (HTMLParseError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (HTMLParseError) EventName() string { return "webinfo: html parse error" }

// EventLevel returns the log severity.
func (HTMLParseError) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HTMLParseError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("url", e.URL),
		slog.String("snippet", e.Snippet),
		slog.Any("error", e.Err),
	}
}
