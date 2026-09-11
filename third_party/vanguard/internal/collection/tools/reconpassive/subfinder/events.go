package subfinder

import (
	"log/slog"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "subfinder"

// EnumerationStarted is emitted when passive enumeration begins for a domain.
type EnumerationStarted struct {
	Domain string
}

// ToolName returns the tool identifier.
func (EnumerationStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (EnumerationStarted) EventName() string { return "subfinder: enumeration started" }

// EventLevel returns the log severity.
func (EnumerationStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e EnumerationStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain)}
}

// ProvidersConfigured is emitted once per enumeration to record which keyed
// subfinder sources Vanguard supplied through its generated provider-config.
type ProvidersConfigured struct {
	Domain  string
	Sources []string
}

// ToolName returns the tool identifier.
func (ProvidersConfigured) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProvidersConfigured) EventName() string { return "subfinder: providers configured" }

// EventLevel returns the log severity.
func (ProvidersConfigured) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProvidersConfigured) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("providers_count", len(e.Sources)),
		slog.String("names", strings.Join(e.Sources, ", ")),
	}
}

// ProviderKeyMissing is emitted for a keyed source whose disposition is
// [DispositionMissing]: the source policy asks for it and no usable key exists.
// The scan continues with keyless sources; the warning makes the downgrade visible
// in tool logs. A key deliberately withheld because a dedicated Vanguard tool owns
// the capability is [ProviderHandledElsewhere], not this event.
type ProviderKeyMissing struct {
	Domain   string
	Provider string
	EnvVar   string
}

// ToolName returns the tool identifier.
func (ProviderKeyMissing) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProviderKeyMissing) EventName() string { return "subfinder: provider key missing" }

// EventLevel returns the log severity.
func (ProviderKeyMissing) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProviderKeyMissing) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("provider", e.Provider),
		slog.String("env_var", e.EnvVar),
	}
}

// ProviderHandledElsewhere is emitted for a keyed source whose disposition is
// [DispositionHandledElsewhere]: Vanguard holds a usable key but a dedicated
// Vanguard tool owns that capability, so the key is withheld from subfinder to
// keep one query path instead of two. It is informational and health-neutral: no
// collection work was attempted or lost, and the named owner performs the query.
type ProviderHandledElsewhere struct {
	Domain   string
	Provider string
	// Owner is the Vanguard tool that queries this provider instead.
	Owner string
}

// ToolName returns the tool identifier.
func (ProviderHandledElsewhere) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProviderHandledElsewhere) EventName() string { return "subfinder: provider handled elsewhere" }

// EventLevel returns the log severity.
func (ProviderHandledElsewhere) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProviderHandledElsewhere) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("provider", e.Provider),
		slog.String("owner", e.Owner),
	}
}

// SubdomainFound is emitted for each discovered subdomain, carrying the subfinder
// sources that reported it so tool coverage can be compared across providers.
type SubdomainFound struct {
	Domain    string
	Subdomain string
	Sources   []string
}

// ToolName returns the tool identifier.
func (SubdomainFound) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (SubdomainFound) EventName() string { return "subfinder: subdomain found" }

// EventLevel returns the log severity.
func (SubdomainFound) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SubdomainFound) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("subdomain", e.Subdomain),
		slog.String("sources", strings.Join(e.Sources, ", ")),
	}
}

// ProviderRateLimited is emitted when an individual OSINT provider hits rate limits (HTTP 429).
type ProviderRateLimited struct {
	Domain   string
	Provider string
	Err      error
}

// ToolName returns the tool identifier.
func (ProviderRateLimited) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProviderRateLimited) EventName() string { return "subfinder: provider rate limited" }

// EventLevel returns the log severity.
func (ProviderRateLimited) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProviderRateLimited) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("provider", e.Provider),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a provider query lost to rate limiting.
func (e ProviderRateLimited) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "subfinder.provider_rate_limited", Component: e.Provider, Target: e.Domain,
	}, true
}

// ProviderAuthFailed is emitted when an individual OSINT provider rejects an API key or requires a paid tier.
type ProviderAuthFailed struct {
	Domain     string
	Provider   string
	StatusCode int
}

// ToolName returns the tool identifier.
func (ProviderAuthFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProviderAuthFailed) EventName() string { return "subfinder: provider auth failed" }

// EventLevel returns the log severity.
func (ProviderAuthFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProviderAuthFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("provider", e.Provider),
		slog.Int("status_code", e.StatusCode),
	}
}

// CollectionHealth reports a provider query rejected by authentication or tier policy.
func (e ProviderAuthFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "subfinder.provider_auth_failed", Component: e.Provider, Target: e.Domain,
	}, true
}

// ProviderPaidPlanRequired is an alias for ProviderAuthFailed to satisfy naming variations.
type ProviderPaidPlanRequired = ProviderAuthFailed

// ProviderFailed is emitted when an individual OSINT provider fails due to network or timeout errors.
type ProviderFailed struct {
	Domain   string
	Provider string
	Err      error
}

// ToolName returns the tool identifier.
func (ProviderFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ProviderFailed) EventName() string { return "subfinder: provider failed" }

// EventLevel returns the log severity.
func (ProviderFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ProviderFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.String("provider", e.Provider),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a failed provider query.
func (e ProviderFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: "subfinder.provider_failed", Component: e.Provider, Target: e.Domain,
	}, true
}

// EnumerationFailed is emitted when enumeration fails above the provider level
// or when subfinder reports that no provider actually ran. It is not emitted when
// granular provider failure events already explain the incomplete enumeration.
type EnumerationFailed struct {
	Domain string
	Err    error
}

// ToolName returns the tool identifier.
func (EnumerationFailed) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (EnumerationFailed) EventName() string { return "subfinder: enumeration failed" }

// EventLevel returns the log severity.
func (EnumerationFailed) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e EnumerationFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("domain", e.Domain), slog.Any("error", e.Err)}
}

// CollectionHealth reports an enumeration failure without provider-level attribution.
func (e EnumerationFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "subfinder.enumeration_failed", Target: e.Domain}, true
}

// EnumerationCompleted is emitted when enumeration finishes or terminates, summarising provider execution metrics.
type EnumerationCompleted struct {
	Domain              string
	Subdomains          int
	TotalProviders      int
	SuccessfulProviders int
	FailedProviders     int
	SkippedProviders    int
	Degraded            bool
}

// ToolName returns the tool identifier.
func (EnumerationCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (EnumerationCompleted) EventName() string { return "subfinder: enumeration completed" }

// EventLevel returns the log severity.
func (EnumerationCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e EnumerationCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("domain", e.Domain),
		slog.Int("subdomains", e.Subdomains),
		slog.Int("providers", e.TotalProviders),
		slog.Int("successful", e.SuccessfulProviders),
		slog.Int("failed", e.FailedProviders),
		slog.Int("skipped", e.SkippedProviders),
		slog.Bool("degraded", e.Degraded),
	}
}

var (
	_ tooleventlog.HealthEvent = ProviderRateLimited{}
	_ tooleventlog.HealthEvent = ProviderAuthFailed{}
	_ tooleventlog.HealthEvent = ProviderFailed{}
	_ tooleventlog.HealthEvent = EnumerationFailed{}
)
