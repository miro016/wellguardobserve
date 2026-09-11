package subfinder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// providerConfigFile is the filename subfinder expects for a provider-config.
const providerConfigFile = "provider-config.yaml"

// keyedSourceEnvVars names the environment variable Vanguard reads for each keyed
// source the client diagnoses. It is used only to tell an operator where a
// genuinely absent key belongs; it never holds key material.
var keyedSourceEnvVars = map[string]string{
	"virustotal": "VIRUSTOTAL_API_KEY",
}

// ProviderDisposition is the closed set of policy outcomes for a keyed subfinder
// source. It lets the client separate a deliberate orchestration decision from a
// genuinely absent credential, so policy is never reported as a configuration
// fault.
type ProviderDisposition string

const (
	// DispositionConfigured means Vanguard supplied this source's key to subfinder.
	DispositionConfigured ProviderDisposition = "configured"
	// DispositionHandledElsewhere means Vanguard holds a usable key but a dedicated
	// Vanguard tool owns that capability, so the key is deliberately withheld from
	// subfinder to avoid a duplicate paid or quota-consuming query.
	DispositionHandledElsewhere ProviderDisposition = "handled_elsewhere"
	// DispositionDisabled means the source policy does not request this keyed source.
	DispositionDisabled ProviderDisposition = "disabled"
	// DispositionMissing means the source policy requests this keyed source but no
	// usable key exists.
	DispositionMissing ProviderDisposition = "missing"
)

// ProviderStatus records the policy decision Vanguard made for one keyed subfinder
// source. It carries provider identity and disposition only: key material stays in
// Config.ProviderKeys and is never copied here, serialized, or logged.
type ProviderStatus struct {
	// Provider is the subfinder source name (e.g. "virustotal").
	Provider string
	// Disposition explains why the source did or did not receive a key.
	Disposition ProviderDisposition
	// Owner names the Vanguard tool that owns the capability instead. Required for
	// DispositionHandledElsewhere and empty for every other disposition.
	Owner string
}

// Config holds configuration for the Client.
type Config struct {
	// Threads controls how many sources subfinder queries concurrently.
	Threads int
	// Timeout is the per-source response timeout.
	Timeout time.Duration
	// MaxEnumerationTime caps the total enumeration time.
	MaxEnumerationTime time.Duration
	// All enables every passive source (including slower ones) rather than the
	// default fast set.
	All bool
	// ProviderKeys maps a subfinder source name (e.g. "virustotal") to its API
	// key(s). Enumerate writes these to a throwaway provider-config and points
	// subfinder at it, so subfinder is driven entirely from Vanguard's config and
	// never reads ambient host state (~/.config/subfinder/provider-config.yaml).
	// Behaviour is then identical on a developer machine and a fresh server. The
	// values are secrets and must never be logged. May be nil/empty, in which case
	// subfinder runs with keyless sources only (still not the host's config).
	ProviderKeys map[string][]string
	// Providers declares the disposition of each keyed source the caller made a
	// policy decision about, so the client reports a deliberately withheld key as
	// policy rather than as a missing credential. It must agree with ProviderKeys:
	// a source is DispositionConfigured exactly when a key is supplied for it. May
	// be nil, in which case the client derives dispositions from All and
	// ProviderKeys (a supplied key is configured; an absent one is missing when All
	// requests every source, and disabled otherwise).
	Providers []ProviderStatus
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client performs passive subdomain enumeration via the projectdiscovery
// subfinder library, which aggregates many third-party passive DNS sources.
type Client struct {
	cfg Config
	// providers is the validated provider disposition set, sorted by provider name,
	// derived once at construction so Enumerate reports a stable order.
	providers []ProviderStatus
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Threads <= 0 {
		return nil, fmt.Errorf("subfinder: Config.Threads must be positive")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("subfinder: Config.Timeout must be positive")
	}
	if cfg.MaxEnumerationTime <= 0 {
		return nil, fmt.Errorf("subfinder: Config.MaxEnumerationTime must be positive")
	}
	providers, err := effectiveProviders(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, providers: providers}, nil
}

// effectiveProviders validates the declared provider dispositions against the
// supplied keys and returns them sorted by provider name. A caller that declares
// nothing gets the derived default, so a standalone client still reports a
// genuinely absent key.
func effectiveProviders(cfg Config) ([]ProviderStatus, error) {
	if len(cfg.Providers) == 0 {
		return defaultProviders(cfg.All, cfg.ProviderKeys), nil
	}
	out := slices.Clone(cfg.Providers)
	seen := make(map[string]bool, len(out))
	for _, p := range out {
		if p.Provider == "" {
			return nil, fmt.Errorf("subfinder: Config.Providers has an entry with no provider name")
		}
		if seen[p.Provider] {
			return nil, fmt.Errorf("subfinder: Config.Providers repeats provider %q", p.Provider)
		}
		seen[p.Provider] = true

		hasKey := hasProviderKey(cfg.ProviderKeys, p.Provider)
		switch p.Disposition {
		case DispositionConfigured:
			if !hasKey {
				return nil, fmt.Errorf("subfinder: provider %q is configured but Config.ProviderKeys holds no key for it", p.Provider)
			}
		case DispositionHandledElsewhere, DispositionDisabled, DispositionMissing:
			if hasKey {
				return nil, fmt.Errorf("subfinder: provider %q is %s but Config.ProviderKeys supplies a key for it", p.Provider, p.Disposition)
			}
		default:
			return nil, fmt.Errorf("subfinder: provider %q has unknown disposition %q", p.Provider, p.Disposition)
		}

		if (p.Owner != "") != (p.Disposition == DispositionHandledElsewhere) {
			return nil, fmt.Errorf("subfinder: provider %q must name an owning tool exactly when it is handled elsewhere", p.Provider)
		}
	}
	for name := range cfg.ProviderKeys {
		if hasProviderKey(cfg.ProviderKeys, name) && !seen[name] {
			return nil, fmt.Errorf("subfinder: provider %q has a key but no declared disposition", name)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

// defaultProviders derives dispositions when the caller declared none: a supplied
// key is configured, and a keyed source the client knows about is missing when all
// sources are requested and disabled otherwise.
func defaultProviders(all bool, keys map[string][]string) []ProviderStatus {
	names := make(map[string]bool, len(keys)+len(keyedSourceEnvVars))
	for name := range keyedSourceEnvVars {
		names[name] = true
	}
	for name := range keys {
		names[name] = true
	}
	out := make([]ProviderStatus, 0, len(names))
	for name := range names {
		p := ProviderStatus{Provider: name, Disposition: DispositionMissing}
		switch {
		case hasProviderKey(keys, name):
			p.Disposition = DispositionConfigured
		case !all:
			p.Disposition = DispositionDisabled
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// Result is a single discovered subdomain together with the subfinder sources
// (for example "crtsh", "virustotal", "shodan") that reported it. The source
// list supports tool coverage and efficiency comparison across data providers.
type Result struct {
	Subdomain string
	Sources   []string
}

// Enumerate runs passive subdomain enumeration for domain and returns the
// discovered subdomains, each with the sources that reported it. The result is
// sorted by subdomain for deterministic output.
func (c *Client) Enumerate(ctx context.Context, domain string) ([]Result, error) {
	c.emit(ctx, EnumerationStarted{Domain: domain})
	c.emitProviderDispositions(ctx, domain)

	opts := &runner.Options{
		Threads:            c.cfg.Threads,
		Timeout:            int(c.cfg.Timeout.Seconds()),
		MaxEnumerationTime: int(c.cfg.MaxEnumerationTime.Minutes()),
		Silent:             true,
		All:                c.cfg.All,
	}

	// Vanguard is the single source of truth for subfinder's provider keys: write
	// them to a throwaway provider-config and point subfinder at it. subfinder
	// prefers an existing Options.ProviderConfig over its default location, so this
	// stops it reading the ambient ~/.config/subfinder/provider-config.yaml and
	// makes a run behave identically on a dev box and a fresh server. The directory
	// holds a live secret, so it is removed as soon as the run ends.
	dir, err := writeProviderConfig(c.cfg.ProviderKeys)
	if err != nil {
		c.emitProviderCompletion(ctx, domain, nil, 0, err)
		return nil, fmt.Errorf("subfinder: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	opts.ProviderConfig = filepath.Join(dir, providerConfigFile)
	c.emit(ctx, ProvidersConfigured{Domain: domain, Sources: sourceNames(c.cfg.ProviderKeys)})

	r, err := runner.NewRunner(opts)
	if err != nil {
		c.emitProviderCompletion(ctx, domain, nil, 0, err)
		return nil, fmt.Errorf("subfinder: failed to create runner: %w", err)
	}

	sourceMap, err := r.EnumerateSingleDomainWithCtx(ctx, domain, nil)
	if err != nil {
		c.emitProviderCompletion(ctx, domain, r.GetStatistics(), 0, err)
		return nil, fmt.Errorf("subfinder: failed to enumerate %s: %w", domain, err)
	}

	results := make([]Result, 0, len(sourceMap))
	for sub, sourceSet := range sourceMap {
		sources := make([]string, 0, len(sourceSet))
		for s := range sourceSet {
			sources = append(sources, s)
		}
		sort.Strings(sources)
		results = append(results, Result{Subdomain: sub, Sources: sources})
		c.emit(ctx, SubdomainFound{Domain: domain, Subdomain: sub, Sources: sources})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Subdomain < results[j].Subdomain })

	c.emitProviderCompletion(ctx, domain, r.GetStatistics(), len(results), nil)
	return results, nil
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

// emitProviderDispositions reports, in provider order, the keyed sources whose
// disposition an operator needs to see: a genuinely absent key warns, and a key
// withheld because a dedicated Vanguard tool owns the capability is stated as
// policy. Configured and disabled sources need no separate event because
// ProvidersConfigured already names everything that received a key.
func (c *Client) emitProviderDispositions(ctx context.Context, domain string) {
	for _, p := range c.providers {
		switch p.Disposition {
		case DispositionMissing:
			c.emit(ctx, ProviderKeyMissing{Domain: domain, Provider: p.Provider, EnvVar: keyedSourceEnvVars[p.Provider]})
		case DispositionHandledElsewhere:
			c.emit(ctx, ProviderHandledElsewhere{Domain: domain, Provider: p.Provider, Owner: p.Owner})
		case DispositionConfigured, DispositionDisabled:
			// Nothing to report: ProvidersConfigured names every keyed source, and a
			// source the policy never asked for is not news.
		}
	}
}

func hasProviderKey(keys map[string][]string, provider string) bool {
	for _, key := range keys[provider] {
		if strings.TrimSpace(key) != "" {
			return true
		}
	}
	return false
}

func (c *Client) emitProviderCompletion(ctx context.Context, domain string, stats map[string]subscraping.Statistics, totalSubdomains int, enumErr error) {
	providers := make([]string, 0, len(stats))
	for provider := range stats {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	var successfulProviders, failedProviders, skippedProviders int
	for _, provider := range providers {
		s := stats[provider]
		if s.Skipped {
			skippedProviders++
			continue
		}
		if s.Errors > 0 {
			failedProviders++
			c.emit(ctx, classifyProviderError(domain, provider, fmt.Errorf("subfinder provider %q reported %d error(s)", provider, s.Errors)))
			continue
		}
		successfulProviders++
	}

	attemptedProviders := successfulProviders + failedProviders
	if failedProviders == 0 && (enumErr != nil || attemptedProviders == 0) {
		if enumErr == nil {
			enumErr = fmt.Errorf("subfinder: no provider ran")
		}
		c.emit(ctx, EnumerationFailed{Domain: domain, Err: enumErr})
	}
	degraded := enumErr != nil || failedProviders > 0 || attemptedProviders == 0
	c.emit(ctx, EnumerationCompleted{
		Domain:              domain,
		Subdomains:          totalSubdomains,
		TotalProviders:      len(providers),
		SuccessfulProviders: successfulProviders,
		FailedProviders:     failedProviders,
		SkippedProviders:    skippedProviders,
		Degraded:            degraded,
	})
}

func classifyProviderError(domain, provider string, err error) tooleventlog.Event {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "429") || strings.Contains(msg, "rate limit") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "quota") {
		return ProviderRateLimited{Domain: domain, Provider: provider, Err: err}
	}
	if strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "invalid api key") || strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "paid plan") {
		status := 401
		if strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "paid plan") {
			status = 403
		}
		return ProviderAuthFailed{Domain: domain, Provider: provider, StatusCode: status}
	}
	return ProviderFailed{Domain: domain, Provider: provider, Err: err}
}

// writeProviderConfig writes keys to a throwaway subfinder provider-config in a
// fresh temp directory and returns that directory for the caller to remove after
// the run. The file uses subfinder's own format: a YAML map of source name to a
// list of API keys. keys may be nil/empty, which writes an empty config so
// subfinder runs with keyless sources only rather than falling back to host
// state. The file holds live secrets (mode 0600) and must never be logged.
func writeProviderConfig(keys map[string][]string) (string, error) {
	dir, err := os.MkdirTemp("", "vanguard-subfinder-")
	if err != nil {
		return "", fmt.Errorf("create provider-config dir: %w", err)
	}
	if keys == nil {
		keys = map[string][]string{}
	}
	// subfinder decodes the provider-config as YAML; JSON is valid YAML, so encode
	// with the standard library and avoid taking a YAML dependency in this tool.
	b, err := json.Marshal(keys)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("marshal provider-config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, providerConfigFile), b, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("write provider-config: %w", err)
	}
	return dir, nil
}

// sourceNames returns the configured source names (keys omitted), sorted, so the
// set of active keyed sources can be logged without ever exposing a secret.
func sourceNames(keys map[string][]string) []string {
	names := make([]string, 0, len(keys))
	for s := range keys {
		names = append(names, s)
	}
	sort.Strings(names)
	return names
}
