package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SourceFreshness declares how long one passive source's observation stays a defensible
// statement about current state. It is a policy, not a measurement: nothing about a
// provider's data says when its claim stops being true, so the window has to be declared
// and printed rather than assumed.
type SourceFreshness struct {
	// Source is the tool name as it appears on EventMeta.Source.
	Source string
	// Window is how long after the source's own observation time the claim still
	// counts as recent.
	Window time.Duration
}

// String renders one declaration in whole days, for printing next to any verdict the
// window produced.
func (f SourceFreshness) String() string {
	return fmt.Sprintf("%s %dd", f.Source, int(f.Window.Hours()/24))
}

// FreshnessPolicy holds the declared per-source windows plus the window applied to a
// passive source with no declaration of its own.
//
// It lives in its own package, deliberately not beside the events, because an event is an
// immutable record of what a source said and a freshness window is a tunable judgement
// about how long that saying stays useful. Changing a window must reclassify existing
// captures without rewriting a single event, and that only stays true while the two are
// separate.
//
// It is shared rather than duplicated because two independent consumers have to agree on
// it exactly: the finding temporal classification and the classified asset surface. If
// they each carried their own constant, a finding could read "current" while the asset it
// concerns read "historical_only", and neither number would be wrong on its own terms.
type FreshnessPolicy struct {
	windows   map[string]time.Duration
	fallback  time.Duration
	clockSkew time.Duration
}

// Default freshness windows, chosen from how often each source actually revisits a host.
// They are deliberately conservative: a window that is too long silently promotes stale
// intelligence to current, which is the failure this whole model exists to prevent.
const (
	// FreshnessCensys is short because Censys rescans the public IPv4 space often.
	FreshnessCensys = 7 * 24 * time.Hour
	// FreshnessShodan covers Shodan's slower full-space revisit cycle.
	FreshnessShodan = 30 * 24 * time.Hour
	// FreshnessNetlas matches Shodan's order of magnitude.
	FreshnessNetlas = 30 * 24 * time.Hour
	// FreshnessVirusTotal is long: its last-seen dates describe name resolution
	// history rather than a service sweep, and it revisits far less predictably.
	FreshnessVirusTotal = 90 * 24 * time.Hour
	// FreshnessDefault applies to a passive source with no declaration of its own.
	FreshnessDefault = 30 * 24 * time.Hour
	// DefaultClockSkewTolerance is the maximum harmless difference between a
	// source-supplied observation time and Vanguard's capture time. A larger future
	// difference is reported as a temporal anomaly rather than silently normalized.
	DefaultClockSkewTolerance = 5 * time.Minute
)

// DefaultFreshnessPolicy returns the declared windows Vanguard ships with.
func DefaultFreshnessPolicy() FreshnessPolicy {
	policy, err := NewFreshnessPolicy(map[string]time.Duration{
		"censys":     FreshnessCensys,
		"shodan":     FreshnessShodan,
		"netlas":     FreshnessNetlas,
		"virustotal": FreshnessVirusTotal,
	}, FreshnessDefault, DefaultClockSkewTolerance)
	if err != nil {
		panic("invalid built-in temporal analysis policy: " + err.Error())
	}
	return policy
}

// NewFreshnessPolicy builds a policy from explicit source windows, a fallback for other
// passive sources, and an allowed clock skew. It copies and normalizes the map so later
// caller mutation cannot change a report halfway through rendering.
func NewFreshnessPolicy(windows map[string]time.Duration, fallback, clockSkew time.Duration) (FreshnessPolicy, error) {
	if fallback <= 0 {
		return FreshnessPolicy{}, fmt.Errorf("fallback freshness window must be positive")
	}
	if clockSkew <= 0 {
		return FreshnessPolicy{}, fmt.Errorf("clock skew tolerance must be positive")
	}
	normalized := make(map[string]time.Duration, len(windows))
	for source, window := range windows {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" {
			return FreshnessPolicy{}, fmt.Errorf("freshness source must not be empty")
		}
		if window <= 0 {
			return FreshnessPolicy{}, fmt.Errorf("freshness window for %s must be positive", source)
		}
		normalized[source] = window
	}
	return FreshnessPolicy{windows: normalized, fallback: fallback, clockSkew: clockSkew}, nil
}

// ClockSkewTolerance returns the allowed future offset for source timestamps. A zero
// policy uses [DefaultClockSkewTolerance], matching Window's safe zero-value behavior.
func (p FreshnessPolicy) ClockSkewTolerance() time.Duration {
	if p.clockSkew > 0 {
		return p.clockSkew
	}
	return DefaultClockSkewTolerance
}

// Window returns the declared window for a source, or the fallback when the source has
// no declaration. A zero policy answers with the default window rather than zero, so a
// caller that forgot to build one cannot accidentally mark every claim stale.
func (p FreshnessPolicy) Window(source string) time.Duration {
	if w, ok := p.windows[strings.ToLower(strings.TrimSpace(source))]; ok {
		return w
	}
	if p.fallback > 0 {
		return p.fallback
	}
	return FreshnessDefault
}

// IsFresh reports whether an observation from source, made at observedAt, is still
// within its declared window at asOf.
//
// An undated observation is never fresh. That is the conservative half of the rule: a
// source that supplied no time has said nothing about currency, and treating silence as
// recency is exactly how stale intelligence gets promoted to current.
func (p FreshnessPolicy) IsFresh(source string, observedAt, asOf time.Time) bool {
	if observedAt.IsZero() || asOf.IsZero() {
		return false
	}
	return !observedAt.Before(asOf.Add(-p.Window(source)))
}

// Declared returns every declared window in sorted order, so a report can print the
// thresholds that produced its verdicts instead of asking the reader to trust them.
func (p FreshnessPolicy) Declared() []SourceFreshness {
	out := make([]SourceFreshness, 0, len(p.windows))
	for src, w := range p.windows {
		out = append(out, SourceFreshness{Source: src, Window: w})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// String renders the whole policy on one line for the reports.
func (p FreshnessPolicy) String() string {
	parts := make([]string, 0, len(p.windows)+1)
	for _, f := range p.Declared() {
		parts = append(parts, f.String())
	}
	fallback := p.fallback
	if fallback == 0 {
		fallback = FreshnessDefault
	}
	parts = append(parts, fmt.Sprintf("other passive sources %dd", int(fallback.Hours()/24)))
	return strings.Join(parts, ", ")
}
