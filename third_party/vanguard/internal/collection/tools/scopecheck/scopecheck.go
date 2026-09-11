package scopecheck

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Allow decides whether normalizedHost may receive a target-facing request.
// Reason is empty for an allowed request and explains a rejection otherwise.
type Allow func(ctx context.Context, normalizedHost string) (allowed bool, reason string)

// Rejection is one hard-exclusion decision made at a target-facing boundary.
// Host is the requested identity. ResolvedIP is populated when the decision was
// made for one DNS answer, including a literal address target. Reason carries the
// canonical matched rule.
type Rejection struct {
	Host       string
	ResolvedIP string
	Reason     string
}

// RejectionSink observes hard-exclusion decisions without changing whether a
// request is allowed. Orchestration uses it to project tool-owned dial decisions
// into the domain audit stream.
type RejectionSink func(Rejection)

type rejectionSinkContextKey struct{}

// WithRejectionSink returns a child context that reports hard-exclusion decisions
// to sink. An existing sink is preserved and called before the new sink, so nested
// tool and phase observers compose. A nil sink is a no-op.
func WithRejectionSink(ctx context.Context, sink RejectionSink) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if sink == nil {
		return ctx
	}
	if previous, ok := ctx.Value(rejectionSinkContextKey{}).(RejectionSink); ok && previous != nil {
		current := sink
		sink = func(rejection Rejection) {
			previous(rejection)
			current(rejection)
		}
	}
	return context.WithValue(ctx, rejectionSinkContextKey{}, sink)
}

// ReportRejection notifies the sink carried by ctx, when present. Tool packages
// call it at the same point they refuse a destination, before target traffic.
func ReportRejection(ctx context.Context, rejection Rejection) {
	if ctx == nil {
		return
	}
	if sink, ok := ctx.Value(rejectionSinkContextKey{}).(RejectionSink); ok && sink != nil {
		sink(rejection)
	}
}

// RedirectDisposition records whether a redirect destination was contacted.
type RedirectDisposition string

const (
	// DispositionFollowed means the redirect destination passed policy and was contacted.
	DispositionFollowed RedirectDisposition = "followed"
	// DispositionRejected means policy rejected the destination before network traffic.
	DispositionRejected RedirectDisposition = "rejected"
)

// RedirectObservation is the immutable result vocabulary for one redirect hop.
type RedirectObservation struct {
	// FromURL is the URL whose response produced the redirect.
	FromURL string
	// ToURL is the redirect destination resolved against FromURL.
	ToURL string
	// Status is the HTTP redirect response status.
	Status int
	// Hop is the one-based position in the redirect chain.
	Hop int
	// Disposition reports whether the destination was followed or rejected.
	Disposition RedirectDisposition
	// Reason explains a rejected disposition and is empty for a followed hop.
	Reason string
}

// Origin identifies the scheduler-approved target from which a request was derived.
type Origin struct {
	// Host is a normalized DNS name or canonical IP literal.
	Host string
	// Depth is the host's discovery depth. A negative value means unavailable.
	Depth int
}

type originContextKey struct{}

// WithOrigin returns a child context carrying a normalized request origin.
func WithOrigin(ctx context.Context, host string, depth int) (context.Context, error) {
	normalized, err := NormalizeHost(host)
	if err != nil {
		return nil, fmt.Errorf("normalize request origin: %w", err)
	}
	return context.WithValue(ctx, originContextKey{}, Origin{Host: normalized, Depth: depth}), nil
}

// OriginFrom returns the request origin carried by ctx, when one is present.
func OriginFrom(ctx context.Context) (Origin, bool) {
	if ctx == nil {
		return Origin{}, false
	}
	origin, ok := ctx.Value(originContextKey{}).(Origin)
	return origin, ok && origin.Host != ""
}

// NormalizeURL parses rawURL and returns its normalized HTTP request host.
func NormalizeURL(rawURL string) (string, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse request URL: %w", err)
	}
	return NormalizeURLHost(target)
}

// NormalizeURLHost returns target's normalized host after validating that it is an
// absolute HTTP or HTTPS URL.
func NormalizeURLHost(target *url.URL) (string, error) {
	if target == nil {
		return "", fmt.Errorf("request URL is nil")
	}
	if !strings.EqualFold(target.Scheme, "http") && !strings.EqualFold(target.Scheme, "https") {
		return "", fmt.Errorf("request URL scheme %q is not HTTP or HTTPS", target.Scheme)
	}
	if target.Host == "" || target.Hostname() == "" {
		return "", fmt.Errorf("request URL has no host")
	}
	// Reparse the rendered URL so manually assembled URL values receive the same
	// malformed-port and escape validation as values parsed from input.
	parsed, err := url.Parse(target.String())
	if err != nil {
		return "", fmt.Errorf("parse request URL: %w", err)
	}
	return normalizeNameOrIP(parsed.Hostname())
}

// NormalizeHost strips an optional port and canonicalizes a DNS name or IP literal.
func NormalizeHost(host string) (string, error) {
	raw := strings.TrimSpace(host)
	if raw == "" {
		return "", fmt.Errorf("request host is empty")
	}
	if ip, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return ip.Unmap().String(), nil
	}
	if strings.Contains(raw, "://") {
		return "", fmt.Errorf("request host %q contains a URL scheme", host)
	}
	parsed, err := url.Parse("http://" + raw)
	if err != nil {
		return "", fmt.Errorf("parse request host %q: %w", host, err)
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("request host %q is malformed", host)
	}
	return normalizeNameOrIP(parsed.Hostname())
}

func normalizeNameOrIP(host string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if name == "" {
		return "", fmt.Errorf("request host is empty")
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Unmap().String(), nil
	}
	if strings.Contains(name, ":") || strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("request host %q is malformed", host)
	}
	for _, r := range name {
		if r <= ' ' || r == '/' || r == '\\' || r == '@' || r == '[' || r == ']' {
			return "", fmt.Errorf("request host %q is malformed", host)
		}
	}
	return name, nil
}

// RejectedError reports a request destination rejected by the injected policy.
type RejectedError struct {
	// Host is the normalized destination host.
	Host string
	// Reason is the unchanged policy explanation.
	Reason string
	// ResolvedIPs are the excluded addresses that caused the rejection, when the
	// decision was made on resolved answers rather than on the name itself. A name
	// denied because every one of its answers is excluded carries them all here, so
	// a caller's typed rejection event can name the destinations the policy actually
	// denied instead of only the host it was probing. Empty when the name itself was
	// barred, or when the destination was a literal address (already in Host).
	ResolvedIPs []string
}

// Error implements error.
func (e *RejectedError) Error() string {
	return fmt.Sprintf("request to %s rejected: %s", e.Host, e.Reason)
}

// Check validates target and asks allow for permission before network traffic.
// A nil allow callback permits a valid target so standalone tools retain their
// existing behavior.
func Check(ctx context.Context, allow Allow, target *url.URL) error {
	host, err := NormalizeURLHost(target)
	if err != nil {
		return err
	}
	if allow == nil {
		return nil
	}
	allowed, reason := allow(ctx, host)
	if allowed {
		return nil
	}
	return &RejectedError{Host: host, Reason: reason}
}
