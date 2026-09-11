package toolerr

import (
	"errors"
	"strings"
)

// ErrProviderUnavailable signals that a paid provider declined to serve the whole
// scan, not just one domain: an auth refusal, a paid-plan or membership wall, or a
// daily request budget that is exhausted. A client wraps it (errors.Is-friendly)
// when it sees such a signal. The orchestrator trips a per-tool circuit breaker on
// it and skips the provider for the rest of the run, rather than repeating a
// guaranteed-failing call once per discovered domain. A plain per-domain error
// (a single bad lookup) must not be wrapped with it.
var ErrProviderUnavailable = errors.New("provider unavailable")

// unavailableMarkers are substrings that, in a provider's error text, mean the
// provider is unavailable for the rest of the scan rather than failing on this one
// request. They cover the shapes seen on free keys: Shodan "Requires membership or
// higher", Netlas "daily_request_limit_exceeded" / "Access denied" / "ip_banned",
// and the generic auth/quota walls.
var unavailableMarkers = []string{
	"requires membership", "membership", "subscription", "payment required",
	"paid plan", "unauthorized", "forbidden", "access denied", "ip_banned",
	"daily_request_limit", "request limit", "rate limit", "ratelimit", "quota",
}

// IsUnavailableMessage reports whether an error message indicates the provider is
// unavailable for the remainder of the scan. Clients use it to decide whether to
// wrap a returned error with ErrProviderUnavailable. Matching is case-insensitive.
func IsUnavailableMessage(msg string) bool {
	lower := strings.ToLower(msg)
	for _, m := range unavailableMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
