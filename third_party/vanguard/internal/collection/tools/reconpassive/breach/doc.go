// Package breach queries the HaveIBeenPwned (HIBP) API v3 for breach data via the
// /breachedDomain/{domain} endpoint, which returns the email aliases on a domain
// that appear in known data breaches along with the breach names.
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Lookup], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome, including
// granular error events (network, rate limit, auth failure, upstream unavailable,
// HTTP status, JSON parsing) that carry operational context and response body snippets
// for debugging. [LookupCompleted] carries summary counters for queries, failures,
// and degradation state. Lookup returns a [Result] of [BreachedAlias] values,
// with an empty slice when the domain has no breached aliases (HTTP 404).
// The granular operational failures implement [tooleventlog.HealthEvent] because
// the attempted lookup lost evidence. Raw response snippets and errors remain only
// on the typed event; the health problem contains a stable code and target. A valid
// zero-breach result and [LookupCompleted] remain health-neutral.
//
// Usage requires a paid HIBP API key and prior domain verification on the HIBP
// dashboard (a 403 means the domain is not verified). The key is a secret, so the
// app injects it from the HIBP_API_KEY environment variable onto Config.APIKey
// rather than reading it from the audit configuration file; the tool stays inert
// when the key is absent.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into BreachDataDiscovered domain events.
package breach
