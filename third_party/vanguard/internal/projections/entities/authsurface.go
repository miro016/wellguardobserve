package entities

import "time"

// AuthSurface records that an active web probe observed an authentication surface
// on a domain: where users or APIs authenticate and of what kind. It is built from
// the responses the probes already fetch (a WWW-Authenticate challenge, a 401/403,
// or a login form on the body) - no login attempts are made. It sharpens the
// dork-inferred auth signal into an observed one, so risk criticality and the
// credential-stuffing scenario key on a confirmed login surface, and downstream
// plan knows the scheme to target.
type AuthSurface struct {
	// Types are the observed auth kinds, sorted and deduped: "basic", "digest",
	// "bearer", "negotiate", "ntlm", "form" (a login form), or "protected" (a bare
	// 401/403 with no scheme advertised).
	Types []string
	// Locations are the URLs where an auth surface was observed, sorted.
	Locations []string
	// LiveVerifiedAt is when the most recent Vanguard probe observed an auth surface.
	LiveVerifiedAt time.Time
}
