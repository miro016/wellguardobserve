package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// TlsPosture aggregates the active TLS-negotiation posture of a single Domain:
// which TLS protocol versions the HTTPS endpoint still accepts and its HSTS
// policy. Like MailSecurity and BreachExposure it is a facet of the owning Domain
// rather than a standalone asset. It is gathered in the active phase (a live TLS
// handshake), distinct from the certificate itself, which is recorded as a
// Certificate asset.
type TlsPosture struct {
	// RemoteAddr is the endpoint the handshake reached.
	RemoteAddr string
	// Reachable is true when the HTTPS endpoint answered. When false the probe
	// never connected and the all-unsupported Versions and absent HSTS are a
	// coverage gap, not a clean posture; consumers must render it as "not reached".
	Reachable bool
	// Versions reports support and risk for each probed TLS version.
	Versions []valueobjects.TlsVersion
	// HSTS is the parsed Strict-Transport-Security policy.
	HSTS valueobjects.HstsPolicy
	// ChainState says whether the certificate chain the endpoint served was
	// validated. ChainTrusted and ChainError carry meaning only when it is tested:
	// a false ChainTrusted with any other state means nothing was judged, which
	// must not be rendered as an untrusted chain.
	ChainState AssessmentState
	// ChainTrusted reports whether a path from the served chain to a trusted root
	// was accepted for this name, and ChainError is the concrete failure otherwise.
	ChainTrusted bool
	ChainError   string
	// ResolvedAt is when the posture was last probed.
	ResolvedAt time.Time
}
