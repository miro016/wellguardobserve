package https

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// CertificateEvidence is the bounded result of one TLS handshake used to decide
// whether a provider-only address serves an in-scope name. DNSNames contains only
// the leaf certificate's DNS SANs; no HTTP request or TLS-version sweep is made.
type CertificateEvidence struct {
	// RemoteAddr is the socket that completed the handshake.
	RemoteAddr string
	// DNSNames are the leaf certificate's DNS subject alternative names.
	DNSNames []string
}

// Result holds aggregated HTTPS reconnaissance data for one domain.
type Result struct {
	RemoteAddr  string
	TLS         *TLSInfo
	TLSVersions []TLSVersionResult
	CertChain   []ChainCert
	// Reachable is true when at least one TLS handshake or HTTPS GET completed, so
	// the rest of the result reflects the live endpoint. It is false when every
	// dial failed (port closed, host unreachable, DNS miss): the caller must then
	// treat the all-unsupported versions and absent HSTS as "not probed", not as a
	// clean posture.
	Reachable       bool
	SecurityHeaders SecurityHeaders
	HSTS            *HSTSResult
	// HeadersComplete is true only when the security-header GET reached a final
	// response. False means absent headers were not inferred.
	HeadersComplete bool
	// ChainValidation is the verdict on the certificate chain the server actually
	// served, nil when no handshake completed and the chain was therefore never
	// judged. Nil must never be read as a trusted chain.
	ChainValidation *ChainValidation
	Error           string
	// RedirectTrail is the shared result contract for redirect decisions made by
	// the security-header HTTP GET. TLS handshake probes cannot redirect.
	RedirectTrail []scopecheck.RedirectObservation
}

// ChainValidation is the outcome of validating the certificate chain the server
// served, against the host's trust store and the probed name. Only the certificates
// the server itself sent are used to build the path, so a failure means the
// deployment is wrong (a missing intermediate, an untrusted issuer, a name the
// certificate does not cover) rather than that the prober lacked a certificate the
// server did send.
type ChainValidation struct {
	// Trusted reports whether a path to a trusted root was built and accepted.
	Trusted bool
	// Error is the concrete validation failure, empty when Trusted.
	Error string
}

// TLSInfo holds leaf certificate metadata from a live TLS handshake.
type TLSInfo struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	SANs      []string
	Serial    string
	SigAlgo   string
	KeyUsage  []string
	IsExpired bool
	DaysLeft  int
}

// TLSVersionResult reports support for one TLS version.
type TLSVersionResult struct {
	Version   string
	Supported bool
	Cipher    string
	Risk      string
	Error     string
}

// ChainCert holds one certificate from the peer chain.
type ChainCert struct {
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	SANs      []string
	Serial    string
	SigAlgo   string
	IsCA      bool
	Position  int
}

// SecurityHeaders holds common browser-facing HTTPS security headers.
type SecurityHeaders struct {
	CSP               string
	XFrameOptions     string
	XContentTypeOpts  string
	ReferrerPolicy    string
	PermissionsPolicy string
	COOP              string
	CORP              string
	COEP              string
	XXSSProtection    string
	MissingHeaders    []string
}

// HSTSResult holds parsed Strict-Transport-Security directives.
type HSTSResult struct {
	Raw               string
	MaxAge            int
	IncludeSubDomains bool
	Preload           bool
}
