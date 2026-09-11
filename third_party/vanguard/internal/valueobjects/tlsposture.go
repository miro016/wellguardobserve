package valueobjects

// TlsVersion reports support for one TLS protocol version observed during an
// active HTTPS probe.
type TlsVersion struct {
	// Version is the protocol name (for example "TLS 1.0".."TLS 1.3").
	Version string
	// Supported is true when the endpoint completed a handshake at this version.
	Supported bool
	// Cipher is the negotiated cipher suite, when supported.
	Cipher string
	// Risk flags weak protocol versions: "critical" (TLS 1.0), "warning" (TLS 1.1),
	// or "" otherwise.
	Risk string
}

// HstsPolicy holds the parsed Strict-Transport-Security policy of an HTTPS
// endpoint.
type HstsPolicy struct {
	// Present is true when the endpoint returned an HSTS header.
	Present bool
	// MaxAge is the max-age directive in seconds.
	MaxAge int
	// IncludeSubDomains is the includeSubDomains directive.
	IncludeSubDomains bool
	// Preload is the preload directive.
	Preload bool
}
