package valueobjects

// MxTlsHost holds the active SMTP STARTTLS posture of a single MX host.
type MxTlsHost struct {
	// Host is the MX hostname.
	Host string
	// Priority is the MX preference (lower is preferred).
	Priority int
	// Banner is the SMTP greeting banner.
	Banner string
	// EHLO lists the advertised EHLO capabilities.
	EHLO []string
	// StartTLSSupported is true when the host advertised and completed STARTTLS.
	StartTLSSupported bool
	// TLSVersion is the negotiated TLS version, when STARTTLS succeeded.
	TLSVersion string
	// TLSCipher is the negotiated cipher suite, when STARTTLS succeeded.
	TLSCipher string
	// CertSubject is the negotiated certificate subject CN, when available.
	CertSubject string
	// CertIssuer is the negotiated certificate issuer, when available.
	CertIssuer string
	// Error describes why the host could not be fully probed, when applicable.
	Error string
}
