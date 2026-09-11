package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = TlsSecurityAssessed{}

// AssessmentState says what a producer actually established about one section of a
// TLS assessment. It exists because the dangerous failure mode of a TLS report is
// an untested check reading as a passed one: an empty issue list means "clean" only
// if the check ran.
//
// Projection entities interpret this plain event value when materializing an
// assessment.
type AssessmentState string

const (
	// AssessmentTested means the section was assessed and its values are meaningful.
	AssessmentTested AssessmentState = "tested"
	// AssessmentNotTested means the scanner did not assess this section, so its
	// zero values carry no information and must not be reported as a clean result.
	AssessmentNotTested AssessmentState = "not_tested"
	// AssessmentError means the scanner attempted the section and failed. It is
	// distinct from not_tested: something went wrong that is worth investigating.
	AssessmentError AssessmentState = "error"
)

// TlsSecurityAssessed carries a full TLS assessment of one endpoint and server
// name. It is deliberately separate from TlsPostureDiscovered: that event is an
// HTTPS-shaped view of a domain (which versions the site accepts, plus HSTS), while
// this one is a service-level assessment that applies to TLS on any port. A
// TLS-wrapped SMTP, LDAP, or database service has the same assessment and none of
// the HTTP semantics, so flattening the two would either lose the port or invent an
// HTTPS meaning the observation never had.
//
// The asset key is IP, Port, and ServerName together. The same endpoint assessed
// under two server names is two observations, because a server can present a
// different certificate and cipher selection per name. A producer that measured
// several names but cannot say which of them a result belongs to leaves both
// ServerName and AssessedNames empty: the measurement is then a property of the
// endpoint alone, and naming any of the candidates would invent an attribution the
// producer never made.
type TlsSecurityAssessed struct {
	EventMeta
	// IP and Port identify the assessed endpoint. ServerName is the SNI value the
	// assessment used, empty when the endpoint was assessed without one or when
	// the producer could not say which of several names the measurement belongs to.
	IP         string
	Port       int
	ServerName string
	// AssessedNames are the server names this measurement is known to cover,
	// sorted. It holds the one name when ServerName is set. Empty means the
	// producer either did not report its names or could not say which of the names
	// it probed this result covers, and a consumer must then treat the measurement
	// as belonging to the endpoint rather than to any name.
	AssessedNames []string
	// Protocols are the distinct SSL/TLS versions the endpoint accepted, sorted.
	// Empty with CipherState tested means the scanner accepted no suite at all,
	// which is a hard negative rather than missing data.
	Protocols []string
	// Ciphers are the accepted suites, sorted and capped by the producer.
	Ciphers []TlsCipherSuite
	// CipherCount is how many suites were accepted before capping, so a capped
	// list still reports the true total.
	CipherCount int
	// CipherState says whether cipher enumeration ran.
	CipherState AssessmentState
	// Chains are the certificate deployments the endpoint presented, in the order
	// presented, capped by the producer. ChainCount is the total before capping.
	Chains     []TlsCertificateChain
	ChainCount int
	// ChainState says whether certificate collection and validation ran.
	ChainState AssessmentState
	// LowestProtocol is the oldest version the endpoint still accepts, and
	// MinStrength the producer's minimum strength rating across suites and keys.
	// Meaningful only when SettingsState is tested.
	LowestProtocol string
	MinStrength    int
	// ExtendedMasterSecret, TLSFallbackSCSV, and SecureRenegotiation are hardening
	// mechanisms; false means the endpoint lacks them, which is a weakness rather
	// than missing data, but only when SettingsState is tested.
	ExtendedMasterSecret bool
	TLSFallbackSCSV      bool
	SecureRenegotiation  bool
	// SessionResumptionID and SessionResumptionTickets report which resumption
	// mechanisms the endpoint offers.
	SessionResumptionID      bool
	SessionResumptionTickets bool
	// MozillaCompliant reports whether the configuration matches the Mozilla
	// recommended server configuration.
	MozillaCompliant bool
	// SettingsState says whether the settings above were assessed.
	SettingsState AssessmentState
	// Vulnerabilities names the checks that came back positive, sorted. Meaningful
	// only when VulnerabilityState is tested: an empty list with any other state
	// means nothing was checked, not that nothing was found.
	Vulnerabilities    []string
	VulnerabilityState AssessmentState
	// SupportedCurves and RejectedCurves are the elliptic curves the endpoint
	// accepted and refused, sorted and capped. ECDHKeyExchange reports whether
	// ECDH key exchange is supported. Meaningful only when CurveState is tested.
	SupportedCurves []string
	RejectedCurves  []string
	ECDHKeyExchange bool
	CurveState      AssessmentState
	// Truncated marks an assessment whose lists hit a producer cap.
	Truncated bool
}

// TlsCipherSuite is one accepted cipher suite reduced to the properties that decide
// whether offering it is acceptable.
type TlsCipherSuite struct {
	// Protocol is the version the suite was accepted under, and Name the suite
	// name (IANA where the producer has one).
	Protocol string
	Name     string
	// KeyExchange, Authentication, Encryption, and Mac are the suite's algorithms.
	KeyExchange    string
	Authentication string
	Encryption     string
	Mac            string
	// EncryptionBits is the symmetric key size and Strength the producer's rating
	// of it.
	EncryptionBits int
	Strength       int
	// ForwardSecrecy reports whether the key exchange provides it.
	ForwardSecrecy bool
	// Export and Draft mark suites that should not be offered at all.
	Export bool
	Draft  bool
}

// TlsCertificateChain is one certificate deployment an endpoint presented.
type TlsCertificateChain struct {
	// ValidatedBy names the trust stores that accepted the chain, sorted. Empty
	// means no trust store accepted it, which is what makes a chain untrusted; it
	// never means validation was skipped, because the enclosing ChainState says
	// whether validation ran.
	ValidatedBy []string
	// ValidOrder reports whether the endpoint sent the chain in the correct order.
	ValidOrder bool
	// Certificates are the chain's certificates in the order presented, so index 0
	// is the leaf when the order is valid. Order is significant.
	Certificates []TlsChainCertificate
}

// TlsChainCertificate is one certificate of a presented chain. It is distinct from
// CertificateData (the certificate-transparency view): this one records a
// certificate as deployed on an endpoint, with its role in the chain and the
// algorithm choices, rather than a certificate as logged by a CT source.
type TlsChainCertificate struct {
	// Role is the certificate's position in the chain: "leaf", "intermediate", or
	// "root".
	Role string
	// SubjectCN and IssuerCN are the common names, and Serial the serial number in
	// the canonical form CanonicalCertSerial produces, so a certificate seen here
	// keys identically to the same certificate seen in a CT log.
	SubjectCN string
	IssuerCN  string
	Serial    string
	// AlternativeNames are the subject alternative names, lowercased, sorted, and
	// capped by the producer.
	AlternativeNames []string
	// ValidFrom and ValidTo bound the certificate's validity.
	ValidFrom time.Time
	ValidTo   time.Time
	// PublicKeyAlgorithm, PublicKeyBits, SignatureAlgorithm, and SignatureHash are
	// the cryptographic choices. The signature hash is kept apart because a weak
	// hash on a leaf is a finding on its own.
	PublicKeyAlgorithm string
	PublicKeyBits      uint64
	SignatureAlgorithm string
	SignatureHash      string
	// SHA1Fingerprint identifies the certificate itself.
	SHA1Fingerprint string
	// CA marks a certificate authority certificate.
	CA bool
	// Truncated marks a certificate whose alternative-name list hit a cap.
	Truncated bool
}

// At returns the capture time recorded in the event envelope.
func (e TlsSecurityAssessed) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e TlsSecurityAssessed) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e TlsSecurityAssessed) String() string {
	name := e.ServerName
	if name == "" {
		name = e.IP
	}
	if e.CipherState != AssessmentTested {
		return fmt.Sprintf("TLS assessment of %s:%d (%s) incomplete: ciphers %s", e.IP, e.Port, name, e.CipherState)
	}
	return fmt.Sprintf("assessed TLS on %s:%d (%s): %d cipher(s), %d issue(s)",
		e.IP, e.Port, name, e.CipherCount, len(e.Vulnerabilities))
}

func (TlsSecurityAssessed) isDomainEvent() {}
