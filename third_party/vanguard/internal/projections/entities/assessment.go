package entities

import "time"

// AssessmentState says what a scanner actually established about one section of a
// multi-part assessment. It exists because the dangerous failure mode of a security
// report is an untested check reading as a passed one: an empty vulnerability list
// means "clean" only if the check ran.
//
// The events package mirrors this as its own string type so it stays free of the
// entities dependency, the same way Confidence and IPReachability are mirrored.
type AssessmentState string

const (
	// AssessmentUnknown is the zero value: no producer said anything about this
	// section, so it was neither tested nor reported as untestable.
	AssessmentUnknown AssessmentState = ""
	// AssessmentTested means the section was assessed and its values are meaningful.
	AssessmentTested AssessmentState = "tested"
	// AssessmentNotTested means the scanner did not assess this section, so its zero
	// values carry no information and must not be presented as a clean result.
	AssessmentNotTested AssessmentState = "not_tested"
	// AssessmentError means the scanner attempted the section and failed, which is
	// worth investigating rather than retrying silently.
	AssessmentError AssessmentState = "error"
)

// assessmentRank orders assessment states from least to most informative, so a
// merge of two observations of the same endpoint is order-independent on replay: a
// section one tool actually tested outranks another's silence about it.
func assessmentRank(s AssessmentState) int {
	switch s {
	case AssessmentTested:
		return 3
	case AssessmentError:
		return 2
	case AssessmentNotTested:
		return 1
	default:
		return 0
	}
}

// Stronger returns the more informative of two assessment states.
func (s AssessmentState) Stronger(other AssessmentState) AssessmentState {
	if assessmentRank(other) > assessmentRank(s) {
		return other
	}
	return s
}

// FieldObservation records one source's value for a field another source reported
// differently. It exists so a merge never has to choose between two non-empty,
// disagreeing observations: the first value stays on the asset and the rest are
// kept here with their attribution, because two tools disagreeing about a product
// version is itself worth reporting and silently keeping one is not.
type FieldObservation struct {
	// Field names the asset field this value was reported for, for example
	// "product" or "version".
	Field string
	// Value is what the source reported.
	Value string
	// Source is the tool that reported it.
	Source string
	// ObservedAt is when the contributing observation was captured.
	ObservedAt time.Time
}

// HostProfile is the host-level evidence an active host scan gathered beside the
// service list. Every field is an inference of some strength, never an assertion:
// OS candidates are ordered guesses, an uptime estimate is derived from TCP
// timestamp drift, and a reverse-DNS name is what the address owner published.
//
// It is deliberately separate from IPAddress.OS, which is the single derived OS
// family the asset graph reads. This is the evidence that guess
// was drawn from, kept whole so a reader can weigh it.
type HostProfile struct {
	// DnsName is the name the scanner settled on for the host, empty when none.
	DnsName string
	// OtherNames are the remaining names seen for the host, sorted and deduplicated.
	OtherNames []string
	// OtherIPs are further addresses attributed to the same host, sorted and
	// deduplicated.
	OtherIPs []string
	// MacAddress is only observable on the scanner's own layer-2 segment, so it is
	// empty for every routed target. A value here means scanner and target share a
	// segment, which is itself worth knowing.
	MacAddress string
	// OSCandidates are the scanner's OS guesses in descending plausibility. Order is
	// significant and is preserved as reported.
	OSCandidates []string
	// OSFromService is an OS a service reply named rather than a fingerprint
	// inferred. It is stronger evidence than a stack fingerprint and kept apart.
	OSFromService string
	// LastBoot and Uptime are estimates, zero when the scanner reported none.
	LastBoot time.Time
	Uptime   time.Duration
	// DetectionReason is the scanner's stated reason for considering the host up,
	// for example "syn-ack". It separates a host that answered from one assumed up.
	DetectionReason string
	// TracerouteHops are the hops to the host in path order. Order is significant.
	TracerouteHops []string
	// Truncated marks a profile whose lists hit a producer cap.
	Truncated bool
	// Sources are the tools that contributed to this profile, sorted and deduped.
	Sources []string
}

// ServiceScript is one host or service script result, such as an nmap NSE script,
// kept as bounded evidence rather than a verdict. An unrecognised script is
// retained: evidence nobody parses yet is worth more than evidence nobody kept.
type ServiceScript struct {
	// Script is the script identifier, for example "ssl-enum-ciphers".
	Script string
	// Scope is "host" or "port", stated rather than inferred from a zero port.
	Scope string
	// Output is the bounded, redacted script output. RawBytes is the size before
	// bounding and Digest a hash of the full output, so two scans can be compared
	// for change without either storing the whole text.
	Output    string
	RawBytes  int
	Digest    string
	Truncated bool
	// ParseStatus states whether a reviewed parser handled the output ("none",
	// "ok", or "failed"). Empty output with status "none" means nobody has written
	// a parser, not that the script found nothing.
	ParseStatus string
	// Source is the tool that ran the script.
	Source string
}

// TlsAssessment is a folded TLS assessment of one endpoint and server name. It is a
// summary: the full cipher table and certificate chains stay in the event stream,
// which is the audit record, while this carries what a report and a detector need.
//
// The state fields are load bearing. A vulnerability list is only evidence of
// safety when VulnerabilityState is "tested"; with any other state an empty list
// means nothing was checked.
type TlsAssessment struct {
	// ServerName is the SNI the assessment used, empty when the endpoint was
	// assessed without one. It is part of the assessment's identity: one endpoint
	// can present different certificates and suites per name.
	ServerName string
	// Protocols are the SSL/TLS versions the endpoint accepted, sorted.
	Protocols []string
	// LowestProtocol is the oldest version still accepted, and MinStrength the
	// producer's minimum strength rating across suites and keys.
	LowestProtocol string
	MinStrength    int
	// CipherCount is how many suites were accepted, and WeakCiphers names the ones
	// that should not be offered (export, draft, RC4, 3DES, anonymous, or below
	// the strength floor), sorted.
	CipherCount int
	WeakCiphers []string
	// ForwardSecrecy reports whether every accepted suite provides it. It is
	// meaningful only when CipherState is tested.
	ForwardSecrecy bool
	// ChainCount is how many certificate deployments the endpoint presented.
	// ChainTrusted reports whether at least one trust store accepted every chain,
	// and ChainOrderValid whether every chain was sent in the right order.
	ChainCount      int
	ChainTrusted    bool
	ChainOrderValid bool
	// LeafSubject, LeafIssuer, LeafSerial, and LeafValidUntil identify the leaf
	// certificate of the first presented chain, so a service listing can show what
	// it is serving without joining to the certificate inventory.
	LeafSubject    string
	LeafIssuer     string
	LeafSerial     string
	LeafValidUntil time.Time
	// Vulnerabilities are the named checks that came back positive, sorted.
	Vulnerabilities []string
	// ExtendedMasterSecret, TLSFallbackSCSV, and SecureRenegotiation are hardening
	// mechanisms: false is a weakness, but only when SettingsState is tested.
	ExtendedMasterSecret bool
	TLSFallbackSCSV      bool
	SecureRenegotiation  bool
	// SessionResumptionID and SessionResumptionTickets report which resumption
	// mechanisms the endpoint offers, and MozillaCompliant whether the
	// configuration matches the Mozilla recommended one.
	SessionResumptionID      bool
	SessionResumptionTickets bool
	MozillaCompliant         bool
	// The per-section states. Each says whether that part of the assessment ran.
	CipherState        AssessmentState
	ChainState         AssessmentState
	SettingsState      AssessmentState
	VulnerabilityState AssessmentState
	CurveState         AssessmentState
	// Truncated marks an assessment whose lists hit a producer cap.
	Truncated bool
	// Sources are the tools that contributed this assessment, sorted and deduped.
	Sources []string
}

// Assessed reports whether any section of the assessment actually ran. A service
// carrying an assessment where nothing was tested is a coverage gap, and a report
// must not present it as a TLS service that came back clean.
func (t TlsAssessment) Assessed() bool {
	return t.CipherState == AssessmentTested || t.ChainState == AssessmentTested ||
		t.SettingsState == AssessmentTested || t.VulnerabilityState == AssessmentTested
}

// SshPosture is the algorithms and protocol an SSH endpoint offers. The lists are
// the server's offer, not a negotiated session: a server offering one weak cipher
// among twenty is exposed by the offer whatever a good client would pick.
type SshPosture struct {
	// ProtocolVersion is the SSH protocol version from the identification string.
	ProtocolVersion string
	// Banner is the endpoint's identification string, bounded by the producer.
	Banner string
	// KeyExchange, HostKey, Encryption, Mac, and Compression are the offered
	// algorithm lists in the server's stated preference order, which is preserved.
	KeyExchange []string
	HostKey     []string
	Encryption  []string
	Mac         []string
	Compression []string
	// AuthMechanisms are the offered authentication methods.
	AuthMechanisms []string
	// GuessedKeyExchange reports a server that proceeded on a guessed key exchange.
	GuessedKeyExchange bool
	// Truncated marks a posture whose lists hit a producer cap, so a short list is
	// never read as the server's complete offer.
	Truncated bool
	// Sources are the tools that contributed this posture, sorted and deduped.
	Sources []string
}
