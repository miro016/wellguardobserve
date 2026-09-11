package goscans

import (
	"log/slog"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// toolName identifies this tool in every event and in the tool log.
const (
	toolName               = "goscans"
	healthCodeModuleFailed = "goscans.module_failed"
)

// Event is the sealed goscans tool-event interface. It is the only way results and
// intermediate state leave the actor: there is no parallel result object to read
// afterwards, so anything not on an event did not happen as far as the rest of the
// system is concerned. The unexported marker keeps the set closed, so orchestration
// can translate it with an exhaustive type switch and a new event cannot appear in
// the stream without a translation decision.
type Event interface {
	// ToolName returns the tool identifier.
	ToolName() string
	// EventName returns a short human-readable label.
	EventName() string
	// EventLevel returns the log severity.
	EventLevel() slog.Level
	// EventAttrs returns the structured key-value pairs for logging and display.
	EventAttrs() []slog.Attr
	isGoscansEvent()
}

// event supplies the two members every goscans event answers identically: the tool
// name and the seal. Each event still declares its own label, level, and attributes.
// It is embedded rather than repeated because this actor produces far more event
// types than a single-purpose tool does, and the repetition would bury the parts
// that actually differ.
type event struct{}

// ToolName returns the tool identifier.
func (event) ToolName() string { return toolName }

func (event) isGoscansEvent() {}

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

// ScanStarted is emitted once, before the first target, after the configuration
// and the whole target list have been validated.
type ScanStarted struct {
	event
	// Targets is the number of scope-approved targets in this run.
	Targets int
	// Modules lists the enabled subordinate modules, sorted.
	Modules []string
	// Workers is the tool-wide ceiling on subordinate jobs in flight, which is the
	// upper bound on this run's traffic however the targets and hosts arrange
	// themselves. It is reported so the configured bound is visible in the stream
	// rather than only in the configuration. Targets is how many of those targets
	// may be assessed at once; a single host is separately capped below this.
	Workers int
	// ProbeSetDigest is the hex SHA-256 of the embedded web enumeration probe set,
	// empty when enumeration is disabled. It records which probe set produced the
	// run, so a later scan comparison can tell a real change from a probe change.
	ProbeSetDigest string
	// Runtime is the external dependency set the startup check resolved: which
	// nmap and which SSLyze produced everything that follows. It is empty only
	// when no startup check ran, which outside a test means the actor was built
	// by something that skipped it.
	Runtime Runtime
	// Library is the vendored upstream GoScans release this binary was built
	// against. It sits beside Runtime rather than inside it because it is not
	// something a machine was found to have: it is compiled in, and it is what
	// decided which scripts ran and how their results were read.
	Library string
}

// EventName returns a short human-readable label.
func (ScanStarted) EventName() string { return "goscans: scan started" }

// EventLevel returns the log severity.
func (ScanStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScanStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.Int("targets", e.Targets),
		slog.Any("modules", e.Modules),
		slog.Int("workers", e.Workers),
		slog.String("probe_set_digest", e.ProbeSetDigest),
		slog.String("nmap_path", e.Runtime.NmapPath),
		slog.String("nmap_version", e.Runtime.NmapVersion),
		slog.String("python_path", e.Runtime.PythonPath),
		slog.String("python_version", e.Runtime.PythonVersion),
		slog.String("sslyze_version", e.Runtime.SslyzeVersion),
		slog.String("library", e.Library),
	}
}

// ScanCompleted is emitted once, last, even when Run returns an error. Its counts
// are the aggregate the data-quality replay reads, so they are reported whether the
// run succeeded, failed, or was cancelled.
type ScanCompleted struct {
	event
	// Targets is the number of targets attempted.
	Targets int
	// Hosts is the number of hosts discovery reported across all targets.
	Hosts int
	// Jobs is the number of subordinate jobs scheduled.
	Jobs int
	// Succeeded, Failed, and Skipped partition the scheduled jobs.
	Succeeded int
	Failed    int
	Skipped   int
	// Workers is the tool-wide ceiling on jobs in flight, and Peak the highest number
	// actually in flight at once. Peak below Workers means the plan, the per-host
	// cap, or the target parallelism was the limit rather than the ceiling; the pair
	// is what makes the run's traffic bound checkable against the configuration.
	Workers int
	Peak    int
	// Degraded marks a run that could not complete its plan, so a zero result must
	// not be read as an honest empty.
	Degraded bool
	// Duration is the wall-clock time of the whole run.
	Duration time.Duration
}

// EventName returns a short human-readable label.
func (ScanCompleted) EventName() string { return "goscans: scan completed" }

// EventLevel returns the log severity.
func (ScanCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScanCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.Int("targets", e.Targets),
		slog.Int("hosts", e.Hosts),
		slog.Int("jobs", e.Jobs),
		slog.Int("succeeded", e.Succeeded),
		slog.Int("failed", e.Failed),
		slog.Int("skipped", e.Skipped),
		slog.Int("workers", e.Workers),
		slog.Int("peak_concurrency", e.Peak),
		slog.Bool("degraded", e.Degraded),
		slog.Duration("duration", e.Duration),
	}
}

// TargetStarted is emitted before discovery runs for one target.
type TargetStarted struct {
	event
	// IP is the target address.
	IP string
	// Vhosts is the number of virtual hosts carried into the TLS and web modules.
	Vhosts int
}

// EventName returns a short human-readable label.
func (TargetStarted) EventName() string { return "goscans: target started" }

// EventLevel returns the log severity.
func (TargetStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TargetStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.Int("vhosts", e.Vhosts)}
}

// TargetCompleted summarises one target. Partial counts a target whose discovery
// succeeded but whose subordinate work did not fully complete, which is a different
// outcome from a target that produced nothing.
type TargetCompleted struct {
	event
	// IP is the target address.
	IP string
	// Attempted, Succeeded, Failed, and Skipped partition this target's jobs.
	Attempted int
	Succeeded int
	Failed    int
	Skipped   int
	// Partial marks a target with both successful and failed subordinate work.
	Partial bool
	// Duration is the wall-clock time for this target.
	Duration time.Duration
}

// EventName returns a short human-readable label.
func (TargetCompleted) EventName() string { return "goscans: target completed" }

// EventLevel returns the log severity.
func (TargetCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TargetCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("attempted", e.Attempted),
		slog.Int("succeeded", e.Succeeded),
		slog.Int("failed", e.Failed),
		slog.Int("skipped", e.Skipped),
		slog.Bool("partial", e.Partial),
		slog.Duration("duration", e.Duration),
	}
}

// -----------------------------------------------------------------------------
// Discovery
// -----------------------------------------------------------------------------

// DiscoveryScope reports how one discovery scan was aimed, before it runs.
//
// It exists because a scoped scan and a full sweep produce results that look
// identical afterwards and mean different things. A scoped scan can only find what
// it was pointed at, so "nothing else was open" is a claim only the full sweep is
// entitled to make. Recording the mode per target is what lets a later reader tell
// the two apart, and lets a scan comparison tell a real change from a change in how
// the host was looked at.
type DiscoveryScope struct {
	event
	// IP is the target address.
	IP string
	// Ports is how many ports the scan was scoped to, zero when it was not scoped.
	Ports int
	// Scoped reports whether the supplied port set was applied. It can be false with
	// a non-zero Ports: the operator's own port argument wins, and the scan then
	// sweeps the range they chose rather than the one that was offered.
	Scoped bool
}

// EventName returns a short human-readable label.
func (DiscoveryScope) EventName() string { return "goscans: discovery scope" }

// EventLevel returns the log severity.
func (DiscoveryScope) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DiscoveryScope) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("ports", e.Ports),
		slog.Bool("scoped", e.Scoped),
	}
}

// DiscoveryCompleted reports one finished discovery scan.
type DiscoveryCompleted struct {
	event
	// IP is the target address.
	IP string
	// Hosts, Services, and Scripts are what discovery returned.
	Hosts    int
	Services int
	Scripts  int
	// Status is the upstream final status string.
	Status string
	// Duration is the wall-clock time of the discovery scan.
	Duration time.Duration
}

// EventName returns a short human-readable label.
func (DiscoveryCompleted) EventName() string { return "goscans: discovery completed" }

// EventLevel returns the log severity.
func (DiscoveryCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DiscoveryCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("hosts", e.Hosts),
		slog.Int("services", e.Services),
		slog.Int("scripts", e.Scripts),
		slog.String("status", e.Status),
		slog.Duration("duration", e.Duration),
	}
}

// DiscoveryEmpty reports a discovery scan that completed without an error and found
// no host. This is an honest empty, not a failure: it is a separate event so a
// replay never has to infer the difference from a zero count.
type DiscoveryEmpty struct {
	event
	// IP is the target address.
	IP string
	// Status is the upstream final status string.
	Status string
}

// EventName returns a short human-readable label.
func (DiscoveryEmpty) EventName() string { return "goscans: discovery found no host" }

// EventLevel returns the log severity.
func (DiscoveryEmpty) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e DiscoveryEmpty) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.String("status", e.Status)}
}

// HostProfileCollected reports the host-level evidence discovery gathered
// alongside the service list: what the host calls itself, which other addresses
// answered for it, and the weak identity signals nmap infers. It is emitted once
// per host discovery reported, before any subordinate job, so a target that
// produces no service still contributes what was learned about the host itself.
//
// Every field here is an inference of some strength, not an assertion. The OS
// candidates are nmap guesses in upstream's order, the MAC address is only ever
// visible on the scanner's own layer-2 segment, and the uptime estimate is derived
// from TCP timestamps. Consumers must present them as guesses.
type HostProfileCollected struct {
	event
	// IP is the host address discovery reported.
	IP string
	// DnsName is the name discovery settled on for this host, chosen from reverse
	// DNS and certificate names ranked by the configured domain order.
	DnsName string
	// OtherNames are the remaining names seen for the host, sorted and capped.
	OtherNames []string
	// OtherIPs are further addresses discovery attributed to the same host, sorted
	// and capped.
	OtherIPs []string
	// MacAddress is set only when the host is on the scanner's own layer-2 segment;
	// it is empty for every routed target, which is every external target.
	MacAddress string
	// OSGuesses are nmap's OS candidates in upstream's order of plausibility, capped.
	// Order is significant and is preserved as given.
	OSGuesses []string
	// OSFromSMB is the OS string an SMB host script reported, when one ran. It is a
	// separate field because it comes from a service reply rather than a fingerprint.
	OSFromSMB string
	// LastBoot is the estimated boot time, zero when nmap reported none.
	LastBoot time.Time
	// Uptime is the estimated uptime, zero when nmap reported none.
	Uptime time.Duration
	// DetectionReason is nmap's stated reason for considering the host up, for
	// example "syn-ack". It is what separates a live host from an assumed one.
	DetectionReason string
	// Hops are the traceroute hops to the host in path order, capped. Order is
	// significant and is preserved as given.
	Hops []string
	// Truncated marks a profile whose lists hit a cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (HostProfileCollected) EventName() string { return "goscans: host profile collected" }

// EventLevel returns the log severity.
func (HostProfileCollected) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e HostProfileCollected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("dns_name", e.DnsName),
		slog.Any("other_names", e.OtherNames),
		slog.Any("other_ips", e.OtherIPs),
		slog.String("mac_address", e.MacAddress),
		slog.Any("os_guesses", e.OSGuesses),
		slog.String("os_smb", e.OSFromSMB),
		slog.Time("last_boot", e.LastBoot),
		slog.Duration("uptime", e.Uptime),
		slog.String("detection_reason", e.DetectionReason),
		slog.Any("hops", e.Hops),
		slog.Bool("truncated", e.Truncated),
	}
}

// ServiceDiscovered reports one service. Tunnel matters as much as Name: nmap
// describes a TLS-wrapped HTTP service as name "http" with tunnel "ssl", so a
// consumer reading Name alone would call an HTTPS service cleartext.
type ServiceDiscovered struct {
	event
	// IP is the host address discovery reported the service on, which may differ
	// from the scanned target when nmap resolved additional addresses.
	IP string
	// Port is the service port.
	Port int
	// Protocol is the transport, straight from nmap.
	Protocol string
	// Name is the nmap service name.
	Name string
	// Tunnel is the nmap tunnel attribute, "ssl" for a TLS-wrapped service.
	Tunnel string
	// Product and Version are the nmap fingerprint, when it matched one.
	Product string
	Version string
	// ExtraInfo is nmap's free-form service detail, for example "Ubuntu".
	ExtraInfo string
	// CPEs are the platform identifiers nmap matched, sorted and deduplicated.
	CPEs []string
	// Method is nmap's detection method, "table" for a port-number guess and
	// "probed" for a service that answered a version probe. It separates a real
	// fingerprint from a lookup, so a consumer never treats a guessed service name
	// as observed.
	Method string
	// DeviceType and Flavor are nmap's coarse device classification and OS flavor
	// for the service. They are carried in the tool log only: the domain model has
	// no consumer for them, and inventing one for two rarely-populated strings
	// would be a projection nothing reads.
	DeviceType string
	Flavor     string
	// TTL is the IP time-to-live observed for this service. Differing TTLs across
	// one host's ports hint at port forwarding. Tool log only, for the same reason.
	TTL int
}

// EventName returns a short human-readable label.
func (ServiceDiscovered) EventName() string { return "goscans: service discovered" }

// EventLevel returns the log severity.
func (ServiceDiscovered) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ServiceDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("protocol", e.Protocol),
		slog.String("service", e.Name),
		slog.String("tunnel", e.Tunnel),
		slog.String("product", e.Product),
		slog.String("version", e.Version),
		slog.String("extra_info", e.ExtraInfo),
		slog.Any("cpes", e.CPEs),
		slog.String("method", e.Method),
		slog.String("device_type", e.DeviceType),
		slog.String("flavor", e.Flavor),
		slog.Int("ttl", e.TTL),
	}
}

// ScriptCollected reports one NSE script result discovery attached to a host or
// port. Output is redacted and capped; RawBytes is the size before capping.
type ScriptCollected struct {
	event
	// IP is the host address.
	IP string
	// Port is the port the script ran against, or 0 for a host script.
	Port int
	// Protocol is the transport for a port script, empty for a host script.
	Protocol string
	// Name is the NSE script name.
	Name string
	// Scope is upstream's script type, "host" for a host-wide script and "port"
	// for one bound to a service. Port is 0 for a host script, so this states the
	// scope rather than leaving it to be inferred from a zero.
	Scope string
	// Output is the redacted, capped script output.
	Output string
	// RawBytes is the output size before capping.
	RawBytes int
	// Truncated marks output that did not fit the cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (ScriptCollected) EventName() string { return "goscans: nse script collected" }

// EventLevel returns the log severity.
func (ScriptCollected) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScriptCollected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("protocol", e.Protocol),
		slog.String("script", e.Name),
		slog.String("scope", e.Scope),
		slog.String("output", e.Output),
		slog.Int("raw_bytes", e.RawBytes),
		slog.Bool("truncated", e.Truncated),
	}
}

// -----------------------------------------------------------------------------
// Module results
// -----------------------------------------------------------------------------

// BannerCollected reports one banner probe response. Upstream sends five probes
// per service (plain, TLS, Telnet, HTTP, HTTPS) and truncates each at 2048 bytes;
// one event is emitted per probe that returned bytes, so a service answering only
// on TLS is distinguishable from one answering in cleartext.
type BannerCollected struct {
	event
	// IP is the host address.
	IP string
	// Port is the service port.
	Port int
	// Protocol is the transport used for the probe.
	Protocol string
	// Probe names which of the five upstream probes produced this banner.
	Probe string
	// Excerpt is the redacted, capped banner text.
	Excerpt string
	// RawBytes is the banner size before capping.
	RawBytes int
	// Digest is a hash of the raw banner, so two observations can be compared
	// without storing the bytes.
	Digest string
	// Truncated marks a banner that did not fit the cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (BannerCollected) EventName() string { return "goscans: banner collected" }

// EventLevel returns the log severity.
func (BannerCollected) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e BannerCollected) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("protocol", e.Protocol),
		slog.String("probe", e.Probe),
		slog.String("excerpt", e.Excerpt),
		slog.Int("raw_bytes", e.RawBytes),
		slog.String("digest", e.Digest),
		slog.Bool("truncated", e.Truncated),
	}
}

// TLSCipher is one accepted cipher suite, reduced to the properties that decide
// whether it is acceptable. The full upstream description carries around twenty
// derived fields per suite; keeping all of them for every suite on every virtual
// host would put tens of kilobytes of mostly-restatable detail into the stream.
type TLSCipher struct {
	// Protocol is the SSL/TLS version the suite was accepted under.
	Protocol string
	// Name is the IANA suite name, falling back to the OpenSSL name when upstream
	// has no IANA one.
	Name string
	// KeyExchange, Authentication, Encryption, and Mac are the suite's algorithms.
	//
	// KeyExchange is read from the suite name rather than taken from the scanner,
	// and so is ForwardSecrecy below. The two travel together because one decides
	// the other, and a reader comparing either against raw scanner output should
	// expect them to differ: a scanner resolves the key exchange through a static
	// suite table, and such a table can disagree with the name it is keyed by. One
	// shipped table types most ECDHE suites as static ECDH, which would report every
	// affected suite as lacking forward secrecy when it provides it. A suite name
	// cannot disagree with itself, so it is the authority. A name that carries no
	// key exchange leaves both fields as the scanner reported them.
	KeyExchange    string
	Authentication string
	Encryption     string
	Mac            string
	// EncryptionBits is the symmetric key size, and Strength upstream's rating of
	// it. Strength is what the low-encryption issue flag is derived from.
	EncryptionBits int
	Strength       int
	// ForwardSecrecy reports whether the key exchange provides it. Derived with
	// KeyExchange above, not taken from the scanner.
	ForwardSecrecy bool
	// Export and Draft mark suites that should not be offered at all.
	Export bool
	Draft  bool
}

// TLSCertificate is one certificate of one chain, reduced to identity, validity,
// and the algorithm choices that decide whether it is acceptable. The raw DER is
// deliberately absent: nothing downstream re-parses it, and it is the single
// largest payload SSLyze returns.
type TLSCertificate struct {
	// Role is the certificate's position in the chain: "leaf", "intermediate", or
	// "root".
	Role string
	// SubjectCN and IssuerCN are the common names.
	SubjectCN string
	IssuerCN  string
	// Serial is the certificate serial in hexadecimal.
	Serial string
	// AlternativeNames are the subject alternative names, sorted and capped.
	AlternativeNames []string
	// ValidFrom and ValidTo bound the certificate's validity.
	ValidFrom time.Time
	ValidTo   time.Time
	// PublicKeyAlgorithm, PublicKeyBits, SignatureAlgorithm, and SignatureHash are
	// the cryptographic choices. A weak signature hash on a leaf is a finding in
	// its own right, so the hash is kept apart from the signature algorithm.
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

// TLSChain is one certificate deployment the server presented.
type TLSChain struct {
	// ValidatedBy names the trust stores that accepted the chain, sorted. Empty
	// means no configured trust store accepted it, which is what makes a chain
	// invalid; it does not mean the check was skipped.
	ValidatedBy []string
	// ValidOrder reports whether the server sent the chain in the correct order.
	ValidOrder bool
	// Certificates are the chain's certificates in the order the server sent them,
	// capped. Order is significant and is preserved as given.
	Certificates []TLSCertificate
}

// TLSSettings are the server's protocol-level configuration choices. Each boolean
// is only meaningful when the assessment actually produced settings, which is what
// TLSAssessed.SettingsKnown states.
type TLSSettings struct {
	// LowestProtocol is the oldest protocol version the server still accepts.
	LowestProtocol string
	// MinStrength is upstream's minimum strength rating across every accepted
	// cipher and certificate key.
	MinStrength int
	// ExtendedMasterSecret, TLSFallbackSCSV, and SecureRenegotiation are hardening
	// mechanisms: false is a weakness, not an absence of data.
	ExtendedMasterSecret bool
	TLSFallbackSCSV      bool
	SecureRenegotiation  bool
	// SessionResumptionID and SessionResumptionTickets report which resumption
	// mechanisms the server offers.
	SessionResumptionID      bool
	SessionResumptionTickets bool
	// MozillaCompliant reports whether the configuration matches the Mozilla
	// recommended server configuration.
	MozillaCompliant bool
}

// TLSAssessed reports the SSLyze assessment of one virtual host on one port. It is
// emitted for a TLS service on any port, not only 443, and it is deliberately not
// shaped like an HTTPS posture: a TLS-wrapped SMTP or LDAP service has the same
// assessment and none of the HTTP semantics.
//
// The three Known booleans exist because upstream returns settings, issues, and
// curves as pointers that are nil when SSLyze produced no such section. A nil
// section means "not tested", which must never read as "nothing wrong": without
// the flag an empty issue list would look identical to a clean result.
type TLSAssessed struct {
	event
	// IP is the host address.
	IP string
	// Port is the TLS port.
	Port int
	// Vhost is the server name this result belongs to, empty when upstream
	// reported fewer results than server names were requested. Upstream drops a
	// result identical to one it already collected, without saying which name it
	// dropped, so in that case no single name owns the measurement and naming one
	// would be a guess.
	Vhost string
	// AssessedNames are the server names this measurement is known to cover: the
	// one name when Vhost is set, and nothing at all otherwise.
	//
	// It stays empty on any short count rather than spreading the survivor over
	// every requested name, because upstream also drops a result that came back
	// empty and does not distinguish that from a duplicate. Claiming the names
	// would charge one name's measurement to names that were never measured.
	AssessedNames []string
	// Protocols are the distinct SSL/TLS versions among the accepted cipher
	// suites, sorted. Empty with ciphers present means upstream named no protocol.
	Protocols []string
	// Ciphers are the accepted suites, sorted by protocol then name, deduplicated,
	// and capped. Upstream can report one negotiated suite several times because its
	// suite table is keyed by OpenSSL name and holds every entry sharing one; a
	// protocol and a name together identify a suite here, so the same name under two
	// protocol versions stays two entries.
	Ciphers []TLSCipher
	// CipherCount is how many distinct suites upstream accepted before capping, so a
	// capped list still reports the true total. It counts the deduplicated suites,
	// which is what Ciphers holds.
	CipherCount int
	// Chains are the certificate deployments the server presented, capped.
	Chains []TLSChain
	// ChainCount is how many chains upstream reported before capping.
	ChainCount int
	// Settings are the server's protocol configuration choices, meaningful only
	// when SettingsKnown is true.
	Settings      TLSSettings
	SettingsKnown bool
	// Issues are the upstream issue flags that were set, sorted by name. They are
	// meaningful only when IssuesKnown is true: an empty list with IssuesKnown
	// false means SSLyze reported nothing, not that the server is clean.
	Issues      []string
	IssuesKnown bool
	// SupportedCurves and RejectedCurves are the elliptic curves the server
	// accepted and refused, sorted and capped. Meaningful only when CurvesKnown.
	SupportedCurves []string
	RejectedCurves  []string
	// ECDHKeyExchange reports whether the server supports ECDH key exchange.
	ECDHKeyExchange bool
	CurvesKnown     bool
	// Truncated marks a result whose cipher, chain, certificate, name, or curve
	// list hit a cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (TLSAssessed) EventName() string { return "goscans: tls assessed" }

// EventLevel returns the log severity.
func (TLSAssessed) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display. The
// cipher and chain detail is summarised rather than expanded: the tool log is a
// human-readable trace, and the full payload travels on the event itself.
func (e TLSAssessed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("vhost", e.Vhost),
		slog.Any("assessed_names", e.AssessedNames),
		slog.Any("protocols", e.Protocols),
		slog.Int("ciphers", e.CipherCount),
		slog.Int("chains", e.ChainCount),
		slog.String("lowest_protocol", e.Settings.LowestProtocol),
		slog.Int("min_strength", e.Settings.MinStrength),
		slog.Bool("settings_known", e.SettingsKnown),
		slog.Any("issues", e.Issues),
		slog.Bool("issues_known", e.IssuesKnown),
		slog.Bool("curves_known", e.CurvesKnown),
		slog.Bool("truncated", e.Truncated),
	}
}

// TLSNamesUnreported reports that a TLS job requested more server names than
// upstream returned results for. Upstream runs one full SSLyze handshake per name
// and then drops any result that matches one it already collected, and it drops a
// result carrying no ciphers or no chains, without distinguishing the two. So a
// missing name means either "configured exactly like a name already reported" or
// "produced nothing at all", and the scanner does not say which.
//
// It is emitted so the gap is visible rather than inferred from a shorter table:
// without it, a socket assessed under two names and reported under one reads as
// complete. Reported distinguishes the two shapes a reader cares about: zero means
// the service was not assessed at all, and any other short count means results
// exist but none of them can be tied to a name.
type TLSNamesUnreported struct {
	event
	// IP is the host address and Port the TLS port.
	IP   string
	Port int
	// Requested are the server names handed to the scanner, sorted.
	Requested []string
	// Reported is how many results came back for them.
	Reported int
}

// EventName returns a short human-readable label.
func (TLSNamesUnreported) EventName() string { return "goscans: tls server names unreported" }

// EventLevel returns the log severity.
func (TLSNamesUnreported) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TLSNamesUnreported) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.Any("requested", e.Requested),
		slog.Int("reported", e.Reported),
	}
}

// SSHAssessed reports the algorithm and protocol choices of one SSH service.
type SSHAssessed struct {
	event
	// IP is the host address.
	IP string
	// Port is the SSH port.
	Port int
	// ProtocolVersion is the banner protocol version.
	ProtocolVersion string
	// KeyExchange, ServerKey, Encryption, Mac, and Compression are the server's
	// offered algorithm lists, each capped.
	KeyExchange []string
	ServerKey   []string
	Encryption  []string
	Mac         []string
	Compression []string
	// AuthMechanisms are the offered authentication mechanisms.
	AuthMechanisms []string
	// GuessedKeyExchange marks a server that used a guessed key exchange.
	GuessedKeyExchange bool
	// Truncated marks a result whose algorithm lists hit a cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (SSHAssessed) EventName() string { return "goscans: ssh assessed" }

// EventLevel returns the log severity.
func (SSHAssessed) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e SSHAssessed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("protocol_version", e.ProtocolVersion),
		slog.Any("key_exchange", e.KeyExchange),
		slog.Any("server_key", e.ServerKey),
		slog.Any("encryption", e.Encryption),
		slog.Any("mac", e.Mac),
		slog.Any("compression", e.Compression),
		slog.Any("auth_mechanisms", e.AuthMechanisms),
		slog.Bool("guessed_key_exchange", e.GuessedKeyExchange),
		slog.Bool("truncated", e.Truncated),
	}
}

// CrawlPage reports one crawled page. The response body never leaves as raw bytes:
// only a redacted excerpt, its size, and a digest.
type CrawlPage struct {
	event
	// IP is the host address.
	IP string
	// Port is the web port.
	Port int
	// Vhost is the server name used for the request.
	Vhost string
	// URL is the requested URL.
	URL string
	// RedirectURL is the final URL after redirects, when any happened.
	RedirectURL string
	// RedirectCount is how many redirects were followed to reach RedirectURL.
	RedirectCount int
	// Depth is the link distance from the crawl entry page, 0 for the entry itself.
	Depth int
	// ResponseCode is the HTTP status code.
	ResponseCode int
	// ContentType is the response content type.
	ContentType string
	// Server is the value of the response Server header, empty when absent.
	Server string
	// AuthMethod is the authentication scheme the response demanded, empty when
	// the page was served without one.
	AuthMethod string
	// Title is the extracted HTML title.
	Title string
	// Excerpt is the redacted, capped body text.
	Excerpt string
	// RawBytes is the body size before capping.
	RawBytes int
	// Digest is a hash of the raw body.
	Digest string
	// Truncated marks a body that did not fit the cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (CrawlPage) EventName() string { return "goscans: page crawled" }

// EventLevel returns the log severity.
func (CrawlPage) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CrawlPage) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("vhost", e.Vhost),
		slog.String("url", e.URL),
		slog.String("redirect_url", e.RedirectURL),
		slog.Int("redirect_count", e.RedirectCount),
		slog.Int("depth", e.Depth),
		slog.Int("status", e.ResponseCode),
		slog.String("content_type", e.ContentType),
		slog.String("server", e.Server),
		slog.String("auth_method", e.AuthMethod),
		slog.String("title", e.Title),
		slog.String("excerpt", e.Excerpt),
		slog.Int("raw_bytes", e.RawBytes),
		slog.String("digest", e.Digest),
		slog.Bool("truncated", e.Truncated),
	}
}

// CrawlCompleted summarises one crawl of one virtual host.
type CrawlCompleted struct {
	event
	// IP is the host address.
	IP string
	// Port is the web port.
	Port int
	// Vhost is the server name crawled.
	Vhost string
	// Pages is the number of pages reported, before capping.
	Pages int
	// Requests is the number of HTTP requests the crawler made.
	Requests int
	// DiscoveredVhosts are additional virtual hosts the crawl observed, sorted and
	// deduplicated. They are names this tool found itself, so they may seed its own
	// later work and the domain stream, but never another tool's target plan.
	DiscoveredVhosts []string
	// FaviconHash is the crawler's hash of the site favicon. It is a cheap pivot
	// for finding the same application on other hosts, so it is recorded even
	// though nothing folds it yet.
	FaviconHash string
	// AuthMethod is the authentication scheme the crawl encountered, empty when
	// none was demanded. AuthSuccess is upstream's flag for a scheme it managed to
	// satisfy, which is always false here: this integration configures no
	// credentials, so an authenticated area is recorded as seen, never as entered.
	AuthMethod  string
	AuthSuccess bool
	// Status is the upstream final status string.
	Status string
	// Truncated marks a crawl whose page events hit the cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (CrawlCompleted) EventName() string { return "goscans: crawl completed" }

// EventLevel returns the log severity.
func (CrawlCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CrawlCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("vhost", e.Vhost),
		slog.Int("pages", e.Pages),
		slog.Int("requests", e.Requests),
		slog.Any("discovered_vhosts", e.DiscoveredVhosts),
		slog.String("favicon_hash", e.FaviconHash),
		slog.String("auth_method", e.AuthMethod),
		slog.Bool("auth_success", e.AuthSuccess),
		slog.String("status", e.Status),
		slog.Bool("truncated", e.Truncated),
	}
}

// EnumItemFound reports one enumeration probe that matched.
type EnumItemFound struct {
	event
	// IP is the host address.
	IP string
	// Port is the web port.
	Port int
	// Vhost is the server name used for the request.
	Vhost string
	// Name is the probe name that matched.
	Name string
	// URL is the probed URL.
	URL string
	// RedirectURL is the final URL after redirects, when any happened.
	RedirectURL string
	// RedirectCount is how many redirects were followed to reach RedirectURL, and
	// RedirectOut marks a redirect that left the probed endpoint entirely.
	RedirectCount int
	RedirectOut   bool
	// ResponseCode is the HTTP status code.
	ResponseCode int
	// ContentType is the response content type.
	ContentType string
	// Server is the value of the response Server header, empty when absent.
	Server string
	// AuthMethod is the authentication scheme the response demanded, empty when
	// the path was served without one.
	AuthMethod string
	// Title is the extracted HTML title.
	Title string
	// Excerpt is the redacted, capped body text.
	Excerpt string
	// RawBytes is the body size before capping.
	RawBytes int
	// Digest is a hash of the raw body.
	Digest string
	// Truncated marks a body that did not fit the cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (EnumItemFound) EventName() string { return "goscans: web path found" }

// EventLevel returns the log severity.
func (EnumItemFound) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e EnumItemFound) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("vhost", e.Vhost),
		slog.String("probe", e.Name),
		slog.String("url", e.URL),
		slog.String("redirect_url", e.RedirectURL),
		slog.Int("redirect_count", e.RedirectCount),
		slog.Bool("redirect_out", e.RedirectOut),
		slog.Int("status", e.ResponseCode),
		slog.String("content_type", e.ContentType),
		slog.String("server", e.Server),
		slog.String("auth_method", e.AuthMethod),
		slog.String("title", e.Title),
		slog.String("excerpt", e.Excerpt),
		slog.Int("raw_bytes", e.RawBytes),
		slog.String("digest", e.Digest),
		slog.Bool("truncated", e.Truncated),
	}
}

// EnumCompleted summarises one enumeration job.
type EnumCompleted struct {
	event
	// IP is the host address.
	IP string
	// Port is the web port.
	Port int
	// Items is the number of matches reported, before capping.
	Items int
	// Status is the upstream final status string.
	Status string
	// Truncated marks an enumeration whose item events hit the cap.
	Truncated bool
}

// EventName returns a short human-readable label.
func (EnumCompleted) EventName() string { return "goscans: web enumeration completed" }

// EventLevel returns the log severity.
func (EnumCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e EnumCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.Int("items", e.Items),
		slog.String("status", e.Status),
		slog.Bool("truncated", e.Truncated),
	}
}

// JobSkipped records work that was deliberately not scheduled. A skip is recorded
// rather than dropped, because "we never looked" and "we looked and found nothing"
// are different facts and only one of them is a coverage gap.
type JobSkipped struct {
	event
	// IP is the host address.
	IP string
	// Port is the service port, or 0 when the skip is not port specific.
	Port int
	// Protocol is the service transport, when known.
	Protocol string
	// Module is the module that was not run.
	Module string
	// Reason explains the skip in stable, machine-comparable words.
	Reason string
	// Eligible marks a skip that left a gap: the service was a valid subject for
	// this module and was not assessed anyway, which is what a cap does. It is
	// false for a module the service was never a subject of - a TLS check on an FTP
	// port - because not running that is the planner working, not a gap. Only the
	// tool can tell the two apart, so it decides here rather than leaving a caller
	// to infer it from the reason text.
	Eligible bool
}

// EventName returns a short human-readable label.
func (JobSkipped) EventName() string { return "goscans: job skipped" }

// EventLevel returns the log severity.
func (JobSkipped) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e JobSkipped) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("protocol", e.Protocol),
		slog.String("module", e.Module),
		slog.String("reason", e.Reason),
		slog.Bool("eligible", e.Eligible),
	}
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

// InvalidInput reports a configuration or target that failed validation. It is
// emitted before any network operation, from construction.
type InvalidInput struct {
	event
	// Field names the offending configuration field or input.
	Field string
	// Err is the validation error.
	Err error
}

// EventName returns a short human-readable label.
func (InvalidInput) EventName() string { return "goscans: invalid input" }

// EventLevel returns the log severity.
func (InvalidInput) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e InvalidInput) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("field", e.Field), slog.Any("error", e.Err)}
}

// ModuleSetupFailed reports an upstream constructor that refused to build a
// scanner. For the TLS module this is also where a missing interpreter or an
// unsupported SSLyze version surfaces, because upstream probes both there.
type ModuleSetupFailed struct {
	event
	// Module is the module that could not be constructed.
	Module string
	// IP and Port identify the job, Port being 0 for discovery.
	IP   string
	Port int
	// Err is the upstream construction error.
	Err error
}

// EventName returns a short human-readable label.
func (ModuleSetupFailed) EventName() string { return "goscans: module setup failed" }

// EventLevel returns the log severity.
func (ModuleSetupFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ModuleSetupFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("module", e.Module),
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports a module that could not be constructed.
func (e ModuleSetupFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeModuleFailed, Component: e.Module, Target: e.IP}, true
}

// ModuleTimeout reports a module that ran out of its deadline.
type ModuleTimeout struct {
	event
	// Module is the module that timed out.
	Module string
	// IP and Port identify the job, Port being 0 for discovery.
	IP   string
	Port int
	// Timeout is the deadline that elapsed.
	Timeout time.Duration
}

// EventName returns a short human-readable label.
func (ModuleTimeout) EventName() string { return "goscans: module timeout" }

// EventLevel returns the log severity.
func (ModuleTimeout) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ModuleTimeout) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("module", e.Module),
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.Duration("timeout", e.Timeout),
	}
}

// CollectionHealth reports a module that exhausted its execution deadline.
func (e ModuleTimeout) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeModuleFailed, Component: e.Module, Target: e.IP}, true
}

// ModuleFailed reports a module that returned a graceful upstream error status:
// the run completed, the payload is usable or empty, and the status says what went
// wrong. Exception distinguishes the harder case, where upstream flagged the whole
// payload as unusable, which is also how an upstream parsing failure arrives.
type ModuleFailed struct {
	event
	// Module is the failing module.
	Module string
	// IP and Port identify the job, Port being 0 for discovery.
	IP   string
	Port int
	// Status is the upstream status string, capped.
	Status string
	// Exception marks an upstream exception, meaning the result must be discarded.
	Exception bool
}

// EventName returns a short human-readable label.
func (ModuleFailed) EventName() string { return "goscans: module failed" }

// EventLevel returns the log severity.
func (ModuleFailed) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ModuleFailed) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("module", e.Module),
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("status", e.Status),
		slog.Bool("exception", e.Exception),
	}
}

// CollectionHealth reports a module whose result was incomplete or unusable.
func (e ModuleFailed) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeModuleFailed, Component: e.Module, Target: e.IP}, true
}

// Cancelled reports that the actor stopped because its context ended. Draining is
// set while the actor waits for an already-started module that cannot be
// interrupted, which is the honest cost of upstream discovery having no context.
type Cancelled struct {
	event
	// Phase names what was running when cancellation arrived.
	Phase string
	// IP is the target being worked on, when there was one.
	IP string
	// Draining marks the wait for an uninterruptible module to finish.
	Draining bool
	// Err is the context error.
	Err error
}

// EventName returns a short human-readable label.
func (Cancelled) EventName() string { return "goscans: cancelled" }

// EventLevel returns the log severity.
func (Cancelled) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e Cancelled) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("phase", e.Phase),
		slog.String("ip", e.IP),
		slog.Bool("draining", e.Draining),
		slog.Any("error", e.Err),
	}
}

// FilesystemError reports a failure in the actor-owned temporary tree. Every path
// this tool writes lives under one root it creates and removes itself.
type FilesystemError struct {
	event
	// Op names the operation, for example "create temp root".
	Op string
	// Path is the path involved.
	Path string
	// Err is the underlying error.
	Err error
}

// EventName returns a short human-readable label.
func (FilesystemError) EventName() string { return "goscans: filesystem error" }

// EventLevel returns the log severity.
func (FilesystemError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e FilesystemError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("op", e.Op),
		slog.String("path", e.Path),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports an actor-owned filesystem failure that prevented work.
func (e FilesystemError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: "goscans.runtime_failed", Component: e.Op}, true
}

// CleanupError reports temporary state that could not be removed. It is emitted
// and joined into the returned error rather than swallowed, because leftover scan
// files are a real defect even when the scan itself succeeded.
type CleanupError struct {
	event
	// Path is the path that could not be removed.
	Path string
	// Err is the underlying error.
	Err error
}

// EventName returns a short human-readable label.
func (CleanupError) EventName() string { return "goscans: cleanup error" }

// EventLevel returns the log severity.
func (CleanupError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e CleanupError) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("path", e.Path), slog.Any("error", e.Err)}
}

// UpstreamLog carries a diagnostic line the GoScans library wanted to log. It
// exists so upstream never needs a logger of its own: the message is capped, and
// upstream debug chatter is dropped rather than forwarded.
type UpstreamLog struct {
	event
	// Module is the module whose logger produced the line.
	Module string
	// IP and Port identify the job, when known.
	IP   string
	Port int
	// Level is the upstream severity, "info", "warning", or "error".
	Level string
	// Message is the capped, redacted log line.
	Message string
}

// EventName returns a short human-readable label.
func (UpstreamLog) EventName() string { return "goscans: upstream log" }

// EventLevel returns the log severity. Upstream warnings and errors are surfaced
// at their own level so a failing dependency is visible in the tool log.
func (e UpstreamLog) EventLevel() slog.Level {
	switch e.Level {
	case "error":
		return slog.LevelError
	case "warning":
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UpstreamLog) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("module", e.Module),
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("level", e.Level),
		slog.String("message", e.Message),
	}
}

var (
	_ tooleventlog.HealthEvent = ModuleSetupFailed{}
	_ tooleventlog.HealthEvent = ModuleTimeout{}
	_ tooleventlog.HealthEvent = ModuleFailed{}
	_ tooleventlog.HealthEvent = FilesystemError{}
)
