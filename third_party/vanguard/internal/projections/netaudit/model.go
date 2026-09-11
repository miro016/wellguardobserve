package netaudit

import "time"

// Status is the capture-health verdict for the collection's capture. It is explicit
// rather than an optional block: the report carries a network-audit section even
// when no capture exists, so a reader can never confuse "no capture" with "no
// violations".
type Status string

const (
	// StatusComplete means the capture parsed to EOF, overlaps the collection,
	// covered non-loopback traffic when active work ran, and reported no drops or
	// unsupported traffic the check needed. Only a complete capture may support a
	// zero-contact confirmation.
	StatusComplete Status = "complete"
	// StatusAbsent means no pcapng or pcap exists for the collection.
	StatusAbsent Status = "absent"
	// StatusUnreadable means the file exists but could not be opened or read.
	StatusUnreadable Status = "unreadable"
	// StatusParseFailed means header/block/packet decoding failed. The offset and a
	// safe error summary are retained.
	StatusParseFailed Status = "parse_failed"
	// StatusPartial means some positive packet evidence was decoded, but the file is
	// truncated, packets were dropped, link types were skipped, or metadata is
	// insufficient. Only positive evidence may be used from a partial capture.
	StatusPartial Status = "partial"
	// StatusCollectionMismatch means the capture times do not overlap the collection
	// or the collection named no configuration snapshot to assess the capture
	// against.
	StatusCollectionMismatch Status = "collection_mismatch"
)

// SupportsZeroContact reports whether a capture in this status may support a
// negative (zero-contact) exclusion conclusion. Only a complete capture does; a
// partial capture contributes positive evidence only, and the remaining statuses
// contribute nothing to a negative conclusion.
func (s Status) SupportsZeroContact() bool { return s == StatusComplete }

// Backend names the capture tool that produced a pcap.
type Backend string

const (
	// BackendPtcpdump is the eBPF, process-aware backend writing pcapng. Its process
	// attribution raises confidence when its metadata can be decoded.
	BackendPtcpdump Backend = "ptcpdump"
	// BackendTcpdump is the libpcap fallback writing classic pcap without process
	// attribution.
	BackendTcpdump Backend = "tcpdump"
	// BackendUnknown means the backend could not be determined from the meta sidecar
	// or the file format.
	BackendUnknown Backend = "unknown"
)

// Verdict is the exclusion-assessment result for one configured rule. Verdicts are
// conservative: negative conclusions require a complete capture, while positive
// packet evidence stands even from a partial capture.
type Verdict string

const (
	// VerdictViolationConfirmed means an outbound target-facing packet matched an
	// excluded CIDR, or a TLS SNI / plaintext HTTP Host directly matched an excluded
	// domain. Capture incompleteness does not weaken this.
	VerdictViolationConfirmed Verdict = "violation_confirmed"
	// VerdictViolationPossible means traffic correlates to an active/exploit
	// invocation and an excluded domain's DNS answer, but shared-IP or missing
	// application identity prevents direct hostname proof.
	VerdictViolationPossible Verdict = "violation_possible"
	// VerdictZeroContactCorroborated means a complete capture covers an exercised
	// rule, rejection events identify the denied target/rule, and no matching
	// outbound target conversation exists.
	VerdictZeroContactCorroborated Verdict = "zero_contact_corroborated"
	// VerdictNotExercised means the rule was configured but no rejection or relevant
	// candidate proves the run attempted to exercise it. This is not enforcement
	// confirmation.
	VerdictNotExercised Verdict = "not_exercised"
	// VerdictInconclusive means capture health, execution binding, parsing,
	// direction, or attribution was insufficient for the requested conclusion.
	// Event-only enforcement evidence remains visible.
	VerdictInconclusive Verdict = "inconclusive"
)

// RuleKind distinguishes a domain exclusion from an IP/CIDR exclusion.
type RuleKind string

const (
	// RuleDomain is a scope.domains.exclude entry: exact name plus subdomains.
	RuleDomain RuleKind = "domain"
	// RuleCIDR is a scope.ip_ranges.exclude entry: canonical CIDR containment.
	RuleCIDR RuleKind = "cidr"
)

// Model is the immutable network-audit evidence for one collection: its single
// capture set plus the rollup a reader scans first. It is the explicit input the
// pure report package renders; the report never re-reads a capture.
type Model struct {
	// Summary is the deterministic rollup of the capture below.
	Summary Summary `json:"summary"`
	// Capture is the audit of the collection's capture. It is always present, and
	// says so explicitly when no capture exists.
	Capture CaptureAudit `json:"capture"`
	// Notes are limitations or observations about the audit as a whole rather than
	// about the capture itself.
	Notes []string `json:"notes,omitempty"`
}

// Summary is the deterministic rollup the report's summary table renders.
type Summary struct {
	// CaptureStatus is the capture-health verdict, repeated here so the rollup is
	// readable on its own.
	CaptureStatus Status `json:"captureStatus"`
	Packets       int    `json:"packets"`

	ViolationsConfirmed int `json:"violationsConfirmed"`
	ViolationsPossible  int `json:"violationsPossible"`
	RulesCorroborated   int `json:"rulesCorroborated"`
	RulesNotExercised   int `json:"rulesNotExercised"`
	RulesInconclusive   int `json:"rulesInconclusive"`
}

// CaptureAudit is the complete network-audit record for the collection's capture.
type CaptureAudit struct {
	// Health is the capture-availability and quality record.
	Health CaptureHealth `json:"health"`
	// Traffic is a compact decoded-traffic overview: distinct peers, conversation
	// and app-layer counts, and the busiest destinations. It gives the section a
	// quick signal even when no exclusion rules are configured, and points a reader
	// at the raw netaudit projection for detail.
	Traffic TrafficSummary `json:"traffic"`
	// Rules is one assessment row per configured domain or CIDR exclusion, in stable
	// order.
	Rules []RuleAssessment `json:"rules"`
	// Violations is the compact confirmed/possible violation list, most severe
	// first.
	Violations []Violation `json:"violations,omitempty"`
	// UnmatchedRejections are the typed tool rejections whose denied destination
	// matched no configured rule. They are reported rather than
	// dropped so tool-side enforcement evidence is never silently lost.
	UnmatchedRejections []UnmatchedRejection `json:"unmatchedRejections,omitempty"`
	// Limitations names every condition that weakened or blocked a conclusion, so the
	// report can state them explicitly.
	Limitations []string `json:"limitations,omitempty"`
}

// CaptureHealth records everything a reader needs to judge whether packet absence
// is evidence for this collection's capture.
type CaptureHealth struct {
	Status  Status  `json:"status"`
	Backend Backend `json:"backend"`
	// RelPath is the capture path relative to the scan root, or empty when absent.
	RelPath string `json:"relPath,omitempty"`
	// SHA256 is the hex digest of the source capture bytes, empty when absent or
	// unreadable. It is the durability anchor: a later replay reproduces the same
	// evidence only against the same hash.
	SHA256 string `json:"sha256,omitempty"`
	// ByteSize is the capture file size in bytes.
	ByteSize int64 `json:"byteSize,omitempty"`
	// Start and Stop are the wrapper-recorded capture bracket, when known.
	Start time.Time `json:"start,omitempty"`
	Stop  time.Time `json:"stop,omitempty"`
	// PacketCount is the total decoded packets; RemotePackets and LoopbackPackets
	// split them by locality. A collection that ran active work and whose capture is
	// loopback-only is partial even when the pcapng structure is otherwise valid.
	PacketCount     int `json:"packetCount"`
	RemotePackets   int `json:"remotePackets"`
	LoopbackPackets int `json:"loopbackPackets"`
	// DroppedPackets is the interface-statistics drop count when the format reports
	// it. A non-zero value prevents a complete verdict.
	DroppedPackets int `json:"droppedPackets"`
	// DecodedLinkTypes and SkippedLinkTypes account for mixed link-layer decoding.
	DecodedLinkTypes []string `json:"decodedLinkTypes,omitempty"`
	SkippedLinkTypes []string `json:"skippedLinkTypes,omitempty"`
	// ProcessAttribution reports whether ptcpdump process identity could be decoded.
	ProcessAttribution bool `json:"processAttribution"`
	// ParseOffset and ParseError retain where and why decoding stopped, for a
	// truncated or malformed capture.
	ParseOffset int64  `json:"parseOffset,omitempty"`
	ParseError  string `json:"parseError,omitempty"`
	// Limitations are the capture-level reasons a negative conclusion is unsafe.
	Limitations []string `json:"limitations,omitempty"`
}

// TrafficSummary is a compact overview of the decoded traffic in one capture. It
// is not exclusion evidence; it orients an investigator and is deterministic.
type TrafficSummary struct {
	// RemotePeers is the count of distinct non-loopback peer addresses contacted.
	RemotePeers int `json:"remotePeers"`
	// Conversations is the count of deduplicated flows.
	Conversations int `json:"conversations"`
	// DNSQueries and DNSAnswers count the decoded DNS names and resolved answers.
	DNSQueries int `json:"dnsQueries"`
	DNSAnswers int `json:"dnsAnswers"`
	// TLSHandshakes and HTTPRequests count the SNI and plaintext HTTP Host
	// observations: the application-level targets the capture could attribute.
	TLSHandshakes int `json:"tlsHandshakes"`
	HTTPRequests  int `json:"httpRequests"`
	// TopDestinations is the busiest remote peers by packet count, most first, for a
	// quick orientation. Bounded to a handful of rows.
	TopDestinations []DestCount `json:"topDestinations,omitempty"`
}

// DestCount is one busy remote destination in a TrafficSummary.
type DestCount struct {
	Addr    string `json:"addr"`
	Packets int    `json:"packets"`
}

// RuleAssessment is the per-rule verdict: how the configured exclusion reconciled
// against the four evidence sources.
type RuleAssessment struct {
	Kind RuleKind `json:"kind"`
	// Rule is the normalized rule text (a domain name, or a canonical CIDR).
	Rule    string  `json:"rule"`
	Verdict Verdict `json:"verdict"`
	// ExclusionIssues is the count of domain exclusion IssueObserved rows that named
	// a target matched by this rule: the event-side enforcement evidence.
	ExclusionIssues int `json:"exclusionIssues"`
	// ToolRejections is the count of typed tool rejection spans matched to this rule.
	ToolRejections int `json:"toolRejections"`
	// PacketConversations is the count of distinct outbound conversations that
	// matched this rule (zero is the corroborating case for a complete capture).
	PacketConversations int `json:"packetConversations"`
	// Detail is a short human-readable reconciliation note.
	Detail string `json:"detail,omitempty"`
}

// Violation is one confirmed or possible exclusion breach, summarizing a single
// outbound conversation. Replies and retransmissions never create extra rows.
type Violation struct {
	Rule    string   `json:"rule"`
	Kind    RuleKind `json:"kind"`
	Verdict Verdict  `json:"verdict"`
	// Destination is the excluded address or hostname the conversation reached.
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port,omitempty"`
	// Attribution is the ptcpdump process or correlated tool identity, empty when
	// unavailable.
	Attribution string    `json:"attribution,omitempty"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	Packets     int       `json:"packets"`
	// Confidence restates the verdict as a short confidence word for the compact
	// table: "confirmed" or "possible".
	Confidence string `json:"confidence"`
}
