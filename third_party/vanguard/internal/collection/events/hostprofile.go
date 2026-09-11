package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = HostProfileObserved{}

// HostProfileObserved carries the host-level evidence an active host scan gathered
// beside the service list: what the host calls itself, which other addresses
// answered for it, and the weak identity signals a scanner can infer without
// credentials. It is tool-neutral: any host scanner that learns these things
// reports them here, and two tools reporting the same host stay separate
// observations distinguished by Source and ToolCorrID.
//
// Every field is an inference of some strength, never an assertion. A projection
// must present them as such: OS candidates are ordered guesses, an uptime estimate
// is derived from TCP timestamps, and a reverse-DNS name is what the address owner
// chose to publish, not proof of ownership. This is deliberately not folded into
// HostOSGuessed: that event carries one derived OS family for the asset graph,
// while this one is the raw host evidence it and other guesses can be drawn from.
//
// Traceroute and uptime share this event rather than getting streams of their own.
// They are observed together, by the same probe, about the same asset, and no
// consumer reads one without the other; splitting them would create two events
// that must always be joined to be useful.
type HostProfileObserved struct {
	EventMeta
	// IP is the address the profile is about. It is the asset key: a profile is
	// always about one address, even when the host answers on several.
	IP string
	// DnsName is the name the scanner settled on for this host, from reverse DNS
	// and certificate names. It is a claim by the address owner, not confirmation
	// that the name resolves here; empty when none was found.
	DnsName string
	// OtherNames are the remaining names seen for the host, lowercased, sorted,
	// deduplicated, and capped by the producer.
	OtherNames []string
	// OtherIPs are further addresses attributed to the same host, sorted,
	// deduplicated, and capped by the producer.
	OtherIPs []string
	// MacAddress is only ever observable on the scanner's own layer-2 segment, so
	// it is empty for every routed target. A non-empty value means the scanner and
	// the target share a segment, which is itself worth knowing.
	MacAddress string
	// OSCandidates are the scanner's OS guesses in descending plausibility. Order
	// is significant and must be preserved; the list is capped by the producer.
	OSCandidates []string
	// OSFromService is an OS string a service reply named rather than a
	// fingerprint inferred, for example from an SMB response. It is kept apart
	// from OSCandidates because a service saying what it runs is stronger evidence
	// than a stack fingerprint.
	OSFromService string
	// LastBoot is the estimated boot time and Uptime the estimated uptime, both
	// zero when the scanner reported none. They are estimates from TCP timestamp
	// drift; treat them as approximate.
	LastBoot time.Time
	Uptime   time.Duration
	// DetectionReason is the scanner's stated reason for considering the host up,
	// for example "syn-ack". It separates a host that answered from one assumed up
	// because probing was skipped.
	DetectionReason string
	// TracerouteHops are the hops to the host in path order. Order is significant
	// and must be preserved; the list is capped by the producer.
	TracerouteHops []string
	// Truncated marks a profile whose lists hit a producer cap, so a short list is
	// never mistaken for a complete one.
	Truncated bool
}

// At returns the capture time recorded in the event envelope.
func (e HostProfileObserved) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e HostProfileObserved) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e HostProfileObserved) String() string {
	if e.DnsName != "" {
		return fmt.Sprintf("host profile for %s (%s)", e.IP, e.DnsName)
	}
	return fmt.Sprintf("host profile for %s", e.IP)
}

func (HostProfileObserved) isDomainEvent() {}
