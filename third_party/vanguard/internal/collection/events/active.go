package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = ServiceDiscovered{}
var _ DomainEvent = ActiveTargetApproved{}
var _ DomainEvent = HttpEndpointDiscovered{}
var _ DomainEvent = HttpRedirectObserved{}
var _ DomainEvent = TechnologyFingerprinted{}

// Service protocol values are the transports a collected service observation
// may assert. A missing or unknown transport does not identify a service asset.
const (
	ServiceProtocolTCP = "tcp"
	ServiceProtocolUDP = "udp"
)

// ActiveTargetKind identifies the normalized host kind admitted to target-facing
// traffic. The kind is persisted with the approval because a DNS name and an IP
// literal are authorized under different rules, and a reader of the stream has to be
// able to tell which rule admitted a destination.
type ActiveTargetKind string

const (
	// ActiveTargetDomain is a normalized DNS name approved at its discovery depth.
	ActiveTargetDomain ActiveTargetKind = "domain"
	// ActiveTargetIP is a canonical IP literal approved by the active host policy.
	ActiveTargetIP ActiveTargetKind = "ip"
)

// ActiveTargetApproved records the positive control decision made after scope,
// ownership, deduplication, and active-budget gates pass but before target-facing
// traffic starts. It is the canonical authorization record: the stream states what
// was allowed to receive traffic and why, separately from what was merely
// discovered, so an auditor can answer "why was this contacted" from the log alone.
// Discovery or asset presence is never an approval.
type ActiveTargetApproved struct {
	EventMeta
	// Target is the normalized DNS name or canonical IP literal admitted to traffic.
	Target string
	// Kind states whether Target is a domain or IP literal.
	Kind ActiveTargetKind
	// Depth is the domain discovery depth. It is -1 for IP targets.
	Depth int
	// AdmissionSource explains which scheduler or ownership decision admitted Target.
	AdmissionSource string
}

// At returns the capture time recorded in the event envelope.
func (e ActiveTargetApproved) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ActiveTargetApproved) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the approval decision.
func (e ActiveTargetApproved) String() string {
	return fmt.Sprintf("active %s target %s approved by %s", e.Kind, e.Target, e.AdmissionSource)
}

func (ActiveTargetApproved) isDomainEvent() {}

// ServiceDiscovered signals an open port and identified service on an IP. It is
// an active-phase event: producing it required connecting to the target. The
// service-identity fields (Product/Version/ExtraInfo/CPEs) are populated when
// nmap service detection runs behind the port scanner; they are empty otherwise.
type ServiceDiscovered struct {
	EventMeta
	IP        string
	Port      int
	Protocol  string // "tcp" or "udp"
	Service   string // best-effort name, for example "https"
	Product   string // service product as fingerprinted by nmap, e.g. "nginx"
	Version   string // product version as fingerprinted by nmap, e.g. "1.25.3"
	ExtraInfo string // extra service detail from nmap, e.g. "Ubuntu"
	// CPEs holds canonical CPE 2.3 formatted strings translated from nmap, for
	// example "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*".
	CPEs   []string
	Banner string // truncated banner if any
}

// At returns the capture time recorded in the event envelope.
func (e ServiceDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ServiceDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e ServiceDiscovered) String() string {
	name := e.Service
	if e.Product != "" {
		name = e.Product
		if e.Version != "" {
			name += " " + e.Version
		}
	}
	return fmt.Sprintf("open %s/%d (%s) on %s", e.Protocol, e.Port, name, e.IP)
}

func (ServiceDiscovered) isDomainEvent() {}

// HttpEndpointDiscovered signals an HTTP(S) endpoint responded.
type HttpEndpointDiscovered struct {
	EventMeta
	URL        string
	StatusCode int
	Title      string
	Server     string   // Server header
	Headers    []string // notable security headers present on the response
	// AuthType is the authentication surface observed on the response, classified
	// from data the probe already fetched: "basic", "digest", "bearer", "negotiate",
	// "ntlm", "form" (a login form), "protected" (a bare 401/403), or empty for none.
	AuthType string
	// AuthEvidence is the concrete observation behind AuthType (for example
	// "WWW-Authenticate: Basic" or "401 + login form"). Empty when AuthType is empty.
	AuthEvidence string
}

// At returns the capture time recorded in the event envelope.
func (e HttpEndpointDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e HttpEndpointDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e HttpEndpointDiscovered) String() string {
	return fmt.Sprintf("HTTP %d at %s", e.StatusCode, e.URL)
}

func (HttpEndpointDiscovered) isDomainEvent() {}

// HttpRedirectDisposition records whether Vanguard contacted the destination of
// an observed HTTP redirect.
type HttpRedirectDisposition string

const (
	// HttpRedirectFollowed means request policy allowed the destination and the
	// producing tool continued the redirect chain.
	HttpRedirectFollowed HttpRedirectDisposition = "followed"
	// HttpRedirectRejected means request policy rejected the destination before
	// the producing tool sent any traffic to it.
	HttpRedirectRejected HttpRedirectDisposition = "rejected"
)

// HttpRedirectObserved records one redirect response and the policy decision for
// its resolved destination. The event proves that FromURL responded; it does not
// claim that ToURL responded, including when Disposition is followed.
type HttpRedirectObserved struct {
	EventMeta
	// FromURL is the URL whose response supplied the Location header.
	FromURL string
	// ToURL is the absolute destination resolved against FromURL.
	ToURL string
	// StatusCode is the redirect response status returned by FromURL.
	StatusCode int
	// Hop is the one-based position in this request chain.
	Hop int
	// Disposition states whether the destination was followed or rejected.
	Disposition HttpRedirectDisposition
	// Reason is empty when followed and contains the policy reason when rejected.
	Reason string
}

// At returns the capture time recorded in the event envelope.
func (e HttpRedirectObserved) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e HttpRedirectObserved) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the redirect decision.
func (e HttpRedirectObserved) String() string {
	if e.Reason != "" {
		return fmt.Sprintf("HTTP %d redirect from %s to %s %s: %s", e.StatusCode, e.FromURL, e.ToURL, e.Disposition, e.Reason)
	}
	return fmt.Sprintf("HTTP %d redirect from %s to %s %s", e.StatusCode, e.FromURL, e.ToURL, e.Disposition)
}

func (HttpRedirectObserved) isDomainEvent() {}

// TechnologyFingerprinted signals a technology was identified on an endpoint.
// Several tools can report the same technology on the same URL with different
// depth of metadata, so projections merge entries by case-insensitive name and
// union the set fields rather than taking the first report.
type TechnologyFingerprinted struct {
	EventMeta
	URL        string
	Technology string // for example "nginx", "WordPress"
	Version    string // when detectable
	Evidence   string // header or body marker that matched
	// Categories are the fingerprint database's classifications of the
	// technology, for example "Web servers" or "CDN". Producers must sort and
	// dedup them so replay of the same observation is byte-identical. Empty when
	// the producing tool has no category data.
	Categories []string
	// CPEs are canonical CPE 2.3 formatted strings for technology, for example
	// "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*". Translator sorts and
	// deduplicates them. Empty when producing tool has no CPE data.
	CPEs []string
}

// At returns the capture time recorded in the event envelope.
func (e TechnologyFingerprinted) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e TechnologyFingerprinted) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e TechnologyFingerprinted) String() string {
	if e.Version != "" {
		return fmt.Sprintf("identified %s %s at %s", e.Technology, e.Version, e.URL)
	}
	return fmt.Sprintf("identified %s at %s", e.Technology, e.URL)
}

func (TechnologyFingerprinted) isDomainEvent() {}
