package entities

import "fmt"

// Service is an asset entity for an open port and the service answering on it.
// It is produced by the active phase, where Vanguard connects to a discovered
// IP rather than only observing it passively.
type Service struct {
	// IP is the address the service is bound to.
	IP string
	// Port is the TCP or UDP port number.
	Port int
	// Protocol is the transport, "tcp" or "udp".
	Protocol string
	// Name is the best-effort service name (for example "https").
	Name string
	// Product is the service product as fingerprinted by nmap (for example
	// "nginx"); empty when service detection did not run or could not identify it.
	Product string
	// Version is the product version as fingerprinted by nmap (for example
	// "1.25.3"); empty when unknown.
	Version string
	// ExtraInfo carries extra service detail from nmap (for example "Ubuntu").
	ExtraInfo string
	// CPEs holds the Common Platform Enumeration identifiers reported by nmap.
	CPEs []string
	// Banner is a truncated banner captured from the service, if any. It is the
	// first one observed, kept as the representative reading for a consumer that
	// wants one; Banners holds them all.
	Banner string
	// Banners are every banner reading collected from this service, ordered by
	// source then value. A banner is a sample of what the service said to one
	// probe at one moment, so several readings are several observations and not a
	// disagreement: a tool that sent an HTTP request and one that read the raw
	// socket are both right about what came back. Each carries the tool that read
	// it and when.
	Banners []FieldObservation
	// Conflicts records values a later source reported for a field that already
	// held a different non-empty value. The first value stays on the field and the
	// disagreement is kept here with its attribution: two tools disagreeing about a
	// product version is itself worth reporting, and silently keeping one of them
	// hides both the disagreement and the weaker tool. Banners are excluded, for
	// the reason on Banners. So are two service names that describe one protocol at
	// two layers ("http" against "https"), and names that identify nothing at all
	// ("tcpwrapped", "unknown"), since neither is a second claim to disagree with.
	Conflicts []FieldObservation
	// Scripts are host or service script results collected against this service,
	// ordered by script name. They are bounded evidence, not verdicts.
	Scripts []ServiceScript
	// TLS holds the TLS assessments of this service, one per assessed server name,
	// ordered by name. A TLS service with no assessment here was never assessed,
	// which is a coverage gap rather than a clean result.
	TLS []TlsAssessment
	// SSH is the algorithm offer of this service when it speaks SSH, nil otherwise.
	SSH *SshPosture
	// Provenance records the events that established facts about this service.
	Provenance []Provenance
}

// Service protocol values. ProtocolUnknown is not a transport: it marks a service
// whose reporter never named the transport it observed. It exists so an unreported
// transport stays visibly unreported instead of being read as tcp, which would let a
// passive observation of unclear transport key the same asset as a confirmed TCP
// service and satisfy rules that only hold for TCP.
const (
	ProtocolTCP     = "tcp"
	ProtocolUDP     = "udp"
	ProtocolUnknown = "unknown"
)

// NewService constructs a Service, enforcing a valid port range and a known
// transport protocol.
func NewService(ip string, port int, protocol string) (Service, error) {
	if port < 1 || port > 65535 {
		return Service{}, fmt.Errorf("service port out of range: %d", port)
	}
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return Service{}, fmt.Errorf("invalid service protocol %q: must be tcp or udp", protocol)
	}
	return Service{IP: ip, Port: port, Protocol: protocol}, nil
}
