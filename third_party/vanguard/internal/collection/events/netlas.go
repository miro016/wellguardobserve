package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = NetlasHostsDiscovered{}

// NetlasHostsDiscovered signals that Netlas returned a set of indexed hosts (IPs
// with their observed services, routing, software, JARM, and known CVEs) for a
// domain. Each service keeps its own application protocol; its transport is
// unknown, because a Netlas response document states none and an application
// protocol is not transport evidence. Like CensysExposure and ShodanExposure it is a facet of the owning
// Domain rather than a standalone asset: it is an independent passive view of the
// domain's host footprint, kept for cross-source coverage comparison against the
// DNS/ASN/portscan/censys/shodan data. Netlas reports an ASN without a routed
// prefix, so its routing data lives inside this facet and is not folded into the
// prefix-keyed Netblock asset model. Its CVE data, when present, drives a detector.
// An empty Hosts slice is not emitted; the orchestrator only translates a non-empty
// result.
type NetlasHostsDiscovered struct {
	EventMeta
	Domain    string
	Hosts     []valueobjects.NetlasHost
	Truncated bool
}

// At returns the capture time recorded in the event envelope.
func (e NetlasHostsDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e NetlasHostsDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e NetlasHostsDiscovered) String() string {
	vulns := 0
	for i := range e.Hosts {
		vulns += len(e.Hosts[i].Vulns)
	}
	return fmt.Sprintf("discovered %d netlas host(s) for %s (%d known CVE(s))", len(e.Hosts), e.Domain, vulns)
}

func (NetlasHostsDiscovered) isDomainEvent() {}
