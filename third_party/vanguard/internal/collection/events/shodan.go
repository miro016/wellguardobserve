package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = ShodanHostsDiscovered{}

// ShodanHostsDiscovered signals that Shodan returned a set of indexed hosts (IPs
// with their observed services, routing, software, and known CVEs) for a domain.
// A host's services carry the transport Shodan observed them on, so tcp/53 and
// udp/53 stay two observations; a service whose transport Shodan did not report
// carries an empty one, meaning unknown rather than tcp. Like
// CensysExposure it is a facet of the owning Domain rather than a standalone
// asset: it is an independent passive view of the domain's host footprint, kept
// for cross-source coverage comparison against the DNS/ASN/portscan/censys data.
// Shodan's distinguishing value is the per-host vulnerability (CVE) data, which a
// detector turns into findings. Shodan reports an ASN without a routed prefix, so
// its routing data lives inside this facet and is not folded into the
// prefix-keyed Netblock asset model. An empty Hosts slice is not emitted; the
// orchestrator only translates a non-empty result.
type ShodanHostsDiscovered struct {
	EventMeta
	Domain    string
	Hosts     []valueobjects.ShodanHost
	Truncated bool
}

// At returns the capture time recorded in the event envelope.
func (e ShodanHostsDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ShodanHostsDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e ShodanHostsDiscovered) String() string {
	vulns := 0
	for i := range e.Hosts {
		vulns += len(e.Hosts[i].Vulns)
	}
	return fmt.Sprintf("discovered %d shodan host(s) for %s (%d known CVE(s))", len(e.Hosts), e.Domain, vulns)
}

func (ShodanHostsDiscovered) isDomainEvent() {}
