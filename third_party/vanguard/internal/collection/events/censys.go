package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = CensysHostsDiscovered{}

// CensysHostsDiscovered signals that Censys associated a set of hosts (IPs with
// their services, ASN, location, OS, software products, known CVEs, and a threat
// reputation) with a domain. Like MailSecurity and BreachExposure it is a facet of
// the owning Domain rather than a standalone asset: it is an independent passive
// view of the domain's host footprint, kept for cross-source coverage comparison
// against the DNS/ASN/portscan data. Like the shodan/netlas facets it carries
// per-host CVE data (from Censys's exposures/compromises), which a detector turns
// into findings and the unified host view merges across providers; it additionally
// carries the host-level reputation verdict and labels Censys already includes in a
// search hit, which the reputation detector flags when risky. Censys reports an ASN
// without a routed prefix, so its routing/geo/OS data lives inside this facet and is
// not folded into the prefix-keyed Netblock asset model. An empty Hosts slice is not
// emitted; the orchestrator only translates a non-empty result.
type CensysHostsDiscovered struct {
	EventMeta
	Domain    string
	Hosts     []valueobjects.CensysHost
	Truncated bool
}

// At returns the capture time recorded in the event envelope.
func (e CensysHostsDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e CensysHostsDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e CensysHostsDiscovered) String() string {
	vulns := 0
	for i := range e.Hosts {
		vulns += len(e.Hosts[i].Vulns)
	}
	return fmt.Sprintf("discovered %d censys host(s) for %s (%d known CVE(s))", len(e.Hosts), e.Domain, vulns)
}

func (CensysHostsDiscovered) isDomainEvent() {}
