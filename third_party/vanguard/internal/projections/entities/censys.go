package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// CensysExposure aggregates the host footprint Censys attributes to a single
// Domain: the IPs, services, ASN, location, OS, software products, known CVEs, and
// the host-level reputation verdict and labels Censys reports. Like MailSecurity and
// BreachExposure it is a facet of the owning Domain rather than a standalone asset,
// and is an independent passive view kept for cross-source coverage comparison
// against the DNS/ASN/portscan data. Its per-host CVEs join the shodan/netlas CVEs in
// the unified host view, and a detector flags a risky reputation. Censys reports an
// ASN without a routed prefix, so its routing/geo/OS data is held here and is not
// folded into the prefix-keyed Netblock asset model.
type CensysExposure struct {
	// Hosts are the hosts Censys associated with the domain, sorted by IP.
	Hosts []valueobjects.CensysHost
	// Truncated is true when the result was capped at the configured host limit.
	Truncated bool
	// ResolvedAt is when the Censys search was last run.
	ResolvedAt time.Time
}
