package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// NetlasExposure aggregates the host footprint Netlas indexed for a single Domain:
// the IPs, open ports, protocols, routing, software, JARM, and known
// vulnerabilities Netlas reports. Like CensysExposure and ShodanExposure it is a
// facet of the owning Domain rather than a standalone asset, and is an independent
// passive view kept for cross-source coverage comparison. Netlas reports an ASN
// without a routed prefix, so its routing data is held here and is not folded into
// the prefix-keyed Netblock asset model.
type NetlasExposure struct {
	// Hosts are the hosts Netlas returned for the domain, sorted by IP.
	Hosts []valueobjects.NetlasHost
	// Truncated is true when the result was capped at the configured host limit.
	Truncated bool
	// ResolvedAt is when the Netlas search was last run.
	ResolvedAt time.Time
}
