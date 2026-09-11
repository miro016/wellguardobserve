package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// ShodanExposure aggregates the host footprint Shodan indexed for a single
// Domain: the IPs, open ports, routing, software, and known vulnerabilities
// Shodan reports. Like CensysExposure it is a facet of the owning Domain rather
// than a standalone asset, and is an independent passive view kept for
// cross-source coverage comparison. Shodan reports an ASN without a routed
// prefix, so its routing data is held here and is not folded into the
// prefix-keyed Netblock asset model.
type ShodanExposure struct {
	// Hosts are the hosts Shodan returned for the domain, sorted by IP.
	Hosts []valueobjects.ShodanHost
	// Truncated is true when the result was capped at the configured host limit.
	Truncated bool
	// ResolvedAt is when the Shodan search was last run.
	ResolvedAt time.Time
}
