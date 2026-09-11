package entities

import (
	"fmt"
	"net"
)

// Netblock is an asset entity for a routed BGP prefix and its owning ASN. It
// groups IP addresses by the infrastructure that announces them.
type Netblock struct {
	// Prefix is the CIDR the netblock covers (for example "203.0.113.0/24").
	Prefix string
	// ASN is the autonomous system number announcing the prefix.
	ASN int
	// Name is the AS organisation name.
	Name string
	// Country is the registry country code.
	Country string
	// Registry is the RIR (for example "ARIN", "RIPE").
	Registry string
	// Provenance records the events that established facts about this netblock.
	Provenance []Provenance
}

// NewNetblock constructs a Netblock, enforcing that prefix is a valid CIDR.
func NewNetblock(prefix string) (Netblock, error) {
	if _, _, err := net.ParseCIDR(prefix); err != nil {
		return Netblock{}, fmt.Errorf("invalid CIDR prefix %q: %w", prefix, err)
	}
	return Netblock{Prefix: prefix}, nil
}
