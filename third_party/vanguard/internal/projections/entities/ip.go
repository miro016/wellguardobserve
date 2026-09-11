package entities

import (
	"fmt"
	"net"
)

// IPReachability records whether the active phase could reach an address from the
// scanner's network. It stays unknown until the active phase decides; the notable
// case is an IPv6-only address that a scanner with no IPv6 route cannot probe, so a
// "0 open ports" result would otherwise masquerade as a clean scan.
type IPReachability string

const (
	// ReachabilityUnknown means the active phase never determined reachability for
	// the address (no active phase ran, or it was never scheduled).
	ReachabilityUnknown IPReachability = ""
	// ReachabilityReachable means an active probe reached the address.
	ReachabilityReachable IPReachability = "reachable"
	// ReachabilityUnreachableIPv6 means the address is IPv6-only and the scanner has
	// no IPv6 route, so it was skipped rather than probed (a coverage gap).
	ReachabilityUnreachableIPv6 IPReachability = "unreachable_ipv6_no_route"
	// ReachabilityUnreachableNoResponse means the address was probed but answered no
	// TCP probe (every port timed out), so the host is down or filtered. The "0 open
	// ports" result is a coverage gap, not a clean scan. It is distinct from
	// ReachabilityUnreachableIPv6, which was never probed at all, so it must not be
	// counted as an IPv6 no-route gap.
	ReachabilityUnreachableNoResponse IPReachability = "unreachable_no_response"
)

// IPAddress is an asset entity for a single resolved IP address. It is the
// bridge between a domain (DNS) and infrastructure (netblock, ASN) and the
// target of the active phase.
type IPAddress struct {
	// Value is the address in its canonical string form.
	Value string
	// Version is the IP version: 4 or 6.
	Version int
	// Netblock is the CIDR prefix this address falls within, once known.
	Netblock string
	// ASN is the autonomous system announcing the address, once known.
	ASN int
	// Reachability records whether the active phase could reach this address.
	// Empty (ReachabilityUnknown) until the active phase decides.
	Reachability IPReachability
	// Confidence states how the address was established: ConfidenceConfirmed for an
	// address resolved directly from a DNS A/AAAA record (the only producer today),
	// or ConfidenceInferred for one asserted by a third party but not independently
	// resolved. Empty is treated as confirmed.
	Confidence Confidence
	// OS is a best-effort, inferred OS family for the host (for example "Linux" or
	// "Windows"). It is a guess derived from nmap service detection (per-service
	// ostype), not a confirmed fingerprint, so it must be presented as inferred,
	// never asserted. Empty when no service exposed an OS hint.
	OS string
	// Profile is the host-level evidence an active host scan gathered beside the
	// service list (names, other addresses, OS candidates, uptime, traceroute). Nil
	// when no scanner produced one. OS above stays the single derived guess the
	// asset graph reads; this is the evidence behind it.
	Profile *HostProfile
	// Provenance records the events that established facts about this address.
	Provenance []Provenance
}

// NewIPAddress constructs an IPAddress, enforcing that value is a valid IPv4 or
// IPv6 address and deriving the version from the parsed form.
func NewIPAddress(value string) (IPAddress, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return IPAddress{}, fmt.Errorf("invalid IP address: %q", value)
	}
	version := 6
	if ip.To4() != nil {
		version = 4
	}
	return IPAddress{Value: value, Version: version}, nil
}
