package events

import (
	"strconv"
	"time"
)

var _ DomainEvent = IPAddressDiscovered{}
var _ DomainEvent = NetblockDiscovered{}
var _ DomainEvent = IPReachabilityObserved{}
var _ DomainEvent = HostOSGuessed{}

// Confidence values state whether an attribution was observed directly or
// inferred from a third party. They are stable event wire values interpreted by
// projections.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceInferred  = "inferred"
)

// Reachability-state values preserve the collector's concrete active-probe
// verdict in the event stream.
const (
	ReachabilityReachable             = "reachable"
	ReachabilityUnreachableIPv6       = "unreachable_ipv6_no_route"
	ReachabilityUnreachableNoResponse = "unreachable_no_response"
)

// IPAddressDiscovered signals an IP address was attributed to a domain, either by a
// direct DNS resolution (Source "dnsinfo") or by a third-party provider's assertion
// (Source "censys"/"shodan"/"netlas", via translate.ProviderIPAddresses) for a host
// the domain's own DNS never resolved. Both producers rejoin the same asset-graph
// node (Inventory.IPs): applyIPAddress keeps the strongest Confidence seen, so a
// provider-only sighting never wins over (or is lost to) a later DNS confirmation.
type IPAddressDiscovered struct {
	EventMeta
	// IP is the resolved or provider-attributed address (IPv4 or IPv6).
	IP string
	// Domain is the name attributed to this IP.
	Domain string
	// RecordType is "A" or "AAAA" for a DNS-resolved address, empty for a
	// provider-attributed one (it was not resolved from a DNS record).
	RecordType string
	// Confidence is "confirmed" for a DNS-resolved address and "inferred" for a
	// third-party assertion without independent resolution. Empty is treated as
	// confirmed by projections.
	Confidence string
}

// At returns the capture time recorded in the event envelope.
func (e IPAddressDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e IPAddressDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e IPAddressDiscovered) String() string {
	return "discovered IP " + e.IP + " for " + e.Domain
}

func (IPAddressDiscovered) isDomainEvent() {}

// NetblockDiscovered signals an IP belongs to a routed prefix / ASN.
type NetblockDiscovered struct {
	EventMeta
	// Prefix is the CIDR the IP falls within (for example "203.0.113.0/24").
	Prefix string
	// ASN is the autonomous system number announcing the prefix.
	ASN int
	// Name is the AS organisation name.
	Name string
	// Country is the registry country code.
	Country string
	// Registry is the RIR (for example "ARIN", "RIPE").
	Registry string
}

// At returns the capture time recorded in the event envelope.
func (e NetblockDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e NetblockDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e NetblockDiscovered) String() string {
	return "discovered netblock " + e.Prefix + " (AS" + strconv.Itoa(e.ASN) + ")"
}

func (NetblockDiscovered) isDomainEvent() {}

// IPReachabilityObserved signals that the active phase determined whether the
// scanner can reach an IP from its own network. It is emitted both when an active
// probe is gated on reachability (an IPv6-only address skipped because the scanner
// has no IPv6 route) and when a probed host answered nothing (down or filtered), so
// the IP asset carries an explicit reachability stamp rather than only an opaque
// coverage issue. A false Reachable is a coverage gap (the host was not usefully
// probed), not a clean negative result.
type IPReachabilityObserved struct {
	EventMeta
	// IP is the address whose reachability was determined.
	IP string
	// Reachable reports whether the scanner can route to IP. It is the boolean
	// summary of State; State carries the distinct unreachable cases apart.
	Reachable bool
	// State names which case produced an unreachable verdict
	// ("unreachable_ipv6_no_route"
	// vs "unreachable_no_response") so the projection records it without guessing from
	// the display-text Reason. "reachable" when Reachable is true.
	State string
	// Reason explains an unreachable verdict (for example "IPv6-only and the scanner
	// has no IPv6 route"). Display text only. Empty when reachable.
	Reason string
}

// At returns the capture time recorded in the event envelope.
func (e IPReachabilityObserved) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e IPReachabilityObserved) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e IPReachabilityObserved) String() string {
	if e.Reachable {
		return "IP " + e.IP + " reachable"
	}
	if e.Reason != "" {
		return "IP " + e.IP + " unreachable: " + e.Reason
	}
	return "IP " + e.IP + " unreachable"
}

func (IPReachabilityObserved) isDomainEvent() {}

// HostOSGuessed carries an inferred OS family for a host, derived by the active
// phase from nmap's per-service ostype hints (aggregated across the host's open
// ports). It is deliberately named a guess, not a fingerprint: the connect scan
// has no privileged -O OS detection, and naabu does not expose nmap's host OS
// match on its result path, so this is the best signal reachable - a weak one. It
// folds onto the IPAddress asset (OS) as an inferred OS family. It must
// be presented as inferred, never asserted. No accuracy is available here, so the
// event carries none; richer OS data needs a privileged scan (deferred).
type HostOSGuessed struct {
	EventMeta
	// IP is the address the OS guess is about.
	IP string
	// OS is the inferred OS family, for example "Linux" or "Windows".
	OS string
	// Method names how the guess was derived, for example "nmap service ostype".
	// It is named distinctly from the embedded EventMeta.Source (the producing
	// tool) to avoid a JSON key collision.
	Method string
}

// At returns the capture time recorded in the event envelope.
func (e HostOSGuessed) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e HostOSGuessed) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e HostOSGuessed) String() string {
	return "host " + e.IP + " OS guess: " + e.OS
}

func (HostOSGuessed) isDomainEvent() {}
