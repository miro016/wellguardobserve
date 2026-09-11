package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// The UDP rules below all read one thing: a ServiceDiscovered whose transport is
// udp. That event is only ever raised for a UDP port that answered - a probe nmap
// sent and a reply that came back - so every finding here rests on a confirmed
// response from an in-scope host. A silent port is open|filtered and never becomes
// a service, so it never reaches these rules and cannot become a finding.
//
// What the rules deliberately do not do is turn a port number into a behavioural
// claim. A responding UDP/53 is an exposed DNS service; it is not an open resolver.
// A responding UDP/161 is an exposed SNMP agent; it is not a default community
// string. A responding UDP/123 is an exposed NTP service; it is not monlist and it
// carries no amplification factor. Each of those claims needs its own bounded
// protocol validator and its own collected event, which the finding
// backlog owns. Discovery evidence supports exposure, and the wording of every
// finding below stays inside what discovery actually saw.

// udpService returns the udp ServiceDiscovered behind an event, or ok=false for any
// other event and for a service on another transport. It is the single gate the UDP
// rules share, so none of them can accidentally fire on a TCP service.
func udpService(evt events.DomainEvent) (events.ServiceDiscovered, bool) {
	e, ok := evt.(events.ServiceDiscovered)
	if !ok {
		return events.ServiceDiscovered{}, false
	}
	if entities.NewServiceID(e.IP, e.Port, e.Protocol).Proto != entities.ProtocolUDP {
		return events.ServiceDiscovered{}, false
	}
	return e, true
}

// udpFinding builds the common shape of a UDP exposure finding: keyed on the udp
// service id so it can never collide with the TCP service on the same number, and
// carrying the observed service identity as evidence of what actually answered.
func udpFinding(e events.ServiceDiscovered, rule, title string, severity events.Severity,
	evidence, recommendation string, references []string) events.FindingRaised {
	sid := entities.NewServiceID(e.IP, e.Port, e.Protocol)
	f := events.FindingRaised{
		Rule:            rule,
		Title:           title,
		FindingCategory: string(entities.FindingExposure),
		AssetKind:       assetService,
		AssetID:         sid.String(),
		Evidence:        evidence,
		Recommendation:  recommendation,
		References:      references,
		Service:         events.ServiceFacet{Port: sid.Port, Proto: sid.Proto, Product: e.Product, Version: e.Version, CPEs: e.CPEs},
	}
	f.Severity = severity
	return f
}

// udpServiceIdentity renders what the pass observed on the port, for the evidence
// line. nmap's service detection often names nothing on UDP, and saying so is more
// honest than a finding that implies a fingerprint it never got.
func udpServiceIdentity(e events.ServiceDiscovered) string {
	switch {
	case e.Product != "" && e.Version != "":
		return fmt.Sprintf("%s %s", e.Product, e.Version)
	case e.Product != "":
		return e.Product
	case e.Service != "":
		return e.Service
	default:
		return "no service identity"
	}
}

// udpManagementPorts are management-plane protocols: the control surface of a
// device rather than one of its applications. Exposing one to the internet hands an
// attacker the administrative interface as a starting point.
var udpManagementPorts = map[int]string{
	161: "SNMP",
	162: "SNMP trap",
	623: "IPMI/RMCP",
}

// UDPManagementPlaneExposure raises a finding for a confirmed public UDP
// management-plane service. The claim is exposure of the management surface and
// nothing further: discovery proves the agent answered, not that it accepts a
// default community string, allows a write, or grants administration. Those need a
// behaviour validator with its own event.
func UDPManagementPlaneExposure(evt events.DomainEvent) []events.FindingRaised {
	e, ok := udpService(evt)
	if !ok {
		return nil
	}
	label, managed := udpManagementPorts[e.Port]
	if !managed {
		return nil
	}
	return []events.FindingRaised{udpFinding(e,
		"udp-management-plane-exposure",
		fmt.Sprintf("Management-plane service exposed over UDP: %s", label),
		events.SeverityHigh,
		fmt.Sprintf("%s answered a UDP probe on %s port %d (%s). The management plane of this device is reachable from where the scan ran. This is exposure of the control surface; it is not evidence that credentials, communities, or administrative operations were accepted.",
			label, e.IP, e.Port, udpServiceIdentity(e)),
		"Restrict the management plane to a management network or VPN; if it must stay reachable, require authentication and rotate any shared secrets.",
		[]string{cweExposedService})}
}

// udpReflectorPorts are protocols whose ordinary request/response shape is the one
// reflection abuse builds on: a small query from a spoofed source, a larger answer
// sent to the victim. Being on this list means the protocol is a candidate surface,
// not that this service amplifies anything.
var udpReflectorPorts = map[int]string{
	53:    "DNS",
	123:   "NTP",
	137:   "NetBIOS name service",
	161:   "SNMP",
	1900:  "SSDP",
	5353:  "mDNS",
	11211: "Memcached",
}

// UDPReflectorSurface raises a candidate finding for a confirmed public UDP service
// on a protocol commonly used for reflection. It is deliberately phrased as an
// exposed responding service: discovery sent one probe and got one reply, which
// proves the service answers unsolicited traffic from off-network. It does not
// measure a response-to-request ratio, does not test recursion, does not query a
// legacy administrative mode, and does not try a community string, so it claims
// none of those.
func UDPReflectorSurface(evt events.DomainEvent) []events.FindingRaised {
	e, ok := udpService(evt)
	if !ok {
		return nil
	}
	label, reflector := udpReflectorPorts[e.Port]
	if !reflector {
		return nil
	}
	return []events.FindingRaised{udpFinding(e,
		"public-udp-reflector-surface",
		fmt.Sprintf("Public UDP service on a reflection-capable protocol: %s", label),
		events.SeverityMedium,
		fmt.Sprintf("%s on %s port %d/udp (%s) replied to an unsolicited probe from outside its network. A connectionless service that answers strangers is the surface reflection attacks are launched from. Whether this service actually amplifies, recurses, or answers administrative queries was not tested and is not claimed here.",
			label, e.IP, e.Port, udpServiceIdentity(e)),
		"Confirm the service is meant to answer the public internet. If it is, restrict it to its intended clients, apply response rate limiting, and disable any query mode it does not need to serve.",
		[]string{"CWE-406"})}
}

// udpRemoteAccessPorts are the UDP endpoints of remote-access and VPN protocols.
// Unlike the TCP remote-access set (Telnet/RDP/VNC), a public VPN endpoint is
// frequently intentional, so this is edge inventory rather than a misconfiguration.
var udpRemoteAccessPorts = map[int]string{
	500:   "IKE (IPsec)",
	1194:  "OpenVPN",
	4500:  "IPsec NAT-T",
	51820: "WireGuard",
}

// UDPRemoteAccessSurface records a confirmed public UDP VPN or remote-access
// endpoint as edge exposure. It is low severity on purpose: a reachable VPN
// concentrator is usually meant to be reachable, and the value here is knowing the
// edge exists and which protocol terminates it. Nothing feeds this into a TCP
// validator - the existing service-auth-probe and open-data-check techniques gate
// on tcp, and a UDP-aware validator would need its own event and health contract.
func UDPRemoteAccessSurface(evt events.DomainEvent) []events.FindingRaised {
	e, ok := udpService(evt)
	if !ok {
		return nil
	}
	label, remote := udpRemoteAccessPorts[e.Port]
	if !remote {
		return nil
	}
	return []events.FindingRaised{udpFinding(e,
		"udp-remote-access-surface",
		fmt.Sprintf("Remote-access endpoint exposed over UDP: %s", label),
		events.SeverityLow,
		fmt.Sprintf("%s answered a UDP probe on %s port %d (%s), so a remote-access edge terminates here. This records the edge; it is not evidence of a weak configuration, a usable credential, or a reachable internal network.",
			label, e.IP, e.Port, udpServiceIdentity(e)),
		"Confirm this endpoint is an intended remote-access edge, that its software is current, and that it enforces multi-factor authentication.",
		[]string{cweExposedService})}
}
