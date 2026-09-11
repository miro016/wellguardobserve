package entities

import (
	neturl "net/url"
	"strconv"
	"strings"
)

// ServiceID identifies a network service by host, port, and transport protocol. Its
// String is the canonical asset id ("host/port/proto") used everywhere a service is
// keyed, so the port scanner, the HTTP probe, and the inventory all resolve to one
// asset instead of the three incompatible schemes (ip:port, ip:port/proto, URL) that
// preceded it. The slash separators keep parsing unambiguous even for an IPv6 host
// (which carries colons but never a slash), which the old ":"-splitting could not.
type ServiceID struct {
	// Host is the IP (unbracketed) or FQDN the service is reached at.
	Host string
	// Port is the TCP/UDP port number.
	Port int
	// Proto is the transport, "tcp" or "udp".
	Proto string
}

// NewServiceID builds a canonical ServiceID: it strips IPv6 brackets from the host,
// lowercases the host and protocol, and defaults an empty protocol to tcp. It does
// not validate the port range; callers that need validation use [NewService].
func NewServiceID(host string, port int, proto string) ServiceID {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		proto = ProtocolTCP
	}
	return ServiceID{Host: strings.ToLower(host), Port: port, Proto: proto}
}

// ServiceIDFromURL derives the ServiceID of the socket a URL is served from: its
// host, its explicit port or the scheme default (443 for https, 80 for http), and
// tcp. ok is false when the URL has no host or no resolvable port, so the caller can
// fall back rather than key a finding on a bad id.
func ServiceIDFromURL(rawURL string) (ServiceID, bool) {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return ServiceID{}, false
	}
	port := 0
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return ServiceID{}, false
		}
	} else {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	if port < 1 || port > 65535 {
		return ServiceID{}, false
	}
	return NewServiceID(u.Hostname(), port, ProtocolTCP), true
}

// ParseServiceID parses a canonical "host/port/proto" service id. ok is false when
// the id is not in that form (for example a legacy ip:port or URL key), so a caller
// reading an untrusted id degrades rather than misparsing.
func ParseServiceID(id string) (ServiceID, bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || parts[0] == "" {
		return ServiceID{}, false
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		return ServiceID{}, false
	}
	return ServiceID{Host: parts[0], Port: port, Proto: parts[2]}, true
}

// String returns the canonical asset id, "host/port/proto".
func (s ServiceID) String() string {
	return s.Host + "/" + strconv.Itoa(s.Port) + "/" + s.Proto
}

// Host returns the service host of a service-kind asset, or "" for another kind or
// an id that is not a canonical service id.
func (a AssetRef) Host() string {
	return a.serviceID().Host
}

// Port returns the service port of a service-kind asset, or 0 for another kind or an
// id that is not a canonical service id. It replaces the string-surgery port parsing
// that the threat scenarios and other consumers each duplicated.
func (a AssetRef) Port() int {
	return a.serviceID().Port
}

// Proto returns the transport of a service-kind asset ("tcp", "udp", or "unknown"),
// or "" for another kind or an id that is not a canonical service id. A rule that
// models one transport - a TCP validator, a remote-access scenario, anything that
// dials - gates on it rather than assuming every service asset is TCP.
func (a AssetRef) Proto() string {
	return a.serviceID().Proto
}

// serviceID parses the asset id as a ServiceID when the asset is a service,
// returning the zero ServiceID (empty host, zero port) otherwise.
func (a AssetRef) serviceID() ServiceID {
	if a.Kind != AssetKindService {
		return ServiceID{}
	}
	s, _ := ParseServiceID(a.ID)
	return s
}
