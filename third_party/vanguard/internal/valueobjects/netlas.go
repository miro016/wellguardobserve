package valueobjects

import "time"

// NetlasService is one service Netlas observed on a host. Netlas indexes one scan
// document per service, so port, transport, and application protocol belong to
// that one service rather than to three host-wide lists that cannot be joined
// back together.
type NetlasService struct {
	// Port is the port number the service answered on.
	Port int
	// Transport is the IP transport, normalized to "tcp" or "udp". Empty means
	// Netlas did not report one for this service: that is unknown transport, never
	// an implied tcp. ApplicationProtocol is not transport evidence, and neither is
	// the port number.
	Transport string
	// ApplicationProtocol is the application protocol Netlas identified (for
	// example "http", "https", "ssh"), empty when absent. It says what was spoken,
	// not what carried it.
	ApplicationProtocol string
}

// NetlasHost is a single host Netlas indexed for a domain, aggregated from the
// per-service scan documents that matched. Netlas reports an ASN string but no
// routed CIDR prefix, so (like CensysHost and ShodanHost) this data is held inside
// the Netlas facet rather than folded into the prefix-keyed Netblock asset model.
type NetlasHost struct {
	// IP is the host address in canonical string form.
	IP string
	// SourceObservedAt is the most recent @timestamp across the host's scan documents (when
	// Netlas indexed them, normally close to scan time). It is a provider-observation
	// time (not a live confirmation), zero when Netlas reported none. The facts read
	// model seeds the host's real-world seen-window from it.
	SourceObservedAt time.Time
	// Services are the services Netlas observed, sorted by port, then transport,
	// then application protocol. Two entries may share a port; they are separate
	// observations and are never merged.
	Services []NetlasService
	// ASN is the autonomous system Netlas attributes the host to (for example
	// "AS15169"), empty when absent.
	ASN string
	// Org is the organisation Netlas attributes the AS to, empty when absent.
	Org string
	// ISP is the ISP providing the IP space, empty when absent.
	ISP string
	// Hostnames are the names Netlas associates with the host.
	Hostnames []string
	// Country is the host's country, empty when absent.
	Country string
	// City is the host's city, empty when absent.
	City string
	// JARM is the JARM TLS fingerprint Netlas computed, empty when absent.
	JARM string
	// Products are the software products Netlas identified on the host's services.
	Products []string
	// Vulns are the CVE identifiers Netlas associated with the host's services.
	Vulns []string
}
