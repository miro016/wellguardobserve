package valueobjects

import "time"

// ShodanService is one service Shodan observed on a host: the port it answered on
// and the IP transport the banner was collected over. It is the unit Shodan
// reports, so it is the unit kept here: a port number alone cannot say whether
// tcp/53 or udp/53 was seen, and the two are different services.
type ShodanService struct {
	// Port is the port number the service answered on.
	Port int
	// Transport is the IP transport Shodan collected the banner over, normalized
	// to "tcp" or "udp". Empty means Shodan did not report one: that is unknown
	// transport, never an implied tcp. A well-known port number or an application
	// protocol is not transport evidence.
	Transport string
}

// ShodanHost is a single host Shodan indexed for a domain, aggregated from the
// per-service banners that matched. Shodan reports an ASN string but no routed
// CIDR prefix, so (like CensysHost) this data is held inside the Shodan facet
// rather than folded into the prefix-keyed Netblock asset model.
type ShodanHost struct {
	// IP is the host address in canonical string form.
	IP string
	// SourceObservedAt is the most recent banner timestamp Shodan reported across the host's
	// services: when Shodan last observed the host. It is a provider-observation time
	// (not a live confirmation and not asset death), zero when Shodan reported none. The
	// facts read model seeds the host's real-world seen-window from it.
	SourceObservedAt time.Time
	// Services are the services Shodan observed, sorted by port and then transport.
	// Two entries may share a port when Shodan saw both transports on it; they are
	// separate observations and are never merged.
	Services []ShodanService
	// ASN is the autonomous system Shodan attributes the host to (for example
	// "AS15169"), empty when absent.
	ASN string
	// Org is the organisation assigned the IP space, empty when absent.
	Org string
	// ISP is the ISP providing the IP space, empty when absent.
	ISP string
	// OS is the operating system Shodan fingerprinted, empty when absent.
	OS string
	// Hostnames are the names Shodan associates with the host.
	Hostnames []string
	// Tags are the characteristic tags Shodan assigned (for example "cloud", "cdn").
	Tags []string
	// Country is the host's country name, empty when absent.
	Country string
	// City is the host's city, empty when absent.
	City string
	// Products are the software products Shodan identified on the host's services.
	Products []string
	// Vulns are the CVE identifiers Shodan inferred for the host's services.
	Vulns []string
}
