package valueobjects

import "time"

// CensysHost is a single host Censys associated with a domain, carrying the
// services, routing, geo, and OS data Censys reports together with the queries
// that matched it. Censys reports an ASN number/name but no routed CIDR prefix,
// so this data is kept inside the Censys facet rather than folded into the
// prefix-keyed Netblock asset model.
type CensysHost struct {
	// IP is the host address in canonical string form.
	IP string
	// Services are the network services Censys observed on the host.
	Services []CensysService
	// ASN is the autonomous system Censys attributes the host to, nil when absent.
	ASN *CensysASN
	// Location is the geographic location Censys reports, nil when absent.
	Location *CensysLocation
	// OS is the operating system product Censys fingerprinted, empty when absent.
	OS string
	// Products are the software product names Censys fingerprinted across the host's
	// services (sorted, deduplicated), like ShodanHost.Products and NetlasHost.Products.
	Products []string
	// Vulns are the CVE identifiers Censys attributes to the host's services (from
	// its exposures and compromises risk lists), sorted and deduplicated. Like the
	// shodan/netlas facets, a detector turns these into inferred findings and the
	// unified host view merges them across providers.
	Vulns []string
	// Reputation is the host-level threat verdict Censys reports (its reputation
	// score level: "malicious", "high_risk", "medium_risk", "low_risk", "benign"),
	// empty when absent. It is extracted from the same search hit at no extra cost;
	// a detector raises a finding when the verdict is risky.
	Reputation string
	// Labels are the surface descriptors Censys assigned to the host (for example
	// "login-page", "remote-access"), sorted and deduplicated, empty when none.
	Labels []string
	// Sources records which Censys queries matched this host: "dns", "tls_cert".
	Sources []string
	// NetworkAllocatedAt is the allocation/registration date of the host's routed network
	// as reported by Censys whois (whois.network.created), zero when absent. It is a genuine
	// real-world date, so the facts model dates the host's Provider at allocation rather than
	// only at the scan snapshot.
	NetworkAllocatedAt time.Time
	// NetworkCIDRs are the CIDR ranges of that network (whois.network.cidrs), retained so the
	// allocated netblock is identifiable; empty when absent.
	NetworkCIDRs []string
}

// CensysService is a single network service observed on a Censys host.
type CensysService struct {
	// Port is the service port number.
	Port int
	// Protocol is the application protocol (for example "HTTP", "HTTPS").
	Protocol string
	// Transport is the transport protocol (for example "tcp", "udp").
	Transport string
	// SourceObservedAt is Censys's scan_time for this service: when Censys last scanned it. It
	// is a provider-observation time (not a live confirmation), zero when Censys reported
	// none. The facts read model seeds the service's real-world seen-window from it.
	SourceObservedAt time.Time
}

// CensysASN holds the autonomous-system attribution Censys reports for a host.
type CensysASN struct {
	// Number is the autonomous system number.
	Number int
	// Name is the AS name.
	Name string
	// Description is the AS description / organisation.
	Description string
}

// CensysLocation holds the geographic location Censys reports for a host.
type CensysLocation struct {
	// Country is the country name.
	Country string
	// City is the city name.
	City string
}
