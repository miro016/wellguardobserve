package dnsinfo

// Records holds all queried DNS record types for a domain.
type Records struct {
	// Domain is the queried domain (FQDN).
	Domain string
	// Resolver is the DNS server used.
	Resolver string
	A        []string
	AAAA     []string
	CNAME    []string
	MX       []MXRecord
	NS       []string
	TXT      []string
	PTR      []PTRRecord
	SOA      *SOARecord
	// DNSSEC is true when DNSKEY records are present.
	DNSSEC bool
}

// MXRecord describes one mail exchanger for a domain.
type MXRecord struct {
	Host     string
	Priority uint16
}

// PTRRecord describes one reverse-DNS result for an IP address.
type PTRRecord struct {
	IP       string
	Hostname string
}

// SOARecord holds the decoded fields from a Start Of Authority record.
type SOARecord struct {
	PrimaryNS  string
	AdminEmail string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinTTL     uint32
}

// ZoneRecord is a single DNS record from a zone transfer.
type ZoneRecord struct {
	// Name is the record owner name without trailing dot.
	Name string
	// Type is the record type string (e.g. "A", "MX").
	Type string
	// Value is the record rdata as a human-readable string.
	Value string
	// TTL is the time-to-live in seconds.
	TTL uint32
}
