package valueobjects

// DnsDomainName represents a fully qualified domain name.
type DnsDomainName string

// String returns the string representation of the DNS domain name.
func (d DnsDomainName) String() string {
	return string(d)
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

// SOARecord holds the decoded fields from a start-of-authority record.
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
	Name  string
	Type  string
	Value string
	TTL   uint32
}
