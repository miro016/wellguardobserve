package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = DnsDomainNameDiscovered{}
var _ DomainEvent = DnsRecordsDiscovered{}
var _ DomainEvent = ZoneTransferDiscovered{}

// Discovery-source values classify how a domain entered the collected event
// stream. Projections interpret these stable wire values when materializing a
// domain entity.
const (
	DiscoverySourceCrtshSubdomain = "crtsh subdomain"
	DiscoverySourceCrtshCert      = "from crtsh cert"
	DiscoverySourceRoot           = "root domain"
	DiscoverySourceSubfinder      = "subfinder"
	DiscoverySourceVirustotal     = "virustotal"
	DiscoverySourceWebsearch      = "websearch"
	DiscoverySourceCertspotter    = "certspotter"
	DiscoverySourceCensys         = "censys"
)

// DnsDomainNameDiscovered signals that a domain was found during passive
// discovery.
type DnsDomainNameDiscovered struct {
	EventMeta
	Domain       string
	ParentDomain string
	Depth        int
	// DiscoverySource states how the domain was discovered, set by the producing
	// tool (for example "root domain", "crtsh subdomain", "from crtsh cert",
	// "subfinder"). It is named distinctly from the embedded EventMeta.Source (the
	// producing tool) to avoid a JSON key collision. Empty falls back to a heuristic
	// classification in the read model.
	DiscoverySource string
	// SourceObservedAt is the discovering source's point-in-time observation of this name
	// (VirusTotal reports a last_seen for each subdomain resolution). It is a
	// provider-observation timestamp, not a live confirmation, and is the zero time
	// when the source carries none (subfinder, crt.sh). The facts read model seeds the
	// name's real-world seen-window from it so a passively-known name lands on the
	// timeline at when it was actually seen rather than at scan time.
	SourceObservedAt time.Time
}

// At returns the capture time recorded in the event envelope.
func (e DnsDomainNameDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e DnsDomainNameDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e DnsDomainNameDiscovered) String() string {
	if e.ParentDomain == "" {
		return fmt.Sprintf("discovered domain %s (root)", e.Domain)
	}
	return fmt.Sprintf("discovered domain %s (parent: %s)", e.Domain, e.ParentDomain)
}

func (DnsDomainNameDiscovered) isDomainEvent() {}

// DnsRecordsDiscovered signals that DNS records for a domain were queried.
type DnsRecordsDiscovered struct {
	EventMeta
	Domain   string
	Resolver string
	A        []string
	AAAA     []string
	CNAME    []string
	MX       []valueobjects.MXRecord
	NS       []string
	TXT      []string
	PTR      []valueobjects.PTRRecord
	SOA      *valueobjects.SOARecord
	DNSSEC   bool
}

// At returns the capture time recorded in the event envelope.
func (e DnsRecordsDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e DnsRecordsDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e DnsRecordsDiscovered) String() string {
	return fmt.Sprintf("discovered DNS records for %s", e.Domain)
}

func (DnsRecordsDiscovered) isDomainEvent() {}

// ZoneTransferDiscovered signals that a zone transfer was successful.
type ZoneTransferDiscovered struct {
	EventMeta
	Domain     string
	Nameserver string
	Records    []valueobjects.ZoneRecord
}

// At returns the capture time recorded in the event envelope.
func (e ZoneTransferDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e ZoneTransferDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e ZoneTransferDiscovered) String() string {
	return fmt.Sprintf("discovered zone transfer for %s from %s", e.Domain, e.Nameserver)
}

func (ZoneTransferDiscovered) isDomainEvent() {}
