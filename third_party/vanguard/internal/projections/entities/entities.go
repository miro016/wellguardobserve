package entities

import (
	"fmt"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Certificate represents a TLS certificate discovered via certificate transparency logs.
// Fields are a subset of what crt.sh returns, normalized for display purposes.
type Certificate struct {
	// CommonName is the primary domain the certificate was issued for.
	CommonName string
	// IssuerName is the distinguished name of the issuing CA.
	IssuerName string
	// SerialNumber is the unique serial assigned by the CA.
	SerialNumber string
	// ValidFrom is the start of the certificate validity window.
	ValidFrom time.Time
	// ValidUntil is the end of the certificate validity window (expiry).
	ValidUntil time.Time
	// LoggedAt is when a historical registry accepted the certificate record.
	LoggedAt time.Time
	// LiveVerifiedAt is when Vanguard directly observed this certificate being served.
	LiveVerifiedAt time.Time
	// Domains holds all DNS names from CN and SAN fields (deduplicated, normalized).
	Domains []string
	// Provenance records the events that established facts about this certificate.
	Provenance []Provenance
}

// NewCertificate constructs a Certificate, enforcing that the serial number and
// common name are non-empty and copying the domains slice defensively.
func NewCertificate(commonName, issuerName, serialNumber string, validFrom, validUntil, loggedAt, liveVerifiedAt time.Time, domains []string) (Certificate, error) {
	if serialNumber == "" {
		return Certificate{}, fmt.Errorf("certificate serial number must not be empty")
	}
	if commonName == "" {
		return Certificate{}, fmt.Errorf("certificate common name must not be empty")
	}
	return Certificate{
		CommonName:     commonName,
		IssuerName:     issuerName,
		SerialNumber:   serialNumber,
		ValidFrom:      validFrom,
		ValidUntil:     validUntil,
		LoggedAt:       loggedAt,
		LiveVerifiedAt: liveVerifiedAt,
		Domains:        append([]string(nil), domains...),
	}, nil
}

// DiscoverySource indicates how a domain was discovered.
type DiscoverySource string

const (
	// SourceCrtshSubdomain indicates the domain was found as a subdomain pattern.
	SourceCrtshSubdomain DiscoverySource = "crtsh subdomain"
	// SourceCrtshCert indicates the domain was found inside a certificate SAN or CN.
	SourceCrtshCert DiscoverySource = "from crtsh cert"
	// SourceRoot indicates this is the initial root domain.
	SourceRoot DiscoverySource = "root domain"
	// SourceSubfinder indicates the domain was found by subfinder passive
	// enumeration (aggregating many third-party passive DNS sources).
	SourceSubfinder DiscoverySource = "subfinder"
	// SourceVirustotal indicates the domain was found by VirusTotal subdomain
	// enumeration.
	SourceVirustotal DiscoverySource = "virustotal"
	// SourceWebsearch indicates the host was found in a web-search (Google dork)
	// result for the root domain.
	SourceWebsearch DiscoverySource = "websearch"
	// SourceCertspotter indicates the domain was found by the certspotter second
	// Certificate Transparency source (the crt.sh coverage corroborator).
	SourceCertspotter DiscoverySource = "certspotter"
	// SourceCensys indicates the domain was found by the censys certificate index,
	// the independent CT-history source that backfills a degraded crt.sh empty.
	SourceCensys DiscoverySource = "censys"
	// SourceHTTPRedirect indicates the name first appeared as a host referenced by
	// an HTTP redirect. It does not imply the destination was contacted.
	SourceHTTPRedirect DiscoverySource = "http redirect"
)

// Domain represents a unique domain name discovered during crawling.
// A domain may appear across multiple certificates; this struct tracks
// when it was first seen and which parent domain triggered its discovery.
type Domain struct {
	// Name is the fully-qualified domain name (lowercased, no trailing dot).
	Name string
	// ParentDomain is the domain that led to this one being discovered.
	// Empty if this is the root domain.
	ParentDomain string
	// Depth is the crawl depth at which this domain was found (0 = root).
	Depth int
	// Source indicates how this domain was discovered (e.g. "crtsh subdomain" or "from crtsh cert").
	Source DiscoverySource
	// DiscoveredAt is the time this domain was first seen.
	DiscoveredAt time.Time
	// DNS holds the DNS records resolved for this domain.
	// It is nil until the domain has been resolved.
	DNS *DnsInfo
	// Registration holds the WHOIS/RDAP registration data for this domain.
	// It is nil until a registration lookup has succeeded.
	Registration *Registration
	// MailSecurity holds the email-authentication posture (SPF/DMARC/DKIM/BIMI)
	// for this domain. It is nil until a mail security lookup has succeeded.
	MailSecurity *MailSecurity
	// BreachExposure holds the email aliases on this domain found in known data
	// breaches. It is nil until a breach lookup has succeeded.
	BreachExposure *BreachExposure
	// CensysExposure holds the host footprint Censys attributes to this domain.
	// It is nil until a Censys search has succeeded.
	CensysExposure *CensysExposure
	// ShodanExposure holds the host footprint Shodan indexed for this domain.
	// It is nil until a Shodan search has succeeded.
	ShodanExposure *ShodanExposure
	// NetlasExposure holds the host footprint Netlas indexed for this domain.
	// It is nil until a Netlas search has succeeded.
	NetlasExposure *NetlasExposure
	// Reputation holds the threat-intelligence VirusTotal reports for this domain.
	// It is nil until a VirusTotal lookup has succeeded.
	Reputation *Reputation
	// WebAssets holds the URLs a web-search (Google dork) pass surfaced for this
	// domain. It is nil until a web-search pass has succeeded.
	WebAssets *WebAssets
	// TlsPosture holds the active TLS-negotiation posture (supported versions and
	// HSTS) for this domain. It is nil until an HTTPS probe has succeeded.
	TlsPosture *TlsPosture
	// AuthSurface holds the authentication surfaces an active web probe observed on
	// this domain (login form, WWW-Authenticate challenge, 401/403). It is nil until
	// a probe observed one.
	AuthSurface *AuthSurface
	// MxTls holds the active SMTP STARTTLS posture of this domain's MX hosts. It
	// is nil until an SMTP probe has succeeded.
	MxTls *MxTls
	// Provenance records the events that established facts about this domain.
	Provenance []Provenance
}

// NewDomain constructs a Domain, normalizing the name (lowercase, no "*." prefix
// or trailing dot) and enforcing that the normalized name is non-empty, free of
// whitespace and path separators, and that depth is not negative.
func NewDomain(name, parent string, depth int, source DiscoverySource, discoveredAt time.Time) (Domain, error) {
	if depth < 0 {
		return Domain{}, fmt.Errorf("domain depth must not be negative")
	}
	normalized := normalizeName(name)
	if normalized == "" {
		return Domain{}, fmt.Errorf("domain name must not be empty or malformed: %q", name)
	}
	return Domain{
		Name:         normalized,
		ParentDomain: normalizeName(parent),
		Depth:        depth,
		Source:       source,
		DiscoveredAt: discoveredAt,
	}, nil
}

// normalizeName lowercases and trims a domain name, strips a leading wildcard
// label and a trailing dot, and returns "" for empty names or names containing
// whitespace or path separators. It mirrors the crawler's normalizeDomain rule.
func normalizeName(s string) string {
	str := strings.TrimSpace(strings.ToLower(s))
	if str == "" {
		return ""
	}
	str = strings.TrimPrefix(str, "*.")
	str = strings.TrimSuffix(str, ".")
	if strings.ContainsAny(str, " \t\r\n/\\") {
		return ""
	}
	return str
}

// DnsInfo aggregates all DNS findings for a single Domain.
//
// It unifies what were previously separate discoveries (a DNS resolution pass
// and an optional zone transfer) into the owning Domain entity, so every DNS
// fact about a name lives in one place. In the reconnaissance lifecycle this is
// the passive DNS enumeration step: it maps a domain to the addresses, mail and
// name servers, and other records that define its attack surface.
type DnsInfo struct {
	// Resolver is the DNS server that answered the records.
	Resolver string
	// A holds IPv4 addresses the domain resolves to.
	A []string
	// AAAA holds IPv6 addresses the domain resolves to.
	AAAA []string
	// CNAME holds canonical-name aliases for the domain.
	CNAME []string
	// MX holds mail exchanger records.
	MX []valueobjects.MXRecord
	// NS holds the authoritative name servers for the domain.
	NS []string
	// TXT holds free-form text records (SPF, verification tokens, and similar).
	TXT []string
	// PTR holds reverse-DNS results for the domain's addresses.
	PTR []valueobjects.PTRRecord
	// SOA holds the start-of-authority record, nil if none was returned.
	SOA *valueobjects.SOARecord
	// DNSSEC indicates whether the domain is DNSSEC-signed.
	DNSSEC bool
	// ZoneNameserver is the name server that permitted a zone transfer (AXFR).
	// Empty when no zone transfer succeeded.
	ZoneNameserver string
	// ZoneTransfer holds records leaked by a successful zone transfer.
	// Nil when no zone transfer succeeded; a populated slice is a finding in
	// itself, since open AXFR exposes the full zone.
	ZoneTransfer []valueobjects.ZoneRecord
	// ResolvedAt is when the records were last resolved.
	ResolvedAt time.Time
}

// Registration aggregates the WHOIS/RDAP registration facts for a single Domain.
//
// Registration data describes ownership and lifecycle of a name (registrar,
// creation/expiry dates, contacts) rather than where it resolves, so it lives
// alongside DnsInfo on the owning Domain. In the reconnaissance lifecycle this
// is the passive registration-data step.
type Registration struct {
	// DataSource records which leg produced the data ("whois" or "rdap"). The
	// whois tool falls back from port-43 WHOIS to RDAP, and the two sources can
	// disagree, so the answering source is kept for comparison.
	DataSource string
	// Registrar is the sponsoring registrar's name.
	Registrar string
	// WhoisServer is the WHOIS server that answered, when known.
	WhoisServer string
	// Status holds the EPP domain status codes (e.g. clientTransferProhibited).
	Status []string
	// CreatedDate is when the domain was first registered.
	CreatedDate time.Time
	// UpdatedDate is when the registration was last changed.
	UpdatedDate time.Time
	// ExpiryDate is when the registration expires.
	ExpiryDate time.Time
	// Nameservers holds the authoritative name servers from registration data.
	// These can be compared against DnsInfo.NS to spot drift.
	Nameservers []string
	// DNSSEC indicates whether registration data reports the domain as signed.
	DNSSEC bool
	// Contacts holds the registrant, administrative, and technical contacts.
	Contacts []valueobjects.RegistrationContact
	// ResolvedAt is when the registration data was last gathered.
	ResolvedAt time.Time
}
