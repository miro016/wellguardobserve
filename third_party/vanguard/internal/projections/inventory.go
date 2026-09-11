package projections

import (
	"net"
	neturl "net/url"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Inventory is a graph read model of all discovered assets for one scan. Nodes
// are keyed by their natural identity for O(1) upsert and dedup; edges are slices
// of those keys, kept unique. Every upsert also accumulates provenance on the
// underlying entity, so the graph records how each node was established.
type Inventory struct {
	// Domains keyed by FQDN.
	Domains map[string]*DomainNode
	// IPs keyed by address.
	IPs map[string]*IPNode
	// Netblocks keyed by CIDR prefix.
	Netblocks map[string]*NetblockNode
	// Certificates keyed by serial number.
	Certificates map[string]*CertNode
	// Services keyed by canonical ServiceID ("host/port/proto").
	Services map[string]*ServiceNode
	// Endpoints keyed by URL (active-phase HTTP(S) endpoints).
	Endpoints map[string]*EndpointNode

	// ipByEventID maps an IPAddressDiscovered EventID to its IP address, so a
	// NetblockDiscovered (which carries only the EventID of the IP that caused it)
	// can be linked back to the right IP node.
	ipByEventID map[string]string
}

// DomainNode is a domain and its edges to IPs, certificates, and subdomains.
type DomainNode struct {
	entities.Domain
	// ReferencedOnly is true when the name is known only from a redirect Location
	// and no event has independently observed or contacted it.
	ReferencedOnly bool
	// IPs are the addresses this name resolves to: DNS-confirmed A/AAAA answers
	// (Confidence confirmed). A graph walk that means "resolves to" crosses only
	// these edges, so a scenario never narrates a passive association as a resolution.
	IPs []string
	// AssociatedIPs are addresses a passive source (censys/shodan reverse links, cert
	// SANs, historical records) attributes to this name without a DNS answer -
	// inferred only. They are queryable breadth for a "seen near this host" question,
	// but the name does not resolve to them, so they stay off the IPs (resolved) edge
	// and disjoint from it. A confirmed answer for the same address promotes it to IPs.
	AssociatedIPs []string
	// CertSerials are the serials of certificates that cover this name.
	CertSerials []string
	// Children are subdomains discovered with this name as their parent.
	Children []string
}

// IPNode is an IP address and its edges to domains, its netblock, and services.
type IPNode struct {
	entities.IPAddress
	// ReferencedOnly is true when the address is known only from a redirect
	// Location and no event has independently observed or contacted it.
	ReferencedOnly bool
	// Domains are the names that resolve to this address.
	Domains []string
	// Netblock is the CIDR prefix this address belongs to.
	Netblock string
	// Services are the canonical ServiceID keys ("host/port/proto") open on this
	// address.
	Services []string
	// AuthSurface is a login/admin surface observed directly on this address - an
	// endpoint probed on a bare IP, with no domain node to attach to. It is nil when
	// none was observed. The graph resolves a domain's auth surface through its IPs,
	// so an IP-hosted surface still reaches the credential paths.
	AuthSurface *entities.AuthSurface
	// LiveTLS records that a completed https response was observed on this address (a
	// bare-IP endpoint), so it is serving live TLS. The graph resolves a name's
	// liveness through its IPs, so a cert served on a bare IP still counts as live.
	LiveTLS bool
	// HostIntel is provider-asserted intelligence (CVEs and tags) a passive source
	// attributes to this address, distilled from the per-host Shodan/Censys/Netlas
	// exposure so scenarios can chain it. Nil when none was
	// reported. It is inferred and never outranks a directly observed finding.
	HostIntel *entities.HostIntel
	// Scripts are host-scope script results (an nmap NSE host script) collected
	// against this address, ordered by script name. Port-scope scripts attach to
	// their service instead.
	Scripts []entities.ServiceScript
}

// NetblockNode is a netblock and the IPs that fall within it.
type NetblockNode struct {
	entities.Netblock
	// IPs are the addresses observed within this prefix.
	IPs []string
}

// CertNode is a certificate and the domains it covers.
type CertNode struct {
	entities.Certificate
	// Domains are the names covered by this certificate (CN and SANs).
	Domains []string
}

// ServiceNode is a discovered service.
type ServiceNode struct {
	entities.Service
}

// EndpointNode is an active-phase HTTP(S) endpoint and the technologies
// fingerprinted on it. Endpoints are a read-model node (no entity type): they are
// observations about a URL, linked to the IP/service that served them via lineage.
type EndpointNode struct {
	// URL is the endpoint address and the node key.
	URL string
	// StatusCode is the HTTP status the endpoint returned.
	StatusCode int
	// Title is the page title, when parsed.
	Title string
	// Server is the Server response header, when present.
	Server string
	// Headers lists notable security headers observed on the response.
	Headers []string
	// AuthType is the authentication surface observed on the endpoint ("basic",
	// "form", "protected", ...), empty when none. AuthEvidence is its observation.
	AuthType     string
	AuthEvidence string
	// Technologies are the stacks fingerprinted on this endpoint.
	Technologies []TechFinding
	// Redirects are the policy decisions for redirect responses returned by this
	// endpoint. A destination listed here is not itself an endpoint observation.
	Redirects []HTTPRedirect
	// Provenance records the events that established facts about this endpoint.
	Provenance []entities.Provenance
}

// HTTPRedirect is one redirect adjacency retained on the endpoint whose response
// supplied the Location header.
type HTTPRedirect struct {
	// EventID identifies the redirect observation and keeps corroborating tools distinct.
	EventID string
	// FromURL and ToURL retain the normalized URL evidence for the hop.
	FromURL string
	ToURL   string
	// FromHost and ToHost are normalized DNS names or canonical IP literals.
	FromHost string
	ToHost   string
	// StatusCode is the 3xx response status returned by FromURL.
	StatusCode int
	// Hop is the one-based position in the request chain.
	Hop int
	// Disposition states whether ToURL was followed or rejected.
	Disposition events.HttpRedirectDisposition
	// Reason explains a rejected destination and is empty when followed.
	Reason string
	// Source is the tool that observed the redirect.
	Source string
	// CapturedAt is when the source response was observed.
	CapturedAt time.Time
}

// TechFinding is one technology fingerprinted on an endpoint, merged across every
// tool that reported it: names match case-insensitively, an unversioned report folds
// into a versioned one, and the metadata sets accumulate.
type TechFinding struct {
	// Technology is the identified stack (for example "nginx", "WordPress"), in the
	// casing of the first tool that reported it.
	Technology string
	// Version is the detected version, when known. Two distinct non-empty versions
	// of the same technology stay separate findings: a page can load two versions
	// of the same library.
	Version string
	// Evidence is the header or body marker that matched, from the first report.
	Evidence string
	// Categories are the fingerprint classifications ("Web servers", "CDN", ...),
	// sorted, deduped, and unioned across reports.
	Categories []string
	// CPEs are Common Platform Enumeration identifiers, sorted, deduped, and
	// unioned across reports.
	CPEs []string
	// Sources are the tools that reported this technology, sorted and deduped.
	Sources []string
}

// NewInventory returns an Inventory with initialised maps.
func NewInventory() Inventory {
	var inv Inventory
	inv.ensureInit()
	return inv
}

func (inv *Inventory) ensureInit() {
	if inv.Domains == nil {
		inv.Domains = make(map[string]*DomainNode)
	}
	if inv.IPs == nil {
		inv.IPs = make(map[string]*IPNode)
	}
	if inv.Netblocks == nil {
		inv.Netblocks = make(map[string]*NetblockNode)
	}
	if inv.Certificates == nil {
		inv.Certificates = make(map[string]*CertNode)
	}
	if inv.Services == nil {
		inv.Services = make(map[string]*ServiceNode)
	}
	if inv.Endpoints == nil {
		inv.Endpoints = make(map[string]*EndpointNode)
	}
	if inv.ipByEventID == nil {
		inv.ipByEventID = make(map[string]string)
	}
}

// Apply upserts the nodes and edges implied by evt. It is idempotent: applying
// the same event again does not duplicate nodes, edges, or provenance.
func (inv *Inventory) Apply(evt events.DomainEvent) {
	inv.ensureInit()
	// Fold on the value form the orchestrator emits live; a replayed (or test-built)
	// pointer of the same event is normalized to that form first, so live and replay
	// fold identically instead of one falling through the type switch (see
	// events.AsValue).
	evt = events.AsValue(evt)
	switch e := evt.(type) {
	case events.DnsDomainNameDiscovered:
		inv.applyDomainName(e)
	case events.CertificateDiscovered:
		inv.applyCertificate(e)
	case events.DnsRecordsDiscovered:
		inv.applyDNSRecords(e)
	case events.ZoneTransferDiscovered:
		inv.applyZoneTransfer(e)
	case events.DomainRegistrationDiscovered:
		inv.applyRegistration(e)
	case events.MailSecurityDiscovered:
		inv.applyMailSecurity(e)
	case events.BreachDataDiscovered:
		inv.applyBreachData(e)
	case events.CensysHostsDiscovered:
		inv.applyCensysHosts(e)
	case events.ShodanHostsDiscovered:
		inv.applyShodanHosts(e)
	case events.NetlasHostsDiscovered:
		inv.applyNetlasHosts(e)
	case events.DomainReputationDiscovered:
		inv.applyReputation(e)
	case events.WebAssetsDiscovered:
		inv.applyWebAssets(e)
	case events.TlsPostureDiscovered:
		inv.applyTlsPosture(e)
	case events.MxTlsDiscovered:
		inv.applyMxTls(e)
	default:
		// Infrastructure / active-phase facets (IP, reachability, netblock, service,
		// endpoint, technology) are dispatched separately to keep this switch's
		// cyclomatic complexity bounded. evt is already value-normalized above.
		inv.applyInfra(evt)
	}
}

// applyInfra folds the infrastructure and active-phase events (the IP/netblock/
// service/endpoint graph) into the inventory. It is the second half of Apply,
// split out so neither type switch grows unbounded.
func (inv *Inventory) applyInfra(evt events.DomainEvent) {
	switch e := evt.(type) {
	case events.IPAddressDiscovered:
		inv.applyIPAddress(e)
	case events.IPReachabilityObserved:
		inv.applyIPReachability(e)
	case events.HostOSGuessed:
		inv.applyHostOSGuess(e)
	case events.NetblockDiscovered:
		inv.applyNetblock(e)
	case events.ServiceDiscovered:
		inv.applyService(e)
	case events.HttpEndpointDiscovered:
		inv.applyEndpoint(e)
	case events.HttpRedirectObserved:
		inv.applyHTTPRedirect(e)
	case events.TechnologyFingerprinted:
		inv.applyTechnology(e)
	case events.HostProfileObserved:
		inv.applyHostProfile(e)
	case events.ServiceScriptObserved:
		inv.applyServiceScript(e)
	case events.TlsSecurityAssessed:
		inv.applyTLSSecurity(e)
	case events.SshPostureDiscovered:
		inv.applySSHPosture(e)
	}
}

func (inv *Inventory) applyDomainName(e events.DnsDomainNameDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.ReferencedOnly = false

	// Prefer the discovery source the producing tool stamped on the event; fall
	// back to the parent-linkage heuristic for events that predate the field.
	// Build through the invariant-enforcing constructor so parent/depth/source are
	// normalized; the crawler already normalizes names, so an error is a defensive
	// fallback rather than the common path. The node key stays the event's name.
	source := entities.DiscoverySource(e.DiscoverySource)
	if source == "" {
		source = domainSource(e)
	}
	d, err := entities.NewDomain(e.Domain, e.ParentDomain, e.Depth, source, e.At())
	if err != nil {
		d = entities.Domain{ParentDomain: e.ParentDomain, Depth: e.Depth, Source: source, DiscoveredAt: e.At()}
	}
	node.ParentDomain = d.ParentDomain
	node.Depth = d.Depth
	node.Source = d.Source
	if node.DiscoveredAt.IsZero() {
		node.DiscoveredAt = d.DiscoveredAt
	}
	inv.addProvenance(&node.Provenance, e.Meta())

	if e.ParentDomain != "" {
		parent := inv.ensureDomainNode(e.ParentDomain)
		parent.Children = appendUnique(parent.Children, e.Domain)
	}
}

func (inv *Inventory) applyCertificate(e events.CertificateDiscovered) {
	// Canonical serial so a live and a CT observation of the same certificate dedup to one
	// node (and one CertSerials entry) instead of splitting on serial case / leading zero.
	serial := valueobjects.CanonicalCertSerial(e.Certificate.SerialNumber)
	if serial == "" {
		return
	}
	certNode := inv.ensureCertNode(e)
	inv.addProvenance(&certNode.Provenance, e.Meta())

	for _, name := range coveredNames(e.Certificate) {
		certNode.Domains = appendUnique(certNode.Domains, name)
		// A wildcard SAN (*.example.com) is certificate data, not a resolvable host:
		// it stays on the cert's Domains list (above) but gets no domain node, so it
		// does not inflate the domain inventory or the "unresolved" progress count.
		if isWildcardName(name) {
			continue
		}
		dNode := inv.ensureDomainNode(name)
		dNode.CertSerials = appendUnique(dNode.CertSerials, serial)
	}
}

func (inv *Inventory) applyIPAddress(e events.IPAddressDiscovered) {
	ipNode := inv.ensureIPNode(e.IP)
	ipNode.ReferencedOnly = false
	inv.addProvenance(&ipNode.Provenance, e.Meta())
	inv.ipByEventID[e.Meta().EventID] = e.IP
	// Keep the strongest confidence seen for the address: a directly resolved
	// (confirmed) sighting never downgrades to a third party's inferred one.
	conf := confidenceOrConfirmed(e.Confidence)
	ipNode.Confidence = ipNode.Confidence.Stronger(conf)

	if e.Domain != "" {
		dNode := inv.ensureDomainNode(e.Domain)
		// Split the domain -> IP edge by the sighting's confidence so a walk that
		// means "resolves to" crosses only DNS-confirmed answers. A confirmed sighting
		// owns the resolved edge and is promoted off the associated set if a passive
		// source listed the address first; an inferred-only sighting stays associated
		// breadth. The two sets are kept disjoint and the fold is order-independent.
		if conf == entities.ConfidenceConfirmed {
			dNode.IPs = appendUnique(dNode.IPs, e.IP)
			dNode.AssociatedIPs = removeString(dNode.AssociatedIPs, e.IP)
		} else if !containsString(dNode.IPs, e.IP) {
			dNode.AssociatedIPs = appendUnique(dNode.AssociatedIPs, e.IP)
		}
		ipNode.Domains = appendUnique(ipNode.Domains, e.Domain)
	}
}

func (inv *Inventory) applyIPReachability(e events.IPReachabilityObserved) {
	ipNode := inv.ensureIPNode(e.IP)
	inv.addProvenance(&ipNode.Provenance, e.Meta())
	// Copy the verdict the orchestrator stamped explicitly. The unreachable cases are
	// distinct - an IPv6 no-route skip (never probed) versus a probed host that
	// answered nothing (down or filtered) - so the projection must not collapse them
	// by inferring from the Reachable bool. The Reason string differs per case but is
	// display text, not a safe discriminator.
	ipNode.Reachability = entities.IPReachability(e.State)
}

func (inv *Inventory) applyHostOSGuess(e events.HostOSGuessed) {
	ipNode := inv.ensureIPNode(e.IP)
	inv.addProvenance(&ipNode.Provenance, e.Meta())
	ipNode.OS = e.OS
}

func (inv *Inventory) applyNetblock(e events.NetblockDiscovered) {
	nbNode := inv.ensureNetblockNode(e)
	inv.addProvenance(&nbNode.Provenance, e.Meta())

	// Link the netblock to the IP that caused its lookup, via the causation ID.
	ip, ok := inv.ipByEventID[e.Meta().CausationID]
	if !ok {
		return
	}
	ipNode := inv.ensureIPNode(ip)
	ipNode.Netblock = e.Prefix
	ipNode.ASN = e.ASN
	nbNode.IPs = appendUnique(nbNode.IPs, ip)
}

// applyService folds one service observation. Several tools probe the same port and
// each sees part of the picture: one fingerprints the product, another catches the
// banner, a third names the service. So a repeat observation is merged rather than
// discarded - an empty field is filled from the later evidence, and a field that
// already holds a different non-empty value keeps it and records the disagreement,
// because two tools disagreeing about a version is itself a fact worth reporting.
func (inv *Inventory) applyService(e events.ServiceDiscovered) {
	key := serviceKey(e.IP, e.Port, e.Protocol)
	svcNode, ok := inv.Services[key]
	if !ok {
		svc, err := entities.NewService(e.IP, e.Port, e.Protocol)
		if err != nil {
			return
		}
		svcNode = &ServiceNode{Service: svc}
		inv.Services[key] = svcNode
	}
	mergeServiceIdentity(&svcNode.Service, e)
	inv.addProvenance(&svcNode.Provenance, e.Meta())

	ipNode := inv.ensureIPNode(e.IP)
	ipNode.Services = appendUnique(ipNode.Services, key)
}

// applyDNSRecords folds a DNS resolution into the owning domain node, so a name
// and its records are read as one asset. DNS records can arrive before (or
// without) the DnsDomainNameDiscovered event, so the node is created on demand.
func (inv *Inventory) applyDNSRecords(e events.DnsRecordsDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	if node.DNS == nil {
		node.DNS = &entities.DnsInfo{}
	}
	node.DNS.Resolver = e.Resolver
	node.DNS.A = append([]string(nil), e.A...)
	node.DNS.AAAA = append([]string(nil), e.AAAA...)
	node.DNS.CNAME = append([]string(nil), e.CNAME...)
	node.DNS.MX = append([]valueobjects.MXRecord(nil), e.MX...)
	node.DNS.NS = append([]string(nil), e.NS...)
	node.DNS.TXT = append([]string(nil), e.TXT...)
	node.DNS.PTR = append([]valueobjects.PTRRecord(nil), e.PTR...)
	node.DNS.SOA = e.SOA
	node.DNS.DNSSEC = e.DNSSEC
	node.DNS.ResolvedAt = e.At()
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyZoneTransfer(e events.ZoneTransferDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	if node.DNS == nil {
		node.DNS = &entities.DnsInfo{}
	}
	node.DNS.ZoneNameserver = e.Nameserver
	node.DNS.ZoneTransfer = append([]valueobjects.ZoneRecord(nil), e.Records...)
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyRegistration(e events.DomainRegistrationDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.Registration = &entities.Registration{
		DataSource:  e.DataSource,
		Registrar:   e.Registrar,
		WhoisServer: e.WhoisServer,
		Status:      append([]string(nil), e.Status...),
		CreatedDate: e.CreatedDate,
		UpdatedDate: e.UpdatedDate,
		ExpiryDate:  e.ExpiryDate,
		Nameservers: append([]string(nil), e.Nameservers...),
		DNSSEC:      e.DNSSEC,
		Contacts:    append([]valueobjects.RegistrationContact(nil), e.Contacts...),
		ResolvedAt:  e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyMailSecurity(e events.MailSecurityDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.MailSecurity = &entities.MailSecurity{
		SPF:           e.SPF,
		SPFAnalysis:   e.SPFAnalysis,
		DMARC:         e.DMARC,
		DMARCSeverity: e.DMARCSeverity,
		DKIM:          append([]valueobjects.DKIMRecord(nil), e.DKIM...),
		BIMI:          e.BIMI,
		ResolvedAt:    e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyBreachData(e events.BreachDataDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.BreachExposure = &entities.BreachExposure{
		Aliases:    append([]valueobjects.BreachedAlias(nil), e.Breaches...),
		ResolvedAt: e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyCensysHosts(e events.CensysHostsDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.CensysExposure = &entities.CensysExposure{
		Hosts:      append([]valueobjects.CensysHost(nil), e.Hosts...),
		Truncated:  e.Truncated,
		ResolvedAt: e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
	for i := range e.Hosts {
		h := &e.Hosts[i]
		inv.addHostIntel(h.IP, h.Vulns, h.Labels, "censys", latestCensysSourceObservation(h.Services))
	}
}

func (inv *Inventory) applyShodanHosts(e events.ShodanHostsDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.ShodanExposure = &entities.ShodanExposure{
		Hosts:      append([]valueobjects.ShodanHost(nil), e.Hosts...),
		Truncated:  e.Truncated,
		ResolvedAt: e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
	for i := range e.Hosts {
		h := &e.Hosts[i]
		inv.addHostIntel(h.IP, h.Vulns, h.Tags, "shodan", h.SourceObservedAt)
	}
}

func (inv *Inventory) applyNetlasHosts(e events.NetlasHostsDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.NetlasExposure = &entities.NetlasExposure{
		Hosts:      append([]valueobjects.NetlasHost(nil), e.Hosts...),
		Truncated:  e.Truncated,
		ResolvedAt: e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
	for i := range e.Hosts {
		h := &e.Hosts[i]
		inv.addHostIntel(h.IP, h.Vulns, nil, "netlas", h.SourceObservedAt)
	}
}

// addHostIntel distils a provider's per-host CVEs and tags onto the IP asset's
// HostIntel facet (creating the IP node on demand), so intel reported against a bare
// address becomes queryable and chainable rather than only display data hanging off
// the queried domain. It merges across providers and passes, keeping the fold
// idempotent on replay. A host with neither CVEs nor tags contributes nothing.
func (inv *Inventory) addHostIntel(ip string, cves, tags []string, source string, sourceObservedAt time.Time) {
	if ip == "" || (len(cves) == 0 && len(tags) == 0) {
		return
	}
	node := inv.ensureIPNode(ip)
	if node.HostIntel == nil {
		node.HostIntel = &entities.HostIntel{}
	}
	hi := node.HostIntel
	hi.CVEs = mergeUniqueSorted(hi.CVEs, cves)
	hi.Tags = mergeUniqueSorted(hi.Tags, tags)
	hi.Sources = mergeUniqueSorted(hi.Sources, []string{source})
	if sourceObservedAt.After(hi.SourceObservedAt) {
		hi.SourceObservedAt = sourceObservedAt
	}
}

// latestCensysSourceObservation returns the newest provider scan_time carried by
// a host's services. Zero means Censys supplied no source observation timestamp.
func latestCensysSourceObservation(services []valueobjects.CensysService) time.Time {
	var latest time.Time
	for _, service := range services {
		if service.SourceObservedAt.After(latest) {
			latest = service.SourceObservedAt
		}
	}
	return latest
}

// mergeUniqueSorted returns the sorted set union of base and extra, dropping empties.
func mergeUniqueSorted(base, extra []string) []string {
	for _, v := range extra {
		if v != "" {
			base = appendUnique(base, v)
		}
	}
	sort.Strings(base)
	return base
}

func (inv *Inventory) applyReputation(e events.DomainReputationDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.Reputation = &entities.Reputation{
		Score:           e.Reputation,
		Malicious:       e.Malicious,
		Suspicious:      e.Suspicious,
		Harmless:        e.Harmless,
		Undetected:      e.Undetected,
		Categories:      append([]valueobjects.ReputationCategory(nil), e.Categories...),
		Tags:            append([]string(nil), e.Tags...),
		PopularityRanks: append([]valueobjects.PopularityRank(nil), e.PopularityRanks...),
		JARM:            e.JARM,
		Registrar:       e.Registrar,
		ResolvedAt:      e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
}

// applyWebAssets attaches each dork hit to the node for the host it actually
// lives on, rather than folding every hit onto the queried root. An in-scope host
// (the root or a subdomain of it) gets the hit on its own node, so a subdomain's
// exposure is judged against the subdomain. An out-of-scope host (a third-party
// site that surfaced in the results) is recorded on the root node's flagged
// OutOfScope bucket, so its exposure is not attributed to the target. Hits dedup
// by URL, keeping the fold idempotent across replays and accumulating across passes.
func (inv *Inventory) applyWebAssets(e events.WebAssetsDiscovered) {
	at := e.At()
	for i := range e.Assets {
		a := e.Assets[i]
		host := a.Host
		if host == "" {
			host = e.Domain
		}
		if hostInScope(host, e.Domain) {
			node := inv.ensureDomainNode(host)
			node.WebAssets = ensureWebAssets(node.WebAssets, at)
			node.WebAssets.Assets = appendWebAssetUnique(node.WebAssets.Assets, a)
			inv.addProvenance(&node.Provenance, e.Meta())
			continue
		}
		root := inv.ensureDomainNode(e.Domain)
		root.WebAssets = ensureWebAssets(root.WebAssets, at)
		root.WebAssets.OutOfScope = appendWebAssetUnique(root.WebAssets.OutOfScope, a)
		inv.addProvenance(&root.Provenance, e.Meta())
	}
}

// ensureWebAssets returns w, allocating it when nil, and advances ResolvedAt to
// the latest pass time so the fold is order-independent on replay.
func ensureWebAssets(w *entities.WebAssets, at time.Time) *entities.WebAssets {
	if w == nil {
		w = &entities.WebAssets{ResolvedAt: at}
	}
	if at.After(w.ResolvedAt) {
		w.ResolvedAt = at
	}
	return w
}

// appendWebAssetUnique appends a to s unless a hit with the same URL is already
// present, so a replayed event or an overlapping pass does not duplicate it.
func appendWebAssetUnique(s []valueobjects.WebAsset, a valueobjects.WebAsset) []valueobjects.WebAsset {
	for _, existing := range s {
		if existing.URL == a.URL {
			return s
		}
	}
	return append(s, a)
}

// confidenceOrConfirmed maps an event's plain-string confidence to the typed
// entities.Confidence, defaulting an empty value to confirmed.
func confidenceOrConfirmed(s string) entities.Confidence {
	if s == "" {
		return entities.ConfidenceConfirmed
	}
	return entities.Confidence(s)
}

// hostFromURL returns the lowercased hostname of a URL (no port, IPv6 brackets
// stripped), or "" when it cannot be parsed. It links an endpoint back to its
// domain node.
func hostFromURL(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// normalizeRedirectURL canonicalizes the scheme and host used as inventory keys
// while retaining path and query evidence. Invalid, relative, or non-HTTP URLs
// return an empty string and are not materialized.
func normalizeRedirectURL(rawURL string) string {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	host := hostFromURL(rawURL)
	if host == "" {
		return ""
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	return u.String()
}

// hostInScope reports whether host is the queried root or a subdomain of it. It
// mirrors the orchestrator's in-scope host test; the small duplication keeps this
// package free of an orchestration import.
func hostInScope(host, root string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	root = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(root), "."))
	if root == "" {
		return false
	}
	return host == root || strings.HasSuffix(host, "."+root)
}

func (inv *Inventory) applyTlsPosture(e events.TlsPostureDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.TlsPosture = &entities.TlsPosture{
		RemoteAddr:   e.RemoteAddr,
		Reachable:    e.Reachable,
		Versions:     append([]valueobjects.TlsVersion(nil), e.Versions...),
		HSTS:         e.HSTS,
		ChainState:   entities.AssessmentState(e.ChainState),
		ChainTrusted: e.ChainTrusted,
		ChainError:   e.ChainError,
		ResolvedAt:   e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyMxTls(e events.MxTlsDiscovered) {
	node := inv.ensureDomainNode(e.Domain)
	node.MxTls = &entities.MxTls{
		Hosts:      append([]valueobjects.MxTlsHost(nil), e.Hosts...),
		ResolvedAt: e.At(),
	}
	inv.addProvenance(&node.Provenance, e.Meta())
}

func (inv *Inventory) applyEndpoint(e events.HttpEndpointDiscovered) {
	node := inv.ensureEndpointNode(e.URL)
	node.StatusCode = e.StatusCode
	node.Title = e.Title
	node.Server = e.Server
	node.Headers = append([]string(nil), e.Headers...)
	node.AuthType = e.AuthType
	node.AuthEvidence = e.AuthEvidence
	inv.addProvenance(&node.Provenance, e.Meta())

	host := hostFromURL(e.URL)
	isIP := net.ParseIP(host) != nil
	var dNode *DomainNode
	isDomain := host != "" && !isIP
	if isDomain {
		dNode = inv.ensureDomainNode(host)
		dNode.ReferencedOnly = false
		inv.addProvenance(&dNode.Provenance, e.Meta())
	} else if isIP {
		ipNode := inv.ensureIPNode(host)
		ipNode.ReferencedOnly = false
		inv.addProvenance(&ipNode.Provenance, e.Meta())
	}

	// A completed https response is a live-TLS observation on the host. It folds onto
	// the IP node for a bare-IP endpoint, so the graph resolves a name's liveness
	// through the addresses it is served from (the same domain -> IP walk the auth
	// surface uses). A domain-hosted endpoint's liveness is already carried by the
	// domain's TlsPosture facet from the dedicated https probe.
	if isIP && e.StatusCode > 0 && isHTTPSURL(e.URL) {
		ipNode := inv.ensureIPNode(host)
		ipNode.LiveTLS = true
		inv.addProvenance(&ipNode.Provenance, e.Meta())
	}

	// An observed auth surface folds onto the asset that actually carries it, so risk
	// criticality and the credential paths react to a confirmed login surface, not
	// only a dork-inferred one. A domain-hosted endpoint folds onto its domain node; an
	// endpoint probed on a bare IP has no domain, so it folds onto the IP node instead
	// of being dropped - the graph resolves a domain's surface through its IPs.
	if e.AuthType == "" {
		return
	}
	switch {
	case isDomain:
		addAuthSurface(&dNode.AuthSurface, e)
	case isIP:
		ipNode := inv.ensureIPNode(host)
		addAuthSurface(&ipNode.AuthSurface, e)
		inv.addProvenance(&ipNode.Provenance, e.Meta())
	}
}

// applyHTTPRedirect materializes the responding URL and both host assets, then
// records the redirect adjacency on the responding endpoint. ToURL never becomes
// an EndpointNode from redirect evidence alone.
func (inv *Inventory) applyHTTPRedirect(e events.HttpRedirectObserved) {
	fromURL := normalizeRedirectURL(e.FromURL)
	toURL := normalizeRedirectURL(e.ToURL)
	if fromURL == "" || toURL == "" {
		return
	}
	fromHost := hostFromURL(fromURL)
	toHost := hostFromURL(toURL)
	if fromHost == "" || toHost == "" {
		return
	}

	source := inv.ensureEndpointNode(fromURL)
	source.StatusCode = e.StatusCode
	inv.addProvenance(&source.Provenance, e.Meta())
	inv.ensureRedirectHost(fromHost, false, e.Meta())
	inv.ensureRedirectHost(toHost, true, e.Meta())

	for _, existing := range source.Redirects {
		if existing.EventID == e.EventID {
			return
		}
	}
	source.Redirects = append(source.Redirects, HTTPRedirect{
		EventID: e.EventID, FromURL: fromURL, ToURL: toURL,
		FromHost: fromHost, ToHost: toHost, StatusCode: e.StatusCode, Hop: e.Hop,
		Disposition: e.Disposition, Reason: e.Reason, Source: e.Source, CapturedAt: e.CapturedAt,
	})
	sort.Slice(source.Redirects, func(i, j int) bool {
		a, b := source.Redirects[i], source.Redirects[j]
		if a.Hop != b.Hop {
			return a.Hop < b.Hop
		}
		if a.ToURL != b.ToURL {
			return a.ToURL < b.ToURL
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.EventID < b.EventID
	})
}

// ensureRedirectHost materializes a host reference without inventing DNS or
// endpoint evidence. A host already established by another event is never
// downgraded to referenced-only.
func (inv *Inventory) ensureRedirectHost(host string, referencedOnly bool, m events.EventMeta) {
	if net.ParseIP(host) != nil {
		if existing, ok := inv.IPs[host]; ok {
			if !referencedOnly {
				existing.ReferencedOnly = false
			}
			inv.addProvenance(&existing.Provenance, m)
			return
		}
		node := inv.ensureIPNode(host)
		node.ReferencedOnly = referencedOnly
		inv.addProvenance(&node.Provenance, m)
		return
	}
	if existing, ok := inv.Domains[host]; ok {
		if !referencedOnly {
			existing.ReferencedOnly = false
		}
		inv.addProvenance(&existing.Provenance, m)
		return
	}
	node := inv.ensureDomainNode(host)
	node.Source = entities.SourceHTTPRedirect
	node.DiscoveredAt = m.CapturedAt
	node.ReferencedOnly = referencedOnly
	inv.addProvenance(&node.Provenance, m)
}

// isHTTPSURL reports whether rawURL is an https endpoint (a completed request to one
// is a live-TLS observation).
func isHTTPSURL(rawURL string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "https://")
}

// addAuthSurface records an observed auth type and location on an asset's
// AuthSurface facet (allocating it when nil), deduping types and locations and
// advancing LiveVerifiedAt. It works on a domain or an IP node's facet alike.
func addAuthSurface(dst **entities.AuthSurface, e events.HttpEndpointDiscovered) {
	if *dst == nil {
		*dst = &entities.AuthSurface{}
	}
	as := *dst
	as.Types = appendUnique(as.Types, e.AuthType)
	sort.Strings(as.Types)
	as.Locations = appendUnique(as.Locations, e.URL)
	sort.Strings(as.Locations)
	if at := e.At(); at.After(as.LiveVerifiedAt) {
		as.LiveVerifiedAt = at
	}
}

// HasAuthSurface reports whether an active probe observed a login/admin surface
// directly on this address (an endpoint on a bare IP).
func (n *IPNode) HasAuthSurface() bool {
	return n != nil && n.AuthSurface != nil && len(n.AuthSurface.Types) > 0
}

// ServesLiveTLS reports whether a completed https response was observed on this
// address, so it is serving live TLS.
func (n *IPNode) ServesLiveTLS() bool {
	return n != nil && n.LiveTLS
}

// applyTechnology folds a technology report onto its endpoint. Several tools
// fingerprint the same URL with different depth and spell the same product
// differently, so entries are matched on the canonical identity from
// [valueobjects.NormalizeTechnology] rather than on the reported name: the same
// product with the same version merges however each tool spelled it, an unversioned
// report merges into an already versioned one and vice versa, and only a second
// distinct non-empty version opens a new finding. Metadata sets union; provenance
// always accumulates.
func (inv *Inventory) applyTechnology(e events.TechnologyFingerprinted) {
	node := inv.ensureEndpointNode(e.URL)
	inv.addProvenance(&node.Provenance, e.Meta())
	tech := valueobjects.NormalizeTechnology(e.Technology, e.Version)
	if tech.Key == "" {
		return
	}
	name, version, key := tech.Name, tech.Version, tech.Key

	var exact, unversioned, sameName *TechFinding
	for i := range node.Technologies {
		t := &node.Technologies[i]
		if valueobjects.NormalizeTechnology(t.Technology, t.Version).Key != key {
			continue
		}
		if sameName == nil {
			sameName = t
		}
		if t.Version == version {
			exact = t
			break
		}
		if t.Version == "" && unversioned == nil {
			unversioned = t
		}
	}

	slot := exact
	switch {
	case slot != nil:
		// same name and version: metadata merge only.
	case version != "" && unversioned != nil:
		// the earlier report had no version; this one upgrades it.
		unversioned.Version = version
		slot = unversioned
	case version == "" && sameName != nil:
		// unversioned report about an already versioned technology.
		slot = sameName
	default:
		node.Technologies = append(node.Technologies, TechFinding{Technology: name, Version: version})
		slot = &node.Technologies[len(node.Technologies)-1]
	}

	if slot.Evidence == "" {
		slot.Evidence = e.Evidence
	}
	slot.Categories = unionSortedStrings(slot.Categories, e.Categories)
	slot.CPEs = unionSortedStrings(slot.CPEs, e.CPEs)
	slot.Sources = unionSortedStrings(slot.Sources, []string{e.Meta().Source})
}

func (inv *Inventory) ensureEndpointNode(url string) *EndpointNode {
	if n, ok := inv.Endpoints[url]; ok {
		return n
	}
	n := &EndpointNode{URL: url}
	inv.Endpoints[url] = n
	return n
}

func (inv *Inventory) ensureDomainNode(name string) *DomainNode {
	if n, ok := inv.Domains[name]; ok {
		return n
	}
	n := &DomainNode{Domain: entities.Domain{Name: name}}
	inv.Domains[name] = n
	return n
}

func (inv *Inventory) ensureIPNode(ip string) *IPNode {
	if n, ok := inv.IPs[ip]; ok {
		return n
	}
	addr, err := entities.NewIPAddress(ip)
	if err != nil {
		addr = entities.IPAddress{Value: ip}
	}
	n := &IPNode{IPAddress: addr}
	inv.IPs[ip] = n
	return n
}

func (inv *Inventory) ensureNetblockNode(e events.NetblockDiscovered) *NetblockNode {
	if n, ok := inv.Netblocks[e.Prefix]; ok {
		return n
	}
	nb, err := entities.NewNetblock(e.Prefix)
	if err != nil {
		nb = entities.Netblock{Prefix: e.Prefix}
	}
	nb.ASN = e.ASN
	nb.Name = e.Name
	nb.Country = e.Country
	nb.Registry = e.Registry
	n := &NetblockNode{Netblock: nb}
	inv.Netblocks[e.Prefix] = n
	return n
}

func (inv *Inventory) ensureCertNode(e events.CertificateDiscovered) *CertNode {
	// Key by canonical serial so live and CT observations of the same certificate merge
	// (see applyCertificate); the node keeps the first producer's raw serial for display.
	serial := valueobjects.CanonicalCertSerial(e.Certificate.SerialNumber)
	n, ok := inv.Certificates[serial]
	if !ok {
		n = &CertNode{Certificate: toCertificate(&e.Certificate)}
		inv.Certificates[serial] = n
		return n
	}
	incoming := toCertificate(&e.Certificate)
	if n.CommonName == "" {
		n.CommonName = incoming.CommonName
	}
	if n.IssuerName == "" {
		n.IssuerName = incoming.IssuerName
	}
	if !incoming.ValidFrom.IsZero() && (n.ValidFrom.IsZero() || incoming.ValidFrom.Before(n.ValidFrom)) {
		n.ValidFrom = incoming.ValidFrom
	}
	if incoming.ValidUntil.After(n.ValidUntil) {
		n.ValidUntil = incoming.ValidUntil
	}
	if !incoming.LoggedAt.IsZero() && (n.LoggedAt.IsZero() || incoming.LoggedAt.Before(n.LoggedAt)) {
		n.LoggedAt = incoming.LoggedAt
	}
	if incoming.LiveVerifiedAt.After(n.LiveVerifiedAt) {
		n.LiveVerifiedAt = incoming.LiveVerifiedAt
	}
	n.Domains = unionSortedStrings(n.Domains, incoming.Domains)
	return n
}

// addProvenance appends a provenance record derived from m, skipping it if an
// entry with the same EventID is already present (keeping Apply idempotent).
func (inv *Inventory) addProvenance(provs *[]entities.Provenance, m events.EventMeta) {
	p := ProvenanceFromMeta(m)
	for _, existing := range *provs {
		if existing.EventID == p.EventID {
			return
		}
	}
	*provs = append(*provs, p)
}

// coveredNames returns the unique set of names a certificate covers.
func coveredNames(c events.CertificateData) []string {
	var names []string
	if c.CommonName != "" {
		names = appendUnique(names, c.CommonName)
	}
	for _, san := range c.Domains {
		if san != "" {
			names = appendUnique(names, san)
		}
	}
	return names
}

// isWildcardName reports whether name is a wildcard certificate SAN (e.g.
// "*.example.com"), which covers subdomains but is not itself a resolvable host.
func isWildcardName(name string) bool {
	return strings.HasPrefix(name, "*.")
}

// serviceKey is the canonical service asset id ("host/port/proto") the inventory
// keys service nodes and IPNode.Services by, so a service node, a risky-open-port
// finding all resolve to the same asset.
func serviceKey(ip string, port int, protocol string) string {
	return entities.NewServiceID(ip, port, protocol).String()
}

// unionSortedStrings returns the sorted set union of base and extra, dropping empty
// and duplicate values. Merged metadata must not depend on the order events arrived
// in, so every accumulating string set goes through it.
func unionSortedStrings(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	set := make(map[string]struct{}, len(base)+len(extra))
	for _, v := range base {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	for _, v := range extra {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// containsString reports whether v is present in s.
func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// removeString returns s without the first occurrence of v, order preserved. It
// promotes an address off the inferred associated-IP set when a confirmed DNS
// answer for the same address arrives, keeping the resolved and associated edges
// disjoint. It allocates a fresh slice so the caller's backing array is untouched.
func removeString(s []string, v string) []string {
	if !containsString(s, v) {
		return s
	}
	out := make([]string, 0, len(s)-1)
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// latestProvenance returns the most recent observation time across the records,
// used as an "updated at" for nodes the graph accumulates over several events.
func latestProvenance(provs []entities.Provenance) time.Time {
	var t time.Time
	for _, p := range provs {
		if p.CapturedAt.After(t) {
			t = p.CapturedAt
		}
	}
	return t
}

// UpdatedAt is the most recent time any event touched this domain node.
func (n *DomainNode) UpdatedAt() time.Time { return latestProvenance(n.Provenance) }

// HasAuthSurface reports whether the domain exposes a login/admin web surface,
// either observed directly by an active probe (an auth challenge, 401/403, or
// login form captured on its AuthSurface facet) or inferred from the admin/auth
// dork categories on its WebAssets facet. The observed signal is the stronger one.
func (n *DomainNode) HasAuthSurface() bool {
	if n == nil {
		return false
	}
	if n.AuthSurface != nil && len(n.AuthSurface.Types) > 0 {
		return true
	}
	if n.WebAssets == nil {
		return false
	}
	for _, a := range n.WebAssets.Assets {
		if a.Category == "admin" || a.Category == "auth" {
			return true
		}
	}
	return false
}

// HasMailInfra reports whether the domain runs mail, from its mail-security facet
// or its MX records.
func (n *DomainNode) HasMailInfra() bool {
	if n == nil {
		return false
	}
	if n.MailSecurity != nil {
		return true
	}
	return n.DNS != nil && len(n.DNS.MX) > 0
}

// UpdatedAt is the most recent time any event touched this certificate node.
func (n *CertNode) UpdatedAt() time.Time { return latestProvenance(n.Provenance) }

// The Sorted* accessors return the graph's nodes as deterministically ordered
// slices, so presentation layers can read the asset model directly without
// importing the map internals or depending on Go's map iteration order.

// SortedDomains returns domain nodes ordered by most recently updated, then name.
func (inv *Inventory) SortedDomains() []*DomainNode {
	out := make([]*DomainNode, 0, len(inv.Domains))
	for _, n := range inv.Domains {
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := out[i].UpdatedAt(), out[j].UpdatedAt()
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ObservedDomainCount returns names established by evidence beyond a redirect
// reference. Redirect-only destinations remain queryable in Domains but do not
// inflate the operator's attack-surface count.
func (inv *Inventory) ObservedDomainCount() int {
	total := 0
	for _, node := range inv.Domains {
		if !node.ReferencedOnly {
			total++
		}
	}
	return total
}

// SortedCertificates returns certificate nodes ordered by most recently updated,
// then serial number.
func (inv *Inventory) SortedCertificates() []*CertNode {
	out := make([]*CertNode, 0, len(inv.Certificates))
	for _, n := range inv.Certificates {
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := out[i].UpdatedAt(), out[j].UpdatedAt()
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return out[i].SerialNumber < out[j].SerialNumber
	})
	return out
}

// SortedNetblocks returns netblock nodes ordered by ASN, then prefix.
func (inv *Inventory) SortedNetblocks() []*NetblockNode {
	out := make([]*NetblockNode, 0, len(inv.Netblocks))
	for _, n := range inv.Netblocks {
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ASN != out[j].ASN {
			return out[i].ASN < out[j].ASN
		}
		return out[i].Prefix < out[j].Prefix
	})
	return out
}

// SortedIPs returns IP nodes ordered by address.
func (inv *Inventory) SortedIPs() []*IPNode {
	out := make([]*IPNode, 0, len(inv.IPs))
	for _, n := range inv.IPs {
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// UnreachableIPv6 returns the IP nodes the active phase marked unreachable because
// the address is IPv6-only and the scanner has no IPv6 route, ordered by address.
func (inv *Inventory) UnreachableIPv6() []*IPNode {
	var out []*IPNode
	for _, n := range inv.IPs {
		if n.Reachability == entities.ReachabilityUnreachableIPv6 {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// SortedServices returns service nodes ordered by IP, then port, then protocol.
// Protocol is part of the order rather than a cosmetic tie-break: services are held
// in a map keyed by IP, port, and protocol, so a TCP and a UDP service on the same
// socket number are two nodes that compare equal on IP and port alone, and the order
// between them would otherwise follow Go's randomized map iteration. That would make
// the entity snapshot differ byte for byte between two projections of the same
// collection.
func (inv *Inventory) SortedServices() []*ServiceNode {
	out := make([]*ServiceNode, 0, len(inv.Services))
	for _, n := range inv.Services {
		out = append(out, n)
	}
	sort.SliceStable(out, lessService(out))
	return out
}

// lessService is the total order over service nodes: IP, then port, then protocol.
// The three fields are exactly the service identity, so no two distinct nodes
// compare equal and the resulting order depends on nothing but the data.
func lessService(s []*ServiceNode) func(i, j int) bool {
	return func(i, j int) bool {
		if s[i].IP != s[j].IP {
			return s[i].IP < s[j].IP
		}
		if s[i].Port != s[j].Port {
			return s[i].Port < s[j].Port
		}
		return s[i].Protocol < s[j].Protocol
	}
}

// SortedEndpoints returns endpoint nodes ordered by URL.
func (inv *Inventory) SortedEndpoints() []*EndpointNode {
	out := make([]*EndpointNode, 0, len(inv.Endpoints))
	for _, n := range inv.Endpoints {
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// The relationship accessors below walk the graph edges to answer the questions a
// cyber analyst asks of the asset model: how the surface is layered by crawl
// depth, which hosts share a routed prefix, and which services a single name
// exposes across all the addresses it resolves to.

// DomainsByDepth groups domain nodes by crawl depth (0 = root), each group
// ordered by name. It exposes how the discovered surface fans out from the root.
func (inv *Inventory) DomainsByDepth() map[int][]*DomainNode {
	out := make(map[int][]*DomainNode)
	for _, n := range inv.Domains {
		out[n.Depth] = append(out[n.Depth], n)
	}
	for _, group := range out {
		sort.SliceStable(group, func(i, j int) bool { return group[i].Name < group[j].Name })
	}
	return out
}

// IPsInNetblock returns the IP nodes observed within the given netblock prefix,
// ordered by address. It maps a routed prefix (ASN) back to the hosts seen in it,
// revealing infrastructure shared across otherwise unrelated names.
func (inv *Inventory) IPsInNetblock(prefix string) []*IPNode {
	nb, ok := inv.Netblocks[prefix]
	if !ok {
		return nil
	}
	out := make([]*IPNode, 0, len(nb.IPs))
	for _, ip := range nb.IPs {
		if n, ok := inv.IPs[ip]; ok {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// ServicesForDomain returns the service nodes reachable on every IP the domain
// resolves to, ordered by IP, then port, then protocol. It is the per-domain attack
// surface: the concrete listening daemons one name exposes.
func (inv *Inventory) ServicesForDomain(name string) []*ServiceNode {
	d, ok := inv.Domains[name]
	if !ok {
		return nil
	}
	var out []*ServiceNode
	for _, ip := range d.IPs {
		ipNode, ok := inv.IPs[ip]
		if !ok {
			continue
		}
		for _, key := range ipNode.Services {
			if svc, ok := inv.Services[key]; ok {
				out = append(out, svc)
			}
		}
	}
	sort.SliceStable(out, lessService(out))
	return out
}
