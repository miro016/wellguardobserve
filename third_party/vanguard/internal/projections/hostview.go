package projections

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Provider labels recorded as the provenance of a unified host datum. The active
// phase has no constant here on purpose: an actively observed service is attributed
// to the tools its own provenance names (portscan, goscans, or both), never to a
// label this package picked for it.
const (
	hostSourceCensys = "censys"
	hostSourceShodan = "shodan"
	hostSourceNetlas = "netlas"
)

// HostView is the unified, per-IP merge of every host signal Vanguard gathered:
// the active port scan (confirmed) plus the censys, shodan, and netlas provider
// facets (inferred), with the IP asset's OS, reachability, ASN, and confidence.
// It is the single authoritative host model the risk model reasons over, instead
// of reconciling four separate provider facets.
//
// It is a pure projection folded from the inventory (the already-merged asset
// graph), built in a fixed, sorted order so the result is deterministic and
// replay-stable. It is the merge counterpart to the data-quality analyzer
// (internal/projections/dataquality), which keeps the per-provider values un-merged to score
// providers; this view answers "what do we know about this host" rather than
// "who said what".
type HostView struct {
	// Hosts is the merged host record per IP address.
	Hosts map[string]*UnifiedHost
}

// UnifiedHost is everything known about one host, merged across sources.
type UnifiedHost struct {
	// IP is the address and the record key.
	IP string
	// Version is the IP version (4 or 6), 0 when the host is provider-only.
	Version int
	// Reachability is the active phase's verdict (empty when never scanned).
	Reachability entities.IPReachability
	// Confidence is the IP asset's confidence (confirmed for a resolved address).
	Confidence entities.Confidence
	// OS is the inferred OS-family guess, empty when unknown.
	OS string
	// ASN is the autonomous system number from the routed prefix, 0 when unknown.
	ASN int
	// Netblock is the CIDR prefix the address belongs to, empty when unknown.
	Netblock string
	// Orgs are the provider-reported AS/organisation names, sorted and deduped.
	Orgs []string
	// JARMs are the provider-reported JARM TLS fingerprints, sorted and deduped.
	JARMs []string
	// Ports are the merged open ports, sorted ascending by port.
	Ports []HostPort
	// CVEs are the merged known vulnerabilities, sorted by identifier.
	CVEs []HostCVE
	// Sources are every provider/tool that contributed to this host, sorted.
	Sources []string
	// SourceObservedAt is the newest real-world observation time across everything
	// merged into this host: a provider's own scan time, or Vanguard's capture time
	// where Vanguard did the observing. Zero means no contributing source dated its
	// claim, which is a coverage gap and not a fresh observation.
	SourceObservedAt time.Time
}

// HostPort is one open port on a host, merged across the sources that reported it.
type HostPort struct {
	// Port is the port number. It is half of the merge key.
	Port int
	// Protocol is the transport: "tcp", "udp", or "unknown" when the reporting
	// provider named none. It is the other half of the merge key, so a UDP service
	// and a TCP service on one port stay two rows, and neither of them absorbs a
	// provider observation whose transport nobody stated.
	Protocol string
	// Service, Product, Version describe the service, best-effort across sources.
	Service string
	Product string
	Version string
	// Banner is the truncated service banner, when captured.
	Banner string
	// Confidence is confirmed when the active scan observed the port open, inferred
	// when only a provider reported it. A port both scanned-open and
	// provider-reported is the strongest signal (confirmed, multiple sources).
	Confidence entities.Confidence
	// Sources are the providers/tools that reported the port, sorted.
	Sources []string
	// SourceObservedAt is the newest real-world observation time across the sources
	// that reported this port, so a year-old provider banner cannot render like this
	// morning's confirmed scan. Zero means no reporter dated its claim.
	SourceObservedAt time.Time
}

// HostCVE is one known vulnerability on a host, merged across the sources.
type HostCVE struct {
	// ID is the CVE identifier and merge key.
	ID string
	// Confidence is inferred: providers infer CVEs from banners, unverified until
	// the version is corroborated.
	Confidence entities.Confidence
	// Sources are the providers that reported the CVE, sorted.
	Sources []string
	// SourceObservedAt is the newest real-world observation time across the providers
	// that reported this CVE. Zero means none of them dated the claim.
	SourceObservedAt time.Time
}

// HostView builds the unified host view from the inventory. It is a pure fold:
// step 1 below seeds every IP asset node (Version/Reachability/Confidence/OS/ASN/
// Netblock, plus confirmed ports from the active scan), then the provider facets
// merge in their inferred ports and CVEs. Since the orchestrator now rejoins a
// provider-only host's IP into Inventory.IPs (translate.ProviderIPAddresses via
// ingestProviderHosts), a host no DNS record ever resolved still gets a real
// Version/ASN/Netblock here instead of the zero value a facet-only merge would
// leave it with. Processing follows a fixed sorted order so a scalar resolved by
// "first non-empty wins" (the active scan, then censys, shodan, netlas) is
// deterministic and replay-stable.
func (inv *Inventory) HostView() HostView {
	hv := HostView{Hosts: make(map[string]*UnifiedHost)}
	ensure := func(ip string) *UnifiedHost {
		h, ok := hv.Hosts[ip]
		if !ok {
			h = &UnifiedHost{IP: ip}
			hv.Hosts[ip] = h
		}
		return h
	}

	// 1) Seed from the IP asset nodes and their actively scanned services. These are
	// directly observed, so their ports are confirmed.
	for _, ip := range sortedKeys(inv.IPs) {
		ipNode := inv.IPs[ip]
		if ipNode.ReferencedOnly {
			continue
		}
		h := ensure(ip)
		h.Version = ipNode.Version
		h.Reachability = ipNode.Reachability
		h.Confidence = ipNode.Confidence
		h.OS = ipNode.OS
		h.ASN = ipNode.ASN
		h.Netblock = ipNode.Netblock
		svcKeys := append([]string(nil), ipNode.Services...)
		sort.Strings(svcKeys)
		for _, key := range svcKeys {
			svc, ok := inv.Services[key]
			if !ok {
				continue
			}
			h.mergePort(&HostPort{
				Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
				Product: svc.Product, Version: svc.Version, Banner: svc.Banner,
				Confidence: entities.ConfidenceConfirmed,
				// Vanguard did this observing, so the capture time is also the
				// real-world observation time.
				SourceObservedAt: latestSelfObservation(svc.Provenance),
			}, activeServiceSources(svc.Provenance)...)
		}
	}

	// 2) Merge the provider facets in a fixed provider-major order, so the provider
	// priority for a conflicting scalar (after the confirmed scan) is stable.
	domains := sortedKeys(inv.Domains)
	for _, d := range domains {
		if c := inv.Domains[d].CensysExposure; c != nil {
			for i := range c.Hosts {
				mergeCensysHost(ensure(c.Hosts[i].IP), &c.Hosts[i])
			}
		}
	}
	for _, d := range domains {
		if s := inv.Domains[d].ShodanExposure; s != nil {
			for i := range s.Hosts {
				mergeShodanHost(ensure(s.Hosts[i].IP), &s.Hosts[i])
			}
		}
	}
	for _, d := range domains {
		if n := inv.Domains[d].NetlasExposure; n != nil {
			for i := range n.Hosts {
				mergeNetlasHost(ensure(n.Hosts[i].IP), &n.Hosts[i])
			}
		}
	}

	for _, h := range hv.Hosts {
		h.finalize()
	}
	return hv
}

func mergeCensysHost(h *UnifiedHost, ch *valueobjects.CensysHost) {
	h.Sources = addUnique(h.Sources, hostSourceCensys)
	if h.OS == "" {
		h.OS = ch.OS
	}
	if ch.ASN != nil {
		h.addOrg(ch.ASN.Name)
		h.addOrg(ch.ASN.Description)
	}
	product := firstNonEmpty(ch.Products)
	for _, s := range ch.Services {
		// Each service keeps its own scan_time: a host-wide summary would let one
		// service inherit a newer sibling's freshness.
		h.mergePort(&HostPort{
			Port: s.Port, Protocol: s.Transport, Service: s.Protocol, Product: product,
			Confidence: entities.ConfidenceInferred, SourceObservedAt: s.SourceObservedAt,
		}, hostSourceCensys)
	}
	hostObserved := latestCensysSourceObservation(ch.Services)
	for _, cve := range ch.Vulns {
		h.mergeCVE(cve, hostSourceCensys, hostObserved)
	}
}

func mergeShodanHost(h *UnifiedHost, sh *valueobjects.ShodanHost) {
	h.Sources = addUnique(h.Sources, hostSourceShodan)
	if h.OS == "" {
		h.OS = sh.OS
	}
	h.addOrg(sh.Org)
	product := firstNonEmpty(sh.Products)
	for _, s := range sh.Services {
		h.mergePort(&HostPort{Port: s.Port, Protocol: s.Transport, Product: product,
			Confidence: entities.ConfidenceInferred, SourceObservedAt: sh.SourceObservedAt}, hostSourceShodan)
	}
	for _, cve := range sh.Vulns {
		h.mergeCVE(cve, hostSourceShodan, sh.SourceObservedAt)
	}
}

func mergeNetlasHost(h *UnifiedHost, nh *valueobjects.NetlasHost) {
	h.Sources = addUnique(h.Sources, hostSourceNetlas)
	h.addOrg(nh.Org)
	if nh.JARM != "" {
		h.JARMs = addUnique(h.JARMs, nh.JARM)
	}
	product := firstNonEmpty(nh.Products)
	for _, s := range nh.Services {
		h.mergePort(&HostPort{Port: s.Port, Protocol: s.Transport, Service: s.ApplicationProtocol,
			Product: product, Confidence: entities.ConfidenceInferred,
			SourceObservedAt: nh.SourceObservedAt}, hostSourceNetlas)
	}
	for _, cve := range nh.Vulns {
		h.mergeCVE(cve, hostSourceNetlas, nh.SourceObservedAt)
	}
}

// mergePort folds a port contribution from sources into the host, merging by port
// number and transport: the confidence is upgraded to the strongest reporter,
// scalars keep the first non-empty value (the fixed processing order makes that
// deterministic), and every contributing source is recorded.
//
// A provider contributes exactly one source; an actively observed service
// contributes the set its own provenance names, so a service only goscans saw is
// not attributed to the port scanner. A contribution with no source at all still
// yields its port row: the observation is real even where nothing named the
// observer, and inventing a name for it would be worse than reporting none.
//
// Transport is part of the key rather than a merged scalar. Merging on the number
// alone folded a provider's udp/53 into the active scan's tcp/53 and let whichever
// arrived first name the transport of both, which is how one confirmed TCP service
// could inherit a UDP reporter's evidence.
func (h *UnifiedHost) mergePort(p *HostPort, sources ...string) {
	p.Protocol = normalizePortTransport(p.Protocol)
	for _, source := range sources {
		h.Sources = addUnique(h.Sources, source)
	}
	if p.SourceObservedAt.After(h.SourceObservedAt) {
		h.SourceObservedAt = p.SourceObservedAt
	}
	for i := range h.Ports {
		if h.Ports[i].Port != p.Port || h.Ports[i].Protocol != p.Protocol {
			continue
		}
		hp := &h.Ports[i]
		hp.Confidence = hp.Confidence.Stronger(p.Confidence)
		for _, source := range sources {
			hp.Sources = addUnique(hp.Sources, source)
		}
		hp.Service = firstNonEmptyStr(hp.Service, p.Service)
		hp.Product = firstNonEmptyStr(hp.Product, p.Product)
		hp.Version = firstNonEmptyStr(hp.Version, p.Version)
		hp.Banner = firstNonEmptyStr(hp.Banner, p.Banner)
		if p.SourceObservedAt.After(hp.SourceObservedAt) {
			hp.SourceObservedAt = p.SourceObservedAt
		}
		return
	}
	p.Sources = slices.Clone(sources)
	h.Ports = append(h.Ports, *p)
}

// activeServiceSources is the sorted, deduplicated set of tools that contributed to
// an actively observed service, read from the service node's own provenance. It
// replaces the fixed "portscan" label the seed used to stamp on every inventory
// service, which misattributed a service only goscans fingerprinted and hid the
// corroboration when both tools saw one.
func activeServiceSources(prov []entities.Provenance) []string {
	var out []string
	for _, p := range prov {
		if p.Source == "" {
			continue
		}
		out = addUnique(out, p.Source)
	}
	sort.Strings(out)
	return out
}

// normalizePortTransport resolves the transport a contribution carries into the
// merge key. The active scan always states one; a provider that stated none yields
// the explicit unknown, which keeps the observation visible without letting it pass
// as TCP.
func normalizePortTransport(s string) string {
	switch t := strings.ToLower(strings.TrimSpace(s)); t {
	case entities.ProtocolTCP, entities.ProtocolUDP:
		return t
	case "":
		return entities.ProtocolUnknown
	default:
		return t
	}
}

func (h *UnifiedHost) mergeCVE(id, source string, observedAt time.Time) {
	h.Sources = addUnique(h.Sources, source)
	if observedAt.After(h.SourceObservedAt) {
		h.SourceObservedAt = observedAt
	}
	for i := range h.CVEs {
		if h.CVEs[i].ID == id {
			h.CVEs[i].Sources = addUnique(h.CVEs[i].Sources, source)
			if observedAt.After(h.CVEs[i].SourceObservedAt) {
				h.CVEs[i].SourceObservedAt = observedAt
			}
			return
		}
	}
	h.CVEs = append(h.CVEs, HostCVE{ID: id, Confidence: entities.ConfidenceInferred,
		Sources: []string{source}, SourceObservedAt: observedAt})
}

// latestSelfObservation returns the newest capture time among the provenance entries
// Vanguard produced by observing directly (an active probe or a DNS answer).
// For those kinds the capture time is also the real-world observation time; for every
// other kind someone else did the observing at an instant only they know, so their
// capture time says nothing about the subject and is skipped.
func latestSelfObservation(prov []entities.Provenance) time.Time {
	var latest time.Time
	for _, p := range prov {
		switch events.ObservationKind(p.ObservationKind) {
		case events.ObservationKindActiveProbe, events.ObservationKindDNSAnswer:
			if p.CapturedAt.After(latest) {
				latest = p.CapturedAt
			}
		case events.ObservationKindInput, events.ObservationKindHistoricalLog,
			events.ObservationKindPassiveSnapshot, events.ObservationKindDerived,
			events.ObservationKindLifecycle, events.ObservationKindOperational:
		}
	}
	return latest
}

func (h *UnifiedHost) addOrg(org string) {
	if org != "" {
		h.Orgs = addUnique(h.Orgs, org)
	}
}

// finalize sorts every accumulated slice so the host record is deterministic.
func (h *UnifiedHost) finalize() {
	sort.Slice(h.Ports, func(i, j int) bool {
		if h.Ports[i].Port != h.Ports[j].Port {
			return h.Ports[i].Port < h.Ports[j].Port
		}
		return h.Ports[i].Protocol < h.Ports[j].Protocol
	})
	sort.Slice(h.CVEs, func(i, j int) bool { return h.CVEs[i].ID < h.CVEs[j].ID })
	sort.Strings(h.Orgs)
	sort.Strings(h.JARMs)
	sort.Strings(h.Sources)
	for i := range h.Ports {
		sort.Strings(h.Ports[i].Sources)
	}
	for i := range h.CVEs {
		sort.Strings(h.CVEs[i].Sources)
	}
}

// SortedHosts returns the unified hosts ordered by IP for stable rendering.
func (hv HostView) SortedHosts() []*UnifiedHost {
	out := make([]*UnifiedHost, 0, len(hv.Hosts))
	for _, h := range hv.Hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// HasConfirmedPort reports whether any of the host's ports was observed open by
// the active scan (as opposed to only being provider-claimed).
func (h *UnifiedHost) HasConfirmedPort() bool {
	for i := range h.Ports {
		if h.Ports[i].Confidence == entities.ConfidenceConfirmed {
			return true
		}
	}
	return false
}

// sortedKeys returns the keys of a string-keyed map in ascending order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// addUnique appends v to s if absent, keeping the slice a set (sorted at finalize).
func addUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstNonEmpty(s []string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
