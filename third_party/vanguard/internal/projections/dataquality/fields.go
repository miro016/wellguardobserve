package dataquality

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// observations holds, for one comparable field, what every provider reported:
// target key -> provider -> the set of normalised values. A presence-only field
// (subdomains) records a provider under a key with an empty value-set; a valued
// field records the actual values. The triple-nested map is built once per field
// from a single pass over the event stream and then read by the comparison.
type observations map[string]map[string]map[string]struct{}

// see records that provider reported value for key. A blank value still registers
// the provider's presence on the key (the presence-field case); blank keys are
// ignored so an extractor can pass through unusable input uniformly.
func (o observations) see(key, provider, value string) {
	if key == "" || provider == "" {
		return
	}
	pm := o[key]
	if pm == nil {
		pm = make(map[string]map[string]struct{})
		o[key] = pm
	}
	vs := pm[provider]
	if vs == nil {
		vs = make(map[string]struct{})
		pm[provider] = vs
	}
	if value != "" {
		vs[value] = struct{}{}
	}
}

// Key-unit labels for the comparable fields, naming what a field's keys count.
const (
	unitDomains   = "domains"
	unitIPs       = "IPs"
	unitEndpoints = "endpoints"
)

// Field is one comparable field in the registry: a human label, the unit its keys
// are counted in (for the report), whether it is presence-only, and the extractor
// that folds the event stream into observations.
type Field struct {
	// Name is the report label, for example "subdomains".
	Name string
	// Unit names what the keys count, for example "domains" or "IPs".
	Unit string
	// Presence is true when the key is itself the value (no conflict is possible).
	Presence bool
	// Extract folds the stream into per-key, per-provider value-sets.
	Extract func([]events.DomainEvent) observations
}

// Fields is the comparable-field registry. It is intentionally small: a handful of
// high-value fields where multiple providers overlap. Code duplication across the
// extractors is acceptable until there are three-plus near-identical ones.
func Fields() []Field {
	return []Field{
		{Name: "subdomains", Unit: unitDomains, Presence: true, Extract: extractSubdomains},
		{Name: "addresses", Unit: unitDomains, Extract: extractAddresses},
		{Name: "services", Unit: unitIPs, Extract: extractServices},
		{Name: "nameservers", Unit: unitDomains, Extract: extractNameservers},
		{Name: "registrar", Unit: unitDomains, Extract: extractRegistrar},
		{Name: "web technologies", Unit: unitEndpoints, Extract: extractWebTechnologies},
	}
}

// extractSubdomains records which provider discovered each domain name. The
// producing tool is stamped on DnsDomainNameDiscovered, so this is "who found this
// name" across crtsh, subfinder, virustotal, websearch, and the root seed.
func extractSubdomains(evts []events.DomainEvent) observations {
	o := observations{}
	for _, evt := range evts {
		if e, ok := evt.(events.DnsDomainNameDiscovered); ok {
			o.see(normalizeDomain(e.Domain), e.Meta().Source, "")
		}
	}
	return o
}

// extractAddresses compares the A/AAAA set a provider reports per domain. dnsinfo
// resolves them live; censys/shodan/netlas report the IPs they associate with the
// name. They are comparable views of "where does this name point".
func extractAddresses(evts []events.DomainEvent) observations {
	o := observations{}
	for _, evt := range evts {
		switch e := evt.(type) {
		case *events.DnsRecordsDiscovered:
			key := normalizeDomain(e.Domain)
			prov := e.Meta().Source
			for _, ip := range e.A {
				o.see(key, prov, normalizeIP(ip))
			}
			for _, ip := range e.AAAA {
				o.see(key, prov, normalizeIP(ip))
			}
		case *events.CensysHostsDiscovered:
			key, prov := normalizeDomain(e.Domain), e.Meta().Source
			for i := range e.Hosts {
				o.see(key, prov, normalizeIP(e.Hosts[i].IP))
			}
		case *events.ShodanHostsDiscovered:
			key, prov := normalizeDomain(e.Domain), e.Meta().Source
			for i := range e.Hosts {
				o.see(key, prov, normalizeIP(e.Hosts[i].IP))
			}
		case *events.NetlasHostsDiscovered:
			key, prov := normalizeDomain(e.Domain), e.Meta().Source
			for i := range e.Hosts {
				o.see(key, prov, normalizeIP(e.Hosts[i].IP))
			}
		}
	}
	return o
}

// extractServices compares the open port/proto set a provider reports per IP.
// portscan observes them active; censys/shodan/netlas report them passively.
//
// The comparison classifies a per-IP difference as a coverage gap when one provider's
// port set is a subset of another's, and a conflict only when the sets are mutually
// exclusive. This subset-is-a-coverage-gap rule is the honest ceiling here: the active
// portscan probes only a fixed port list (tools.portscan.ports) while passive
// providers report whatever full-range scans found, so a passive provider almost
// always reports a superset. A true open/closed comparison would restrict to the
// intersection of the ports each provider actually scanned, but passive providers
// report only observed-open ports, not their scanned-port set, so that intersection is
// not recoverable from the stream.
func extractServices(evts []events.DomainEvent) observations {
	o := observations{}
	for _, evt := range evts {
		switch e := evt.(type) {
		case *events.ServiceDiscovered:
			o.see(normalizeIP(e.IP), e.Meta().Source, normalizeService(e.Port, e.Protocol))
		case *events.CensysHostsDiscovered:
			prov := e.Meta().Source
			for i := range e.Hosts {
				key := normalizeIP(e.Hosts[i].IP)
				for _, s := range e.Hosts[i].Services {
					o.see(key, prov, normalizeProviderService(s.Port, s.Transport))
				}
			}
		case *events.ShodanHostsDiscovered:
			prov := e.Meta().Source
			for i := range e.Hosts {
				key := normalizeIP(e.Hosts[i].IP)
				for _, s := range e.Hosts[i].Services {
					o.see(key, prov, normalizeProviderService(s.Port, s.Transport))
				}
			}
		case *events.NetlasHostsDiscovered:
			prov := e.Meta().Source
			for i := range e.Hosts {
				key := normalizeIP(e.Hosts[i].IP)
				for _, s := range e.Hosts[i].Services {
					o.see(key, prov, normalizeProviderService(s.Port, s.Transport))
				}
			}
		}
	}
	return o
}

// extractNameservers compares the NS set per domain: dnsinfo reports the live DNS
// delegation, whois reports the registry-side nameservers. They should match; a
// drift between them is the interesting conflict.
func extractNameservers(evts []events.DomainEvent) observations {
	o := observations{}
	for _, evt := range evts {
		switch e := evt.(type) {
		case *events.DnsRecordsDiscovered:
			key, prov := normalizeDomain(e.Domain), e.Meta().Source
			for _, ns := range e.NS {
				o.see(key, prov, normalizeDomain(ns))
			}
		case *events.DomainRegistrationDiscovered:
			key, prov := normalizeDomain(e.Domain), e.Meta().Source
			for _, ns := range e.Nameservers {
				o.see(key, prov, normalizeDomain(ns))
			}
		}
	}
	return o
}

// extractRegistrar compares the registrar string per domain: whois/RDAP is
// authoritative, virustotal carries a corroborating value.
func extractRegistrar(evts []events.DomainEvent) observations {
	o := observations{}
	for _, evt := range evts {
		switch e := evt.(type) {
		case *events.DomainRegistrationDiscovered:
			o.see(normalizeDomain(e.Domain), e.Meta().Source, normalizeRegistrar(e.Registrar))
		case *events.DomainReputationDiscovered:
			o.see(normalizeDomain(e.Domain), e.Meta().Source, normalizeRegistrar(e.Registrar))
		}
	}
	return o
}

// extractWebTechnologies compares the technology set each fingerprinting tool
// reports per endpoint. wappalyzer runs the embedded WappalyzerGo database and
// webinfo runs its own heuristics against domain URLs. httpprobe is excluded: it
// probes IP URLs without the domain Host/SNI identity, so captures proved its response
// is not comparable by exact URL to either domain probe.
//
// Each versioned observation contributes both "name" and "name version". A bare name
// from one tool is therefore a subset of a versioned result, while two different
// versions remain a real conflict. Capture-proven aliases reconcile IIS/Microsoft-IIS,
// ARR/Application Request Routing, Microsoft ASP.NET/ASP.NET, and Apache variants.
// Categories and CPEs are metadata, not identity - only wappalyzer supplies them.
//
// The value form is folded through events.AsValue because this field is the first
// one whose events the orchestrator emits as values live and persistence decodes as
// pointers on replay; both must produce the same report.
func extractWebTechnologies(evts []events.DomainEvent) observations {
	o := observations{}
	for _, evt := range evts {
		e, ok := events.AsValue(evt).(events.TechnologyFingerprinted)
		if !ok {
			continue
		}
		if e.Meta().Source != "wappalyzer" && e.Meta().Source != "webinfo" {
			continue
		}
		for _, token := range technologyComparisonTokens(e.Technology, e.Version) {
			o.see(normalizeEndpointURL(e.URL), e.Meta().Source, token)
		}
	}
	return o
}

// sortedKeys returns the observation keys in deterministic order.
func sortedKeys(o observations) []string {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedValues returns a value-set as a sorted slice.
func sortedValues(vs map[string]struct{}) []string {
	out := make([]string, 0, len(vs))
	for v := range vs {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
