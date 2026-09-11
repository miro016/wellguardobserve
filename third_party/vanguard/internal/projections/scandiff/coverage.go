package scandiff

import (
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Entity-key coverage is the quick-insight layer over the per-event classification:
// instead of reading every event, it answers "how many domains/IPs/services/
// findings appeared or disappeared" by comparing the key sets each scan covers per
// entity kind. It stays pure over the event stream (coverage source B from the
// plan): the keys are extracted directly from the events with the same normalizers
// as identity, so no projection or persistence dependency is pulled in.

// EntityKind names a kind of asset whose key set is compared across scans.
type EntityKind string

const (
	// KindDomain counts normalized domain names.
	KindDomain EntityKind = "domains"
	// KindIP counts normalized IP addresses.
	KindIP EntityKind = "ips"
	// KindService counts ip + port/proto services.
	KindService EntityKind = "services"
	// KindEndpoint counts normalized HTTP(S) endpoint URLs.
	KindEndpoint EntityKind = "endpoints"
	// KindCertificate counts canonical certificate serial identities.
	KindCertificate EntityKind = "certificates"
	// KindFinding counts rule + assetKind + assetID finding identities.
	KindFinding EntityKind = "findings"
	// KindNetblock counts routed prefixes.
	KindNetblock EntityKind = "netblocks"
)

// CoverageDelta is the per-kind set comparison: how many keys each scan covered, how
// many they share, and which keys were gained (in candidate B, not baseline A) or
// lost (in A, not B). Added and Removed are complete and sorted; the rendered
// Markdown (step 4) may cap them.
type CoverageDelta struct {
	Kind    EntityKind `json:"kind"`
	ACount  int        `json:"aCount"`
	BCount  int        `json:"bCount"`
	Common  int        `json:"common"`
	Added   []string   `json:"added,omitempty"`
	Removed []string   `json:"removed,omitempty"`
}

// coverageExtractor folds an event stream into a normalized key set for one kind.
type coverageExtractor func([]events.DomainEvent) map[string]struct{}

// coverageExtractors maps each kind to its extractor, in stable output order.
var coverageExtractors = []struct {
	kind    EntityKind
	extract coverageExtractor
}{
	{KindDomain, extractDomainKeys},
	{KindIP, extractIPKeys},
	{KindService, extractServiceKeys},
	{KindEndpoint, extractEndpointKeys},
	{KindCertificate, extractCertificateKeys},
	{KindFinding, extractFindingKeys},
	{KindNetblock, extractNetblockKeys},
}

// Coverage computes the per-kind coverage deltas between baseline A and candidate B.
// It is pure and deterministic: every kind is reported (even when both sides are
// empty) in a fixed order, with sorted Added/Removed lists.
func Coverage(a, b []events.DomainEvent) []CoverageDelta {
	out := make([]CoverageDelta, 0, len(coverageExtractors))
	for _, e := range coverageExtractors {
		out = append(out, coverageFor(e.kind, e.extract(a), e.extract(b)))
	}
	return out
}

// coverageFor turns two key sets into the delta: shared keys count toward Common,
// keys only in A are Removed, keys only in B are Added.
func coverageFor(kind EntityKind, as, bs map[string]struct{}) CoverageDelta {
	cd := CoverageDelta{Kind: kind, ACount: len(as), BCount: len(bs)}
	for k := range as {
		if _, ok := bs[k]; ok {
			cd.Common++
		} else {
			cd.Removed = append(cd.Removed, k)
		}
	}
	for k := range bs {
		if _, ok := as[k]; !ok {
			cd.Added = append(cd.Added, k)
		}
	}
	sort.Strings(cd.Added)
	sort.Strings(cd.Removed)
	return cd
}

// keySet collects non-empty keys into a set.
type keySet map[string]struct{}

func (s keySet) add(k string) {
	if k != "" {
		s[k] = struct{}{}
	}
}

// extractDomainKeys collects the normalized domain of every domain-bearing event,
// so the coverage answers "which names does each scan know about".
func extractDomainKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		switch e := events.AsValue(evt).(type) {
		case events.DnsDomainNameDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.DnsRecordsDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.ZoneTransferDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.DomainRegistrationDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.MailSecurityDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.MxTlsDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.TlsPostureDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.BreachDataDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.DomainReputationDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.WebAssetsDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.CensysHostsDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.ShodanHostsDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.NetlasHostsDiscovered:
			s.add(normalizeDomain(e.Domain))
		case events.IPAddressDiscovered:
			s.add(normalizeDomain(e.Domain))
		}
	}
	return s
}

// extractIPKeys collects normalized IP addresses from the events that name a host.
func extractIPKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		switch e := events.AsValue(evt).(type) {
		case events.IPAddressDiscovered:
			s.add(normalizeIP(e.IP))
		case events.ServiceDiscovered:
			s.add(normalizeIP(e.IP))
		case events.IPReachabilityObserved:
			s.add(normalizeIP(e.IP))
		case events.HostOSGuessed:
			s.add(normalizeIP(e.IP))
		case events.CensysHostsDiscovered:
			for i := range e.Hosts {
				s.add(normalizeIP(e.Hosts[i].IP))
			}
		case events.ShodanHostsDiscovered:
			for i := range e.Hosts {
				s.add(normalizeIP(e.Hosts[i].IP))
			}
		case events.NetlasHostsDiscovered:
			for i := range e.Hosts {
				s.add(normalizeIP(e.Hosts[i].IP))
			}
		}
	}
	return s
}

// extractServiceKeys collects ip + port/proto services from the active probe and
// the passive host snapshots.
func extractServiceKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		switch e := events.AsValue(evt).(type) {
		case events.ServiceDiscovered:
			s.add(keyJoin(normalizeIP(e.IP), normalizeService(e.Port, e.Protocol)))
		case events.CensysHostsDiscovered:
			for i := range e.Hosts {
				ip := normalizeIP(e.Hosts[i].IP)
				for _, svc := range e.Hosts[i].Services {
					s.add(keyJoin(ip, normalizeProviderService(svc.Port, svc.Transport)))
				}
			}
		case events.ShodanHostsDiscovered:
			for i := range e.Hosts {
				ip := normalizeIP(e.Hosts[i].IP)
				for _, svc := range e.Hosts[i].Services {
					s.add(keyJoin(ip, normalizeProviderService(svc.Port, svc.Transport)))
				}
			}
		case events.NetlasHostsDiscovered:
			for i := range e.Hosts {
				ip := normalizeIP(e.Hosts[i].IP)
				for _, svc := range e.Hosts[i].Services {
					s.add(keyJoin(ip, normalizeProviderService(svc.Port, svc.Transport)))
				}
			}
		}
	}
	return s
}

// extractEndpointKeys collects normalized HTTP(S) endpoint URLs.
func extractEndpointKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		if e, ok := events.AsValue(evt).(events.HttpEndpointDiscovered); ok {
			s.add(normalizeURL(e.URL))
		}
	}
	return s
}

// extractCertificateKeys collects canonical certificate serial identities,
// matching both the CertificateDiscovered identity key and inventory projection.
func extractCertificateKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		if e, ok := events.AsValue(evt).(events.CertificateDiscovered); ok {
			s.add(certificateKey(e))
		}
	}
	return s
}

// extractFindingKeys collects rule + assetKind + assetID finding identities,
// matching the FindingRaised identity key.
func extractFindingKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		if e, ok := events.AsValue(evt).(events.FindingRaised); ok {
			s.add(findingKey(e))
		}
	}
	return s
}

// extractNetblockKeys collects routed prefixes.
func extractNetblockKeys(evts []events.DomainEvent) map[string]struct{} {
	s := keySet{}
	for _, evt := range evts {
		if e, ok := events.AsValue(evt).(events.NetblockDiscovered); ok {
			s.add(strings.TrimSpace(e.Prefix))
		}
	}
	return s
}

// findingKey is the rule + assetKind + assetID natural key shared by the finding
// identity and the finding coverage/delta.
func findingKey(e events.FindingRaised) string {
	return keyJoin(normalizeText(e.Rule), normalizeText(e.AssetKind), normalizeText(e.AssetID))
}
