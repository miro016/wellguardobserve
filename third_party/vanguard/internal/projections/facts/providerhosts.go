package facts

import (
	"fmt"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// providerService is one service a flat-list provider (shodan, netlas) reported:
// the port and the transport it was observed on, empty when the provider stated
// none.
type providerService struct {
	Port      int
	Transport string
}

// applyShodanHosts folds a ShodanHostsDiscovered event into passive host facts.
func (g *Graph) applyShodanHosts(e events.ShodanHostsDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain != "" {
		g.ensureDomain(m, domain)
	}
	if e.Truncated {
		g.addIssue(Issue{Type: issueIncompletePassiveResult, Source: m.Source, Severity: events.SeverityLow,
			Message: "shodan result truncated; host coverage may be incomplete for " + domain, RawEventID: m.EventID})
	}
	for _, h := range e.Hosts {
		services := make([]providerService, 0, len(h.Services))
		for _, s := range h.Services {
			services = append(services, providerService{Port: s.Port, Transport: s.Transport})
		}
		g.addProviderHost(m, domain, h.IP, services, h.ASN, h.OS, h.Products, h.Vulns, h.SourceObservedAt)
	}
}

// applyNetlasHosts folds a NetlasHostsDiscovered event into passive host facts.
func (g *Graph) applyNetlasHosts(e events.NetlasHostsDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain != "" {
		g.ensureDomain(m, domain)
	}
	if e.Truncated {
		g.addIssue(Issue{Type: issueIncompletePassiveResult, Source: m.Source, Severity: events.SeverityLow,
			Message: "netlas result truncated; host coverage may be incomplete for " + domain, RawEventID: m.EventID})
	}
	for _, h := range e.Hosts {
		services := make([]providerService, 0, len(h.Services))
		for _, s := range h.Services {
			services = append(services, providerService{Port: s.Port, Transport: s.Transport})
		}
		g.addProviderHost(m, domain, h.IP, services, h.ASN, "", h.Products, h.Vulns, h.SourceObservedAt)
	}
}

// addProviderHost folds one passive host record from Shodan or Netlas: the IPAddress, its
// open ports as passive Service assets (exposes_service, medium), the ASN provider
// (hosted_by_provider), host-level products (host_observed_technology), OS as evidence,
// and any CVE intel as evidence. It never emits runs_technology - the product carries no
// port mapping, so which service runs it is unknown - or a finding candidate.
// It mirrors applyCensysHost for the shodan/netlas host shape.
//
// sourceObservedAt is the provider's real-world observation time for the host (Shodan's
// latest banner timestamp), seeding the host assets' seen window and every assertion this
// record makes. A zero value falls back to scan time for ordering only and is recorded as
// a missing source time, never as evidence the host was up during the scan.
func (g *Graph) addProviderHost(m events.EventMeta, domain, rawIP string, services []providerService, asnRaw, os string, products, vulns []string, sourceObservedAt time.Time) {
	seen := realSeen(m, sourceObservedAt)
	hostClaim := claim{SourceObservedAt: sourceObservedAt, Confidence: ConfidenceMedium}
	ip, version, ok := normalizeIP(rawIP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid %s host IP %q", m.Source, rawIP), RawEventID: m.EventID})
		return
	}
	g.upsertAssetClaim(Asset{Type: AssetIPAddress, Key: ip,
		Attributes: map[string]any{"ip": ip, attrIPVersion: version},
		FirstSeen:  seen, LastSeen: seen, Sources: srcs(m.Source)}, hostClaim)
	g.addObsEvidence(m, ip, m.Source+"_host_observed", "passive_host_intelligence_evidence", "host:"+ip,
		fmt.Sprintf("%s reported %s as related to %s.", m.Source, ip, domain), ConfidenceMedium,
		map[string]any{attrQueryDomain: domain})

	for _, svc := range services {
		if svc.Port < 1 || svc.Port > 65535 {
			continue
		}
		// The provider's own transport is carried through. A provider that named
		// none leaves the service keyed on the explicit unknown transport, so it
		// stays visible as an observation without ever colliding with, upgrading, or
		// standing in for the TCP service on the same port.
		transport, okTransport := normalizeProviderTransport(svc.Transport)
		if !okTransport {
			g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
				Message:    fmt.Sprintf("unsupported %s transport %q on %s:%d", m.Source, svc.Transport, ip, svc.Port),
				RawEventID: m.EventID})
			continue
		}
		sid := entities.NewServiceID(ip, svc.Port, transport).String()
		p := svc.Port
		g.upsertAssetClaim(Asset{Type: AssetService, Key: sid,
			Attributes: map[string]any{"ip": ip, attrPort: p, attrTransport: transport,
				attrExposureSource: m.Source, attrExposureMode: "passive"},
			FirstSeen: seen, LastSeen: seen, Sources: srcs(m.Source)}, hostClaim)
		disc := "service:" + sid
		g.addObsEvidence(m, sid, m.Source+"_service_observed", "passive_service_exposure_evidence", disc,
			fmt.Sprintf("%s reported %s/%d on %s.", m.Source, transport, p, ip), ConfidenceMedium,
			map[string]any{attrPort: p})
		g.upsertRelationshipClaim(Relationship{Type: RelExposesService, From: ip, To: sid,
			EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceMedium, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: seen, LastSeen: seen}, hostClaim)
	}

	if n, okASN := parseASNString(asnRaw); okASN {
		pk := providerKey(n)
		g.upsertAssetClaim(Asset{Type: AssetProvider, Key: pk,
			Attributes: map[string]any{attrASNNumber: n},
			FirstSeen:  seen, LastSeen: seen, Sources: srcs(m.Source)}, hostClaim)
		disc := "asn:" + pk
		g.addObsEvidence(m, ip, m.Source+"_asn_observed", "provider_attribution_evidence", disc,
			fmt.Sprintf("%s attributed %s to AS%d.", m.Source, ip, n), ConfidenceMedium,
			map[string]any{attrASNNumber: n})
		g.upsertRelationshipClaim(Relationship{Type: RelHostedByProvider, From: ip, To: pk,
			EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceMedium, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: seen, LastSeen: seen}, hostClaim)
	}

	for _, prod := range products {
		name, okProd := normalizeProduct(prod)
		if !okProd {
			continue
		}
		g.upsertAssetClaim(Asset{Type: AssetTechnology, Key: name, Attributes: map[string]any{attrName: name},
			FirstSeen: seen, LastSeen: seen, Sources: srcs(m.Source)}, hostClaim)
		disc := "product:" + ip + ":" + name
		g.addObsEvidence(m, ip, m.Source+"_product_observed", "passive_technology_evidence", disc,
			fmt.Sprintf("%s observed product %s on host %s, with no mapping to a listening service.", m.Source, name, ip),
			ConfidenceMedium, map[string]any{attrProduct: name, "mapping_level": attrHost})
		g.upsertRelationshipClaim(Relationship{Type: RelHostObservedTechnology, From: ip, To: name,
			EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceMedium, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: seen, LastSeen: seen}, hostClaim)
	}

	if os != "" {
		g.addObsEvidence(m, ip, m.Source+"_os_observed", "passive_os_fingerprint_evidence", "os:"+ip,
			fmt.Sprintf("%s reported OS=%s for %s.", m.Source, os, ip), ConfidenceLow,
			map[string]any{"os": os})
	}

	for _, v := range vulns {
		cve := strings.TrimSpace(v)
		if cve == "" {
			continue
		}
		g.addObsEvidence(m, ip, m.Source+"_vulnerability_observed", "passive_vulnerability_intelligence_evidence",
			"vuln:"+ip+":"+cve, fmt.Sprintf("%s attributed %s to %s.", m.Source, cve, ip),
			ConfidenceMedium, map[string]any{"cve": cve})
	}
}
