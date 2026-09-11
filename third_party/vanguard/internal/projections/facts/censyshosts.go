package facts

import (
	"fmt"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// censysObservedWindow returns the earliest and latest scan_time across a host's
// services. A service without scan_time falls back to the event's scan time, matching
// the per-service fold and keeping the host window complete. The fallback is recorded as
// a missing source time on the assertion, so it cannot read as a real observation.
func censysObservedWindow(m events.EventMeta, svcs []valueobjects.CensysService) (firstSeen, lastSeen time.Time) {
	if len(svcs) == 0 {
		return m.CapturedAt, m.CapturedAt
	}
	for _, s := range svcs {
		seen := realSeen(m, s.SourceObservedAt)
		if firstSeen.IsZero() || seen.Before(firstSeen) {
			firstSeen = seen
		}
		if seen.After(lastSeen) {
			lastSeen = seen
		}
	}
	return firstSeen, lastSeen
}

// applyCensysHosts folds a CensysHostsDiscovered event. Censys is passive third-party
// intelligence, so everything it produces is medium confidence and passive mode: per
// host it emits the IPAddress, its services (exposes_service), ASN provider
// (hosted_by_provider), host-level technologies (host_observed_technology), OS as
// evidence, source attribution, and any passive CVE intel as evidence. It deliberately
// does not emit runs_technology (no service-level product mapping), a Domain->IP edge
// (no concrete hostname), or any finding candidate. A truncated result is a coverage
// issue.
func (g *Graph) applyCensysHosts(e events.CensysHostsDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain != "" {
		g.upsertAsset(Asset{Type: assetTypeFor(domain, g.rootTarget), Key: domain,
			Attributes: map[string]any{attrFQDN: domain, "role": attrQueryDomain},
			FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	}
	if e.Truncated {
		g.addIssue(Issue{Type: issueIncompletePassiveResult, Source: m.Source, Severity: events.SeverityLow,
			Message: "censys result truncated; host coverage may be incomplete for " + domain, RawEventID: m.EventID})
	}
	for _, h := range e.Hosts {
		g.applyCensysHost(m, domain, h)
	}
}

// applyCensysHost folds one Censys host record.
func (g *Graph) applyCensysHost(m events.EventMeta, domain string, h valueobjects.CensysHost) {
	ip, version, ok := normalizeIP(h.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid censys host IP %q", h.IP), RawEventID: m.EventID})
		return
	}
	// The host's real-world window spans the scan_time values across its services;
	// per-service assets keep their own scan_time below.
	hostFirstSeen, hostLastSeen := censysObservedWindow(m, h.Services)
	// The host assertion carries the newest scan_time across its services, which is the
	// only provider time that is true of the host itself. Each service keeps its own
	// below; nothing borrows a sibling's timestamp.
	hostClaim := claim{SourceObservedAt: latestCensysObservation(h.Services), Confidence: ConfidenceMedium}
	g.upsertAssetClaim(Asset{Type: AssetIPAddress, Key: ip,
		Attributes: map[string]any{"ip": ip, attrIPVersion: version},
		FirstSeen:  hostFirstSeen, LastSeen: hostLastSeen, Sources: srcs(m.Source)}, hostClaim)
	hostDisc := "host:" + ip
	g.addObservation(Observation{ID: obsID(m.EventID, hostDisc), Type: "censys_host_observed", AssetKey: ip,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: censysHostMeta(domain, h)})
	g.addEvidence(Evidence{ID: evID(m.EventID, hostDisc), Type: "passive_host_intelligence_evidence",
		ObservationID: obsID(m.EventID, hostDisc),
		Statement:     fmt.Sprintf("Censys reported %s as related to %s.", ip, domain),
		Source:        m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID})

	for _, svc := range h.Services {
		g.addCensysService(m, ip, svc)
	}
	if h.ASN != nil {
		g.addCensysASN(m, ip, h.ASN, hostFirstSeen, hostLastSeen, hostClaim, h.NetworkAllocatedAt, h.NetworkCIDRs)
	}
	for _, p := range h.Products {
		g.addCensysProduct(m, ip, p, hostFirstSeen, hostLastSeen, hostClaim)
	}
	if os := strings.TrimSpace(h.OS); os != "" {
		oid := obsID(m.EventID, "os:"+ip)
		g.addObservation(Observation{ID: oid, Type: "censys_os_observed", AssetKey: ip,
			Source: m.Source, Mode: m.Phase, Confidence: ConfidenceLow,
			RawEventID: m.EventID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
			Metadata: map[string]any{"os": os}})
		g.addEvidence(Evidence{ID: evID(m.EventID, "os:"+ip), Type: "passive_os_fingerprint_evidence",
			ObservationID: oid, Statement: fmt.Sprintf("Censys reported OS=%s for %s.", os, ip),
			Source: m.Source, Mode: m.Phase, Confidence: ConfidenceLow, RawEventID: m.EventID})
	}
	if len(h.Sources) > 0 {
		g.addObservation(Observation{ID: obsID(m.EventID, "sources:"+ip), Type: "censys_source_attribution_observed",
			AssetKey: ip, Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
			RawEventID: m.EventID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
			Metadata: map[string]any{"sources": h.Sources, attrQueryDomain: domain}})
	}
	for _, v := range h.Vulns {
		g.addCensysVuln(m, ip, v)
	}
}

// addCensysService emits a passive Service asset keyed by the canonical ServiceID plus
// its observation, exposure evidence, and exposes_service edge.
func (g *Graph) addCensysService(m events.EventMeta, ip string, svc valueobjects.CensysService) {
	if svc.Port < 1 || svc.Port > 65535 {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid censys service port %d on %s", svc.Port, ip), RawEventID: m.EventID})
		return
	}
	transport, okTransport := normalizeProviderTransport(svc.Transport)
	if !okTransport {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message:    fmt.Sprintf("unsupported censys transport %q on %s:%d", svc.Transport, ip, svc.Port),
			RawEventID: m.EventID})
		return
	}
	protocol := normalizeProtocol(svc.Protocol)
	svcSeen := realSeen(m, svc.SourceObservedAt)
	svcClaim := claim{SourceObservedAt: svc.SourceObservedAt, Confidence: ConfidenceMedium}
	sid := entities.NewServiceID(ip, svc.Port, transport).String()
	g.upsertAssetClaim(Asset{Type: AssetService, Key: sid,
		Attributes: map[string]any{"ip": ip, attrPort: svc.Port, attrTransport: transport, "protocol": protocol,
			attrExposureSource: "censys", attrExposureMode: "passive"},
		FirstSeen: svcSeen, LastSeen: svcSeen, Sources: srcs(m.Source)}, svcClaim)
	disc := "service:" + sid
	oid := obsID(m.EventID, disc)
	g.addObservation(Observation{ID: oid, Type: "censys_service_observed", AssetKey: sid,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		SourceObservedAt: svc.SourceObservedAt,
		Metadata:         map[string]any{"ip": ip, attrPort: svc.Port, attrTransport: transport, "protocol": protocol}})
	eid := evID(m.EventID, disc)
	g.addEvidence(Evidence{ID: eid, Type: "passive_service_exposure_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("Censys reported %s/%d %s on %s.", transport, svc.Port, protocol, ip),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID})
	g.upsertRelationshipClaim(Relationship{Type: RelExposesService, From: ip, To: sid, EvidenceID: eid,
		Confidence: ConfidenceMedium, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: svcSeen, LastSeen: svcSeen}, svcClaim)
}

// addCensysASN emits the Provider asset, its attribution observation and evidence, and
// the hosted_by_provider edge. firstSeen/lastSeen span the host's service observations.
func (g *Graph) addCensysASN(m events.EventMeta, ip string, asn *valueobjects.CensysASN, firstSeen, lastSeen time.Time, cl claim, allocatedAt time.Time, cidrs []string) {
	pk := providerKey(asn.Number)
	attrs := map[string]any{attrASNNumber: asn.Number, attrName: asn.Name, "description": asn.Description}
	if !allocatedAt.IsZero() {
		attrs["network_allocated_at"] = allocatedAt
	}
	if len(cidrs) > 0 {
		attrs["network_cidrs"] = append([]string(nil), cidrs...)
	}
	// The network's allocation date is an earlier real-world anchor than the scan snapshot,
	// so it lowers the provider's first_seen when present.
	provFirstSeen := firstSeen
	if !allocatedAt.IsZero() && (provFirstSeen.IsZero() || allocatedAt.Before(provFirstSeen)) {
		provFirstSeen = allocatedAt
	}
	g.upsertAssetClaim(Asset{Type: AssetProvider, Key: pk, Attributes: attrs,
		FirstSeen: provFirstSeen, LastSeen: lastSeen, Sources: srcs(m.Source)}, cl)
	// Record the allocation as the start of an open-ended validity interval, not a point
	// observation: the network's registration opened at this instant and (as far as we
	// know) still holds, so ValidFrom with no ValidUntil is the faithful shape. Modeling it
	// as a point SourceObservedAt would feed the observation-freshness check, which would
	// then flag a years-old allocation date as a stale provider observation on every scan.
	// As an interval start it still counts as a source-dated assertion and lowers the
	// provider's earliest-known time, but it never outranks a fresh scan observation
	// (freshSource wins in classification) and never trips the staleness anomaly.
	if !allocatedAt.IsZero() {
		g.upsertAssetClaim(Asset{Type: AssetProvider, Key: pk,
			FirstSeen: allocatedAt, LastSeen: allocatedAt, Sources: srcs(m.Source)},
			claim{ValidFrom: allocatedAt, Confidence: ConfidenceMedium})
	}
	disc := "asn:" + pk
	oid := obsID(m.EventID, disc)
	g.addObservation(Observation{ID: oid, Type: "censys_asn_observed", AssetKey: ip,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{attrASNNumber: asn.Number, "asn_name": asn.Name}})
	eid := evID(m.EventID, disc)
	g.addEvidence(Evidence{ID: eid, Type: "provider_attribution_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("Censys attributed %s to ASN %d %s.", ip, asn.Number, asn.Name),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID})
	g.upsertRelationshipClaim(Relationship{Type: RelHostedByProvider, From: ip, To: pk, EvidenceID: eid,
		Confidence: ConfidenceMedium, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: firstSeen, LastSeen: lastSeen}, cl)
}

// addCensysProduct emits a host-level Technology asset with its observation, evidence,
// and a host_observed_technology edge from the address. firstSeen/lastSeen span the
// host's service observations.
//
// The edge is deliberately not runs_technology. Censys reports products at host level
// with no port mapping, so the honest claim is that the product was seen on the host,
// not that a particular listening service runs it. The evidence statement says exactly
// that, and only an independent service or endpoint fingerprint - which arrives through
// addTechnology - can add the stronger edge. Repeated observations of one product merge
// onto the same edge and keep every assertion, so several Censys snapshots at different
// scan times stay individually readable.
func (g *Graph) addCensysProduct(m events.EventMeta, ip, raw string, firstSeen, lastSeen time.Time, cl claim) {
	name, ok := normalizeProduct(raw)
	if !ok {
		return
	}
	g.upsertAssetClaim(Asset{Type: AssetTechnology, Key: name,
		Attributes: map[string]any{attrName: name},
		FirstSeen:  firstSeen, LastSeen: lastSeen, Sources: srcs(m.Source)}, cl)
	disc := "product:" + name
	oid := obsID(m.EventID, disc)
	g.addObservation(Observation{ID: oid, Type: "censys_product_observed", AssetKey: ip,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		SourceObservedAt: cl.SourceObservedAt,
		Metadata:         map[string]any{attrProduct: name, "mapping_level": attrHost}})
	eid := evID(m.EventID, disc)
	g.addEvidence(Evidence{ID: eid, Type: "passive_technology_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("Censys observed product %s on host %s, with no mapping to a listening service.", name, ip),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID})
	g.upsertRelationshipClaim(Relationship{Type: RelHostObservedTechnology, From: ip, To: name,
		EvidenceID: eid, Confidence: ConfidenceMedium, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: firstSeen, LastSeen: lastSeen}, cl)
}

// addCensysVuln records a passive CVE hypothesis as observation and evidence only. It
// never becomes a finding candidate directly; a later detector/validation event can
// consume this evidence.
func (g *Graph) addCensysVuln(m events.EventMeta, ip, cve string) {
	cve = strings.TrimSpace(cve)
	if cve == "" {
		return
	}
	disc := "vuln:" + ip + ":" + cve
	oid := obsID(m.EventID, disc)
	g.addObservation(Observation{ID: oid, Type: "censys_vulnerability_observed", AssetKey: ip,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{"cve": cve}})
	g.addEvidence(Evidence{ID: evID(m.EventID, disc), Type: "passive_vulnerability_intelligence_evidence",
		ObservationID: oid, Statement: fmt.Sprintf("Censys attributed %s to %s.", cve, ip),
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID})
}

// latestCensysObservation returns the newest provider scan_time on a host.
func latestCensysObservation(services []valueobjects.CensysService) time.Time {
	var latest time.Time
	for _, service := range services {
		if service.SourceObservedAt.After(latest) {
			latest = service.SourceObservedAt
		}
	}
	return latest
}

// censysHostMeta gathers the host-level enrichment (query domain, match sources,
// location, reputation, labels) as observation metadata.
func censysHostMeta(domain string, h valueobjects.CensysHost) map[string]any {
	md := map[string]any{attrQueryDomain: domain}
	if len(h.Sources) > 0 {
		md["sources"] = h.Sources
	}
	if h.Location != nil {
		md["location"] = map[string]any{"country": h.Location.Country, "city": h.Location.City}
	}
	if h.Reputation != "" {
		md["reputation"] = h.Reputation
	}
	if len(h.Labels) > 0 {
		md["labels"] = h.Labels
	}
	return md
}
