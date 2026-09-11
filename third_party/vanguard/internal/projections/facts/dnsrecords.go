package facts

import (
	"fmt"
	"net"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// applyDNSRecords folds a DnsRecordsDiscovered event. It always emits the owner name
// asset and a dns_lookup_observed observation, then one fact set per record value:
// A/AAAA resolve to IPs (resolves_to), CNAME points to a target (cname_to), MX names a
// mail exchanger (has_mx), PTR names the reverse target of an address (ptr_to), and
// NS/TXT attach DnsRecord nodes (has_ns/has_txt). A null record field emits nothing
// (absence is not negative proof); DNSSEC state is always recorded as observation and
// evidence.
//
// Only NS and TXT materialize a DnsRecord node, because for those two the literal record
// value is the thing being modeled. For A, AAAA, CNAME, MX, and PTR the useful subject is
// the target itself - an address, a name, a mail host - and the direct edge from the owner
// to that target already carries the meaning of the record. A parallel DnsRecord node for
// them was an unreferenced duplicate of an edge that already existed, so it is no longer
// created; the observation, evidence, resolver, priority, and timestamps are unchanged.
func (g *Graph) applyDNSRecords(e events.DnsRecordsDiscovered) {
	m := e.Meta()
	owner := normalizeFQDN(e.Domain)
	if owner == "" {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: m.Severity, Message: "empty DNS owner name", RawEventID: m.EventID})
		return
	}
	// A successful lookup that returned nothing is a real observation of the scan, not
	// of the name: it must not widen the owner's seen window to scan time, or a name
	// that stopped resolving years ago reads as last seen this morning. The name stays
	// in the graph either way; only the temporal claim differs.
	resolved := hasPositiveDNSData(e)
	currentness := CurrentnessUnknown
	owned := Asset{Type: assetTypeFor(owner, g.rootTarget), Key: owner,
		Attributes: map[string]any{attrFQDN: owner}, Sources: srcs(m.Source)}
	if resolved {
		currentness = CurrentnessCurrentlyResolved
		owned.FirstSeen, owned.LastSeen = m.CapturedAt, m.CapturedAt
		g.upsertAssetClaim(owned, claim{SourceObservedAt: m.CapturedAt, Confidence: ConfidenceHigh})
	} else {
		g.upsertAssetClaim(owned, claim{NoSubjectTime: true, Confidence: ConfidenceHigh})
	}
	g.addObservation(Observation{
		ID: obsID(m.EventID, "dns_lookup"), Type: "dns_lookup_observed", AssetKey: owner,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, Currentness: currentness,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID,
		CapturedAt: m.CapturedAt, Metadata: resolverMeta(e.Resolver),
	})

	for _, ip := range e.A {
		g.addAddressRecord(m, owner, e.Resolver, ip, "A")
	}
	for _, ip := range e.AAAA {
		g.addAddressRecord(m, owner, e.Resolver, ip, "AAAA")
	}
	for _, raw := range e.CNAME {
		g.addCNAME(m, owner, raw)
	}
	for _, mx := range e.MX {
		g.addMX(m, owner, mx.Host, int(mx.Priority))
	}
	for _, ns := range e.NS {
		host := normalizeFQDN(ns)
		g.addOwnerRecordEdge(m, owner, "NS", host, RelHasNS, "dns_ns_record_observed",
			"ns_record_evidence", fmt.Sprintf("%s reported nameserver %s for %s.", m.Source, host, owner))
	}
	for _, txt := range e.TXT {
		val := strings.TrimSpace(txt)
		g.addOwnerRecordEdge(m, owner, "TXT", val, RelHasTXT, "dns_txt_record_observed",
			"txt_record_evidence", fmt.Sprintf("%s reported a TXT record for %s.", m.Source, owner))
	}
	for _, ptr := range e.PTR {
		g.addPTR(m, ptr.IP, ptr.Hostname)
	}
	g.addDNSSEC(m, owner, e.DNSSEC, e.Resolver)
}

// hasPositiveDNSData reports whether a DNS event contains at least one usable
// positive answer. A successful but empty or malformed result does not prove that
// the owner currently resolves.
func hasPositiveDNSData(e events.DnsRecordsDiscovered) bool {
	for _, raw := range append(append([]string(nil), e.A...), e.AAAA...) {
		if net.ParseIP(strings.TrimSpace(raw)) != nil {
			return true
		}
	}
	for _, names := range [][]string{e.CNAME, e.NS} {
		for _, name := range names {
			if normalizeFQDN(name) != "" {
				return true
			}
		}
	}
	for _, mx := range e.MX {
		if normalizeFQDN(mx.Host) != "" {
			return true
		}
	}
	for _, txt := range e.TXT {
		if strings.TrimSpace(txt) != "" {
			return true
		}
	}
	for _, ptr := range e.PTR {
		if net.ParseIP(strings.TrimSpace(ptr.IP)) != nil && normalizeFQDN(ptr.Hostname) != "" {
			return true
		}
	}
	return e.SOA != nil || e.DNSSEC
}

// addAddressRecord emits the IPAddress, the record observation, the resolution evidence,
// and the resolves_to edge for one A/AAAA value. An unparseable address is quarantined
// and the rest of the event still normalizes.
func (g *Graph) addAddressRecord(m events.EventMeta, owner, resolver, rawIP, recordType string) {
	ip, version, ok := normalizeIP(rawIP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid %s record %q for %s", recordType, rawIP, owner), RawEventID: m.EventID})
		return
	}
	g.upsertAsset(Asset{Type: AssetIPAddress, Key: ip,
		Attributes: map[string]any{"ip": ip, attrIPVersion: version},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	lower := strings.ToLower(recordType)
	oid := obsID(m.EventID, "dns_"+lower+":"+ip)
	g.addObservation(Observation{ID: oid, Type: "dns_" + lower + "_record_observed", AssetKey: owner,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{attrRecordType: recordType, attrValue: ip, attrResolver: resolver}})
	eid := evID(m.EventID, "resolves_to:"+ip)
	g.addEvidence(Evidence{ID: eid, Type: "dns_resolution_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("%s reported that %s resolved to %s.", m.Source, owner, ip),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, RawEventID: m.EventID})
	g.upsertRelationship(Relationship{Type: RelResolvesTo, From: owner, To: ip, EvidenceID: eid,
		Confidence: ConfidenceHigh, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// addCNAME emits the target name asset and the cname_to edge. The
// target is typed by scope (assetTypeFor): a target under the scan root is a Subdomain,
// one outside it an ExternalDomain, so a provider hostname like autodiscover.outlook.com
// is kept with its evidence and edge but never counted as an in-scope subdomain.
func (g *Graph) addCNAME(m events.EventMeta, owner, raw string) {
	target := normalizeFQDN(raw)
	if target == "" {
		return
	}
	// A wildcard is a zone directive, not a name that exists. Materializing it would put
	// a node in the graph that nothing can ever resolve, and the edge to it would be a
	// claim about a name no host answers on.
	if isWildcard(target) {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("wildcard CNAME target %q for %s", target, owner), RawEventID: m.EventID})
		return
	}
	g.upsertAsset(Asset{Type: assetTypeFor(target, g.rootTarget), Key: target,
		Attributes: map[string]any{attrFQDN: target},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	oid := obsID(m.EventID, "dns_cname:"+target)
	g.addObservation(Observation{ID: oid, Type: "dns_cname_record_observed", AssetKey: owner,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt})
	eid := evID(m.EventID, "cname_to:"+target)
	g.addEvidence(Evidence{ID: eid, Type: "cname_record_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("%s reported that %s is a CNAME for %s.", m.Source, owner, target),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, RawEventID: m.EventID})
	g.upsertRelationship(Relationship{Type: RelCnameTo, From: owner, To: target, EvidenceID: eid,
		Confidence: ConfidenceHigh, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// addMX emits the MailService asset and the has_mx edge (priority as metadata).
func (g *Graph) addMX(m events.EventMeta, owner, rawHost string, priority int) {
	host := normalizeFQDN(rawHost)
	if host == "" {
		return
	}
	if isWildcard(host) {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("wildcard MX host %q for %s", host, owner), RawEventID: m.EventID})
		return
	}
	g.upsertAsset(Asset{Type: AssetMailService, Key: host,
		Attributes: map[string]any{attrHost: host},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	oid := obsID(m.EventID, "dns_mx:"+host)
	g.addObservation(Observation{ID: oid, Type: "dns_mx_record_observed", AssetKey: owner,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{attrHost: host, attrPriority: priority}})
	eid := evID(m.EventID, "mx:"+host)
	g.addEvidence(Evidence{ID: eid, Type: "mx_record_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("%s reported mail exchanger %s for %s.", m.Source, host, owner),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, RawEventID: m.EventID})
	g.upsertRelationship(Relationship{Type: RelHasMX, From: owner, To: host, EvidenceID: eid,
		Confidence: ConfidenceHigh, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Metadata: map[string]any{attrPriority: priority}})
}

// addOwnerRecordEdge emits a DnsRecord asset, its observation and evidence, and an edge
// from the owner to that record. It backs the NS and TXT record types, whose MVP target
// is the DnsRecord node itself.
func (g *Graph) addOwnerRecordEdge(m events.EventMeta, owner, recordType, value string,
	rel RelationshipType, obsType, evType, statement string) {
	if value == "" {
		return
	}
	recKey := dnsRecordKey(owner, recordType, value)
	g.upsertAsset(Asset{Type: AssetDNSRecord, Key: recKey,
		Attributes: map[string]any{attrOwner: owner, attrRecordType: recordType, attrValue: value},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	lower := strings.ToLower(recordType)
	oid := obsID(m.EventID, "dns_"+lower+":"+value)
	g.addObservation(Observation{ID: oid, Type: obsType, AssetKey: owner,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt})
	eid := evID(m.EventID, lower+":"+value)
	g.addEvidence(Evidence{ID: eid, Type: evType, ObservationID: oid, Statement: statement,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, RawEventID: m.EventID})
	g.upsertRelationship(Relationship{Type: rel, From: owner, To: recKey, EvidenceID: eid,
		Confidence: ConfidenceHigh, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// addPTR folds one reverse-DNS answer: the IPAddress, the target name, and a ptr_to edge
// from the address to that name.
//
// The edge is medium confidence and never resolves_to. A PTR record is published by
// whoever controls the address block, so it states what that operator calls the address;
// it is not proof that the name resolves back to it, and shared hosting, cloud providers,
// and mail relays disagree with forward DNS routinely. Keeping the two edge types apart is
// what lets a consumer see the disagreement instead of inheriting it as a forward record.
// A reverse answer with no hostname is a real observation of an address with no PTR, so it
// is recorded without an edge rather than dropped.
func (g *Graph) addPTR(m events.EventMeta, rawIP, rawHost string) {
	ip, version, ok := normalizeIP(rawIP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid PTR record IP %q", rawIP), RawEventID: m.EventID})
		return
	}
	host := normalizeFQDN(rawHost)
	if isWildcard(host) {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("wildcard PTR hostname %q for %s", host, ip), RawEventID: m.EventID})
		host = ""
	}
	g.upsertAsset(Asset{Type: AssetIPAddress, Key: ip,
		Attributes: map[string]any{"ip": ip, attrIPVersion: version},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	oid := obsID(m.EventID, "dns_ptr:"+ip)
	g.addObservation(Observation{ID: oid, Type: "dns_ptr_record_observed", AssetKey: ip,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{"hostname": host}})
	eid := evID(m.EventID, "ptr:"+ip)
	g.addEvidence(Evidence{ID: eid, Type: "ptr_record_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("%s had PTR hostname %s.", ip, host),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID})
	if host == "" {
		return
	}
	g.upsertAsset(Asset{Type: assetTypeFor(host, g.rootTarget), Key: host,
		Attributes: map[string]any{attrFQDN: host},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	g.upsertRelationship(Relationship{Type: RelPtrTo, From: ip, To: host, EvidenceID: eid,
		Confidence: ConfidenceMedium, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// addDNSSEC records the DNSSEC state as observation and evidence (no edge, no finding).
func (g *Graph) addDNSSEC(m events.EventMeta, owner string, dnssec bool, resolver string) {
	oid := obsID(m.EventID, "dnssec")
	g.addObservation(Observation{ID: oid, Type: "dnssec_state_observed", AssetKey: owner,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{"dnssec": dnssec, attrResolver: resolver}})
	g.addEvidence(Evidence{ID: evID(m.EventID, "dnssec"), Type: "dnssec_state_evidence", ObservationID: oid,
		Statement: fmt.Sprintf("%s reported DNSSEC=%t for %s.", m.Source, dnssec, owner),
		Source:    m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, RawEventID: m.EventID})
}

// resolverMeta returns the resolver observation metadata, or nil when unknown.
func resolverMeta(resolver string) map[string]any {
	if resolver == "" {
		return nil
	}
	return map[string]any{attrResolver: resolver}
}
