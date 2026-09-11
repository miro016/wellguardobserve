package facts

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// applyZoneTransfer folds a ZoneTransferDiscovered event: a zone_transfer_observed fact
// on the domain plus a DnsRecord asset per transferred record, joined to its owner name
// by a has_dns_record edge. A successful AXFR is a misconfiguration, but the finding
// itself arrives as a separate FindingRaised event that the finding path folds into a
// candidate; here it is recorded as discovery facts.
//
// The transfer dumps records of every type, including types with no dedicated edge, so
// the generic owner edge is what keeps each record reachable. Without it the dump lands
// in the graph as a pile of nodes nothing points at, which is exactly as useful as not
// recording it.
func (g *Graph) applyZoneTransfer(e events.ZoneTransferDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	g.addObsEvidence(m, domain, "zone_transfer_observed", "zone_transfer_evidence", "axfr:"+domain,
		fmt.Sprintf("%s completed a zone transfer of %s from %s (%d record(s)).",
			m.Source, domain, e.Nameserver, len(e.Records)), ConfidenceHigh,
		map[string]any{"nameserver": e.Nameserver, "record_count": len(e.Records)})

	for _, r := range e.Records {
		owner := normalizeFQDN(r.Name)
		val := strings.TrimSpace(r.Value)
		recordType := strings.ToUpper(strings.TrimSpace(r.Type))
		if owner == "" || val == "" || recordType == "" {
			continue
		}
		recKey := dnsRecordKey(owner, recordType, val)
		g.upsertAsset(Asset{Type: AssetDNSRecord, Key: recKey,
			Attributes: map[string]any{attrOwner: owner, attrRecordType: recordType, attrValue: val},
			FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
		g.ensureDomain(m, owner)
		g.upsertRelationship(Relationship{Type: RelHasDNSRecord, From: owner, To: recKey,
			EvidenceID: evID(m.EventID, "axfr:"+domain), Confidence: ConfidenceHigh, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
	}
}
