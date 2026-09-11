package facts

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// applyIPAddress folds an IPAddressDiscovered event: the IPAddress asset plus a
// resolves_to edge from the attributed name, at a confidence that reflects whether the
// address was DNS-resolved (confirmed/high) or provider-attributed (inferred/medium).
func (g *Graph) applyIPAddress(e events.IPAddressDiscovered) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid IP %q attributed to %s", e.IP, e.Domain), RawEventID: m.EventID})
		return
	}
	g.ensureIP(m, ip, version)
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	conf := mapEventConfidence(e.Confidence)
	disc := "ip_attribution:" + ip
	md := map[string]any{"ip": ip, "confidence": string(conf)}
	if e.RecordType != "" {
		md[attrRecordType] = e.RecordType
	}
	g.addObsEvidence(m, ip, "ip_attribution_observed", "ip_attribution_evidence", disc,
		fmt.Sprintf("%s attributed %s to %s.", m.Source, ip, domain), conf, md)
	g.upsertRelationship(Relationship{Type: RelResolvesTo, From: domain, To: ip,
		EvidenceID: evID(m.EventID, disc), Confidence: conf, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// applyNetblock folds a NetblockDiscovered event: the Netblock asset, the Provider from
// the announcing ASN, and the belongs_to_asn edge. The event carries no member IP, so no
// ip_in_netblock edge is emitted here.
func (g *Graph) applyNetblock(e events.NetblockDiscovered) {
	m := e.Meta()
	prefix := e.Prefix
	if prefix == "" {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: "netblock event without a prefix", RawEventID: m.EventID})
		return
	}
	g.upsertAsset(Asset{Type: AssetNetblock, Key: prefix,
		Attributes: map[string]any{"prefix": prefix, attrASNNumber: e.ASN, attrName: e.Name,
			"country": e.Country, "registry": e.Registry},
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	g.addObsEvidence(m, prefix, "netblock_observed", "netblock_evidence", "netblock:"+prefix,
		fmt.Sprintf("%s reported %s announced by AS%d (%s).", m.Source, prefix, e.ASN, e.Name),
		ConfidenceHigh, map[string]any{attrASNNumber: e.ASN, "registry": e.Registry})
	if e.ASN <= 0 {
		return
	}
	pk := providerKey(e.ASN)
	g.upsertAsset(Asset{Type: AssetProvider, Key: pk,
		Attributes: map[string]any{attrASNNumber: e.ASN, attrName: e.Name},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	g.upsertRelationship(Relationship{Type: RelBelongsToASN, From: prefix, To: pk,
		EvidenceID: evID(m.EventID, "netblock:"+prefix), Confidence: ConfidenceHigh, Mode: m.Phase,
		SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// applyReachability folds an IPReachabilityObserved event as a coverage signal on the IP
// (no evidence, no edge): a false Reachable is a coverage gap, not a clean negative.
func (g *Graph) applyReachability(e events.IPReachabilityObserved) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		return
	}
	g.upsertAsset(Asset{Type: AssetIPAddress, Key: ip,
		Attributes: map[string]any{"ip": ip, attrIPVersion: version, "reachability": e.State},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	currentness := liveVerifiedCurrentness(m.ObservationKind, e.Reachable)
	g.addObservation(Observation{ID: obsID(m.EventID, "reachability:"+ip), Type: "ip_reachability_observed",
		AssetKey: ip, Source: m.Source, Mode: m.Phase, Confidence: ConfidenceHigh, Currentness: currentness,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID, CapturedAt: m.CapturedAt,
		Metadata: map[string]any{"reachable": e.Reachable, "state": e.State, "reason": e.Reason}})
}

// applyHostOS folds a HostOSGuessed event as a low-confidence, inferred OS guess on the IP.
func (g *Graph) applyHostOS(e events.HostOSGuessed) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		return
	}
	g.ensureIP(m, ip, version)
	g.addObsEvidence(m, ip, "host_os_guessed", "host_os_guess_evidence", "os_guess:"+ip,
		fmt.Sprintf("%s guessed OS %s for %s (%s).", m.Source, e.OS, ip, e.Method),
		ConfidenceLow, map[string]any{"os": e.OS, "method": e.Method})
}
