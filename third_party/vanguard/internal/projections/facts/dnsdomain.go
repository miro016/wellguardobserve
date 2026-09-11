package facts

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// applyDNSDomainName folds a DnsDomainNameDiscovered event. A root event (Depth 0 or no
// parent) emits a Domain asset and a domain_observed observation. A subdomain event
// emits the parent Domain, the Subdomain, a subdomain_observed observation, and - when
// the child validates as a name under the parent - a subdomain_relationship_evidence and
// a subdomain_of relationship. Wildcards and empty/invalid names are quarantined as
// issues instead of materialized.
func (g *Graph) applyDNSDomainName(e events.DnsDomainNameDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	switch {
	case domain == "":
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: m.Severity, Message: "empty domain name", RawEventID: m.EventID})
		return
	case isWildcard(domain):
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: m.Severity, Message: "wildcard domain not materialized: " + domain, RawEventID: m.EventID})
		return
	}

	// A passive source may report when it last saw the name resolve (VirusTotal last_seen);
	// use it as the name's real-world seen instant so a passively-known name lands on the
	// timeline at when it was observed rather than at scan time. The min/max fold refines it
	// against any earlier signal (a covering cert). Empty falls back to scan time.
	nameSeen := realSeen(m, e.SourceObservedAt)
	nameClaim := claim{SourceObservedAt: e.SourceObservedAt, Confidence: ConfidenceMedium}

	parent := normalizeFQDN(e.ParentDomain)
	if e.Depth == 0 || parent == "" {
		g.upsertAssetClaim(Asset{
			Type: assetTypeFor(domain, g.rootTarget), Key: domain,
			Attributes: map[string]any{attrFQDN: domain},
			FirstSeen:  nameSeen, LastSeen: nameSeen, Sources: srcs(m.Source),
		}, nameClaim)
		g.addObservation(Observation{
			ID: obsID(m.EventID, "domain_observed"), Type: "domain_observed", AssetKey: domain,
			Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
			RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID,
			CapturedAt: m.CapturedAt, SourceObservedAt: e.SourceObservedAt, Metadata: discoveryMeta(e, parent),
		})
		return
	}

	// The parent is only mentioned by this event, never observed by it.
	g.ensureDomain(m, parent)
	g.upsertAssetClaim(Asset{
		Type: AssetSubdomain, Key: domain,
		Attributes: map[string]any{attrFQDN: domain, "parent_domain_key": parent, "depth": e.Depth},
		FirstSeen:  nameSeen, LastSeen: nameSeen, Sources: srcs(m.Source),
	}, nameClaim)
	g.addObservation(Observation{
		ID: obsID(m.EventID, "subdomain_observed"), Type: "subdomain_observed", AssetKey: domain,
		Source: m.Source, Mode: m.Phase, Confidence: ConfidenceMedium,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID,
		CapturedAt: m.CapturedAt, SourceObservedAt: e.SourceObservedAt, Metadata: discoveryMeta(e, parent),
	})

	// Parent validation: the child must be a name under the parent, else record the name
	// but do not assert a false subdomain_of edge.
	if domain == parent || !strings.HasSuffix(domain, "."+parent) {
		g.addIssue(Issue{
			Type: issueQuarantine, Source: m.Source, Severity: m.Severity,
			Message:    fmt.Sprintf("subdomain %q not under parent %q; subdomain_of skipped", domain, parent),
			RawEventID: m.EventID,
		})
		return
	}

	ev := Evidence{
		ID: evID(m.EventID, "subdomain_of"), Type: "subdomain_relationship_evidence",
		ObservationID: obsID(m.EventID, "subdomain_observed"),
		Statement:     fmt.Sprintf("%s reported %s as a subdomain of %s.", m.Source, domain, parent),
		Source:        m.Source, Mode: m.Phase, Confidence: ConfidenceMedium, RawEventID: m.EventID,
	}
	g.addEvidence(ev)
	g.upsertRelationshipClaim(Relationship{
		Type: RelSubdomainOf, From: domain, To: parent, EvidenceID: ev.ID,
		Confidence: ConfidenceMedium, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: nameSeen, LastSeen: nameSeen,
	}, nameClaim)
}

// discoveryMeta captures the how/where provenance of a domain discovery as observation
// metadata (never as graph topology).
func discoveryMeta(e events.DnsDomainNameDiscovered, parent string) map[string]any {
	md := map[string]any{"depth": e.Depth}
	if e.DiscoverySource != "" {
		md["discovery_source"] = e.DiscoverySource
	}
	if parent != "" {
		md["parent_domain"] = parent
	}
	return md
}
