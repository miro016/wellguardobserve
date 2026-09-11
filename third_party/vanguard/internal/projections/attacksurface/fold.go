package attacksurface

import (
	"net"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections/facts"
)

// factRepresentedElsewhere lists the facts observation types whose entire content is
// already carried by a node, an edge, or a path in the contracted graph. Everything else
// becomes a facet, so an observation type added upstream is folded rather than lost: the
// default is to keep, and each exception here names what already represents it.
// representedByResolvesTo is the reason shared by the record types whose whole content
// is the address edge; naming it once keeps the three entries from drifting apart.
const representedByResolvesTo = "the resolves_to edge"

var factRepresentedElsewhere = map[string]string{
	"domain_observed":           "the Domain node itself",
	"subdomain_observed":        "the Domain node and its subdomain_of edge",
	"dns_a_record_observed":     representedByResolvesTo,
	"dns_aaaa_record_observed":  representedByResolvesTo,
	"dns_cname_record_observed": "the cname_to edge",
	"dns_mx_record_observed":    "the mail_routes_to edge",
	"dns_ptr_record_observed":   "the ptr_to edge",
	"dns_ns_record_observed":    "the folded NS record facet, which also carries the record value",
	"dns_txt_record_observed":   "the folded TXT record facet, which also carries the record value",
	"ip_attribution_observed":   representedByResolvesTo,
	"http_endpoint_observed":    "the observed path on the web surface",
	"web_asset_observed":        "the observed path on the web surface",
	"technology_observed":       "the folded technology entry on the node that runs it",
	"censys_product_observed":   "the folded host-observed technology entry",
	"certificate_observed":      "the folded certificate coverage facet on each covered name",
	"finding_observed":          "the finding attached to the affected node",
}

// foldRecords folds the DnsRecord assets onto the Domain node that owns them. The record
// value is what a DNS policy question is actually about - which nameservers, which SPF
// string - so it is carried into the facet rather than left as a key nothing reads.
func (b *builder) foldRecords() {
	for _, r := range b.v.Relationships {
		var kind string
		switch r.Type {
		case facts.RelHasNS:
			kind = "dns_ns_record"
		case facts.RelHasTXT:
			kind = "dns_txt_record"
		case facts.RelHasDNSRecord:
			kind = "dns_record"
		default:
			continue
		}
		owner := b.domainRef(r.From)
		rec, ok := b.assets[typedKey(facts.AssetDNSRecord, r.To)]
		if owner == "" || !ok {
			continue
		}
		values := map[string]any{}
		for k, v := range rec.Attributes {
			values[k] = v
		}
		if kind == "dns_record" {
			// A zone transfer dumps every type at once, so the record type is the
			// only thing separating one facet from the next.
			if rt, typed := rec.Attributes["record_type"].(string); typed {
				kind = "dns_record:" + strings.ToLower(rt)
			}
		}
		b.nodes[owner].Facets = append(b.nodes[owner].Facets, Facet{
			Kind:        kind,
			Statement:   b.statement(r.EvidenceID),
			Confidence:  r.Confidence,
			Currentness: b.edgeCurrentness(r),
			Mode:        r.Mode,
			Values:      values,
			EvidenceID:  r.EvidenceID,
		})
		b.markFolded(rec)
	}
}

// foldCertificates attaches a coverage summary to every name a certificate covers.
//
// It is a coverage claim and nothing more. A certificate in a CT log proves that someone
// asked a CA to issue for that name, not that anything is serving it today, so the facet
// keeps the validity window and the source's currentness verbatim and the contraction
// never turns it into a live-deployment claim.
func (b *builder) foldCertificates() {
	for _, r := range b.v.Relationships {
		if r.Type != facts.RelCertCoversName {
			continue
		}
		target := b.domainRef(r.To)
		cert, ok := b.assets[typedKey(facts.AssetCertificate, r.From)]
		if target == "" || !ok {
			continue
		}
		values := map[string]any{"certificate_key": cert.Key}
		for k, v := range cert.Attributes {
			values[k] = v
		}
		b.nodes[target].Facets = append(b.nodes[target].Facets, Facet{
			Kind:        "certificate_coverage",
			Statement:   b.statement(r.EvidenceID),
			Confidence:  r.Confidence,
			Currentness: b.assetCurrentness(facts.AssetCertificate, cert.Key),
			Mode:        r.Mode,
			Values:      values,
			EvidenceID:  r.EvidenceID,
		})
		b.markFolded(cert)
	}
}

// foldProviders folds the Provider and Netblock assets into a provider-attribution facet
// on each address they concern.
//
// A netblock reaches an address by containment rather than by an edge: the facts graph
// records which ASN announces a prefix, not which addresses fall inside it, and testing
// containment is exact where guessing from a shared ASN would attach a prefix to
// addresses that are not in it.
func (b *builder) foldProviders() {
	for _, r := range b.v.Relationships {
		if r.Type != facts.RelHostedByProvider {
			continue
		}
		ip := b.ipRef(r.From)
		provider, ok := b.assets[typedKey(facts.AssetProvider, r.To)]
		if ip == "" || !ok {
			continue
		}
		values := map[string]any{"provider_key": provider.Key}
		for k, v := range provider.Attributes {
			values[k] = v
		}
		b.nodes[ip].Facets = append(b.nodes[ip].Facets, Facet{
			Kind:        "provider_attribution",
			Statement:   b.statement(r.EvidenceID),
			Confidence:  r.Confidence,
			Currentness: b.edgeCurrentness(r),
			Mode:        r.Mode,
			Values:      values,
			EvidenceID:  r.EvidenceID,
		})
		b.markFolded(provider)
	}

	for _, block := range b.v.AssetsByType(facts.AssetNetblock) {
		_, prefix, err := net.ParseCIDR(block.Key)
		if err != nil {
			continue
		}
		for _, a := range b.v.AssetsByType(facts.AssetIPAddress) {
			addr := net.ParseIP(a.Key)
			if addr == nil || !prefix.Contains(addr) {
				continue
			}
			id := b.ipRef(a.Key)
			if id == "" {
				continue
			}
			values := map[string]any{"prefix": block.Key}
			for k, v := range block.Attributes {
				values[k] = v
			}
			b.nodes[id].Facets = append(b.nodes[id].Facets, Facet{
				Kind:        "netblock",
				Confidence:  facts.ConfidenceHigh,
				Currentness: b.assetCurrentness(facts.AssetNetblock, block.Key),
				Values:      values,
			})
			b.markFolded(block)
			b.markAnnouncingProviders(block.Key)
		}
	}
}

// markAnnouncingProviders accounts for the providers a folded prefix belongs to. Such a
// provider is reachable in the facts graph only through the netblock - no address in the
// scan is attributed to it directly - and the netblock facet already carries its ASN and
// name, so it is contracted by that facet rather than left looking like a dropped asset.
func (b *builder) markAnnouncingProviders(prefix string) {
	for _, r := range b.v.Relationships {
		if r.Type != facts.RelBelongsToASN || r.From != prefix {
			continue
		}
		if provider, ok := b.assets[typedKey(facts.AssetProvider, r.To)]; ok {
			b.markFolded(provider)
		}
	}
}

// foldTechnologies attaches each product to the node the source relationship named,
// keeping the two attributions apart.
//
// runs_technology came from a fingerprint of the thing itself; host_observed_technology
// came from a passive source that mapped a product to a host and to no port at all. The
// contraction copies the relation across unchanged: promoting a host observation to a
// service fingerprint here would manufacture precision that no source ever claimed, and
// it is the kind of error that only shows up when someone acts on it.
func (b *builder) foldTechnologies() {
	for _, r := range b.v.Relationships {
		var relation TechnologyRelation
		switch r.Type {
		case facts.RelRunsTechnology:
			relation = TechRuns
		case facts.RelHostObservedTechnology:
			relation = TechHostObserved
		default:
			continue
		}
		tech, ok := b.assets[typedKey(facts.AssetTechnology, r.To)]
		if !ok {
			continue
		}
		host := b.technologyHost(r.From)
		if host == "" {
			continue
		}
		b.nodes[host].Technologies = append(b.nodes[host].Technologies, Technology{
			Key:         tech.Key,
			Relation:    relation,
			Versions:    stringsOf(tech.Attributes["versions"]),
			Categories:  stringsOf(tech.Attributes["categories"]),
			CPEs:        stringsOf(tech.Attributes["cpes"]),
			Confidence:  r.Confidence,
			Currentness: b.edgeCurrentness(r),
			Sources:     unionSorted(nil, assertionSources(r.Assertions)),
			EvidenceIDs: appendUnique(nil, r.EvidenceID),
		})
		b.markFolded(tech)
	}
}

// technologyHost resolves the source side of a technology relationship, which the facts
// graph writes as an address, a canonical service id, or an endpoint URL.
func (b *builder) technologyHost(key string) string {
	if id := b.ipRef(key); id != "" {
		return id
	}
	if id := b.serviceRef(key); id != "" {
		return id
	}
	return b.surfaceRef(key)
}

// foldFacets folds every remaining observation onto the node it was recorded against.
//
// The default is to keep. An observation type this package has never heard of still lands
// on its node with its statement, metadata, and provenance intact, which is the only
// arrangement where adding a normalizer upstream cannot quietly shrink the attack surface.
// The exceptions are listed in factRepresentedElsewhere and each names what already
// carries the same content.
func (b *builder) foldFacets() {
	for _, o := range b.v.Observations {
		if _, skip := factRepresentedElsewhere[o.Type]; skip {
			continue
		}
		id := b.observationHost(o.AssetKey)
		if id == "" {
			continue
		}
		ev := b.ev[evidenceOf(o)]
		b.nodes[id].Facets = append(b.nodes[id].Facets, Facet{
			Kind:             o.Type,
			Statement:        ev.Statement,
			Confidence:       o.Confidence,
			Currentness:      o.Currentness,
			Source:           o.Source,
			Mode:             o.Mode,
			Values:           o.Metadata,
			ObservationID:    o.ID,
			EvidenceID:       ev.ID,
			SourceObservedAt: firstNonZero(o.SourceObservedAt, o.LiveVerifiedAt),
		})
		b.nodes[id].ObservationIDs = appendUnique(b.nodes[id].ObservationIDs, o.ID)
		if ev.ID != "" {
			b.nodes[id].EvidenceIDs = appendUnique(b.nodes[id].EvidenceIDs, ev.ID)
		}
	}
}

// observationHost resolves the node an observation's asset key belongs to.
func (b *builder) observationHost(key string) string {
	if id := b.domainRef(key); id != "" {
		return id
	}
	if id := b.ipRef(key); id != "" {
		return id
	}
	if id := b.serviceRef(key); id != "" {
		return id
	}
	if id := b.surfaceRef(key); id != "" {
		return id
	}
	return b.nodeOf[typedKey(facts.AssetMailService, key)]
}

// attachFindings puts every raised weakness on the retained node it concerns, and puts
// the ones with no defensible target in the unmapped list rather than dropping them.
//
// A finding is the one thing in this artifact that can hurt someone if it goes missing,
// so the fallbacks are deliberately generous and each one records the rule it used. What
// is never done is attaching a finding to a node it does not concern: an unmapped finding
// an analyst can see beats a plausible-looking attachment to the wrong asset.
func (b *builder) attachFindings() {
	for _, c := range b.v.FindingCandidates {
		f := Finding{
			ID: c.ID, Rule: c.Rule, Title: c.Title, Category: c.Category,
			Severity:      c.Severity,
			Confidence:    c.Confidence,
			EvidenceIDs:   append([]string(nil), c.EvidenceIDs...),
			FactsAssetKey: c.AssetKey,
		}
		targets, rule := b.findingTargets(c.AssetKey)
		if len(targets) == 0 {
			f.AttachmentRule = "unmapped"
			b.unmapped = append(b.unmapped, f)
			continue
		}
		f.AttachmentRule = rule
		for _, id := range targets {
			b.nodes[id].Findings = append(b.nodes[id].Findings, f)
		}
		b.attached++
	}
}

// findingTargets resolves the nodes a finding's facts asset key concerns, with the rule
// that decided it.
func (b *builder) findingTargets(key string) (ids []string, rule string) {
	if id := b.observationHost(key); id != "" {
		return []string{id}, "direct"
	}
	// A certificate finding belongs on the names the certificate covers: those are the
	// things an operator can act on. The original certificate key stays on the finding.
	if covered := b.certificateNames(key); len(covered) > 0 {
		return covered, "certificate_covered_name"
	}
	// A finding raised against a URL lands on the origin that URL belongs to. This is a
	// contraction, not a repair: the endpoint the finding names is retained by the facts
	// graph, and several endpoints on one origin fold into one WebSurface node.
	if o, ok := parseOrigin(key); ok {
		if n, exists := b.nodes[nodeID(NodeWebSurface, o.origin)]; exists {
			return []string{n.ID}, "url_origin"
		}
	}
	// A finding raised against a DNS record belongs to the name that owns the record.
	if rec, ok := b.assets[typedKey(facts.AssetDNSRecord, key)]; ok {
		if owner, typed := rec.Attributes["owner"].(string); typed {
			if id := b.domainRef(owner); id != "" {
				return []string{id}, "dns_record_owner"
			}
		}
	}
	return nil, ""
}

// certificateNames returns the Domain nodes covered by the certificate a finding names.
// The finding carries the canonical certificate asset key, the same key the facts graph
// materialized, so the lookup is direct: no serial-shaped fallback scan is needed, and a
// key that names no certificate is genuinely unmapped rather than guessed at.
//
// No Certificate node enters the surface graph. A certificate is a credential covering
// names, not a thing an operator attacks, so its findings land on the covered names.
func (b *builder) certificateNames(key string) []string {
	if _, ok := b.assets[typedKey(facts.AssetCertificate, key)]; !ok {
		return nil
	}
	var ids []string
	for _, r := range b.v.Relationships {
		if r.Type != facts.RelCertCoversName || r.From != key {
			continue
		}
		if id := b.domainRef(r.To); id != "" {
			ids = appendUnique(ids, id)
		}
	}
	return ids
}

// markFolded counts a folded asset once, however many nodes it contributed to.
func (b *builder) markFolded(a facts.Asset) {
	k := typedKey(a.Type, a.Key)
	if b.folded[k] {
		return
	}
	b.folded[k] = true
	if out, ok := b.outcomes[a.Type]; ok {
		out.Contracted++
	}
}

// statement returns the evidence sentence behind an id, or the empty string when the edge
// carried no evidence reference.
func (b *builder) statement(evidenceID string) string {
	return b.ev[evidenceID].Statement
}

// assetCurrentness returns the currentness the facts graph classified an asset with.
func (b *builder) assetCurrentness(t facts.AssetType, key string) facts.Currentness {
	if c, ok := b.classA[typedKey(t, key)]; ok {
		return c.Primary
	}
	return facts.CurrentnessUnknown
}

// edgeCurrentness returns the currentness the facts graph classified a relationship with.
func (b *builder) edgeCurrentness(r facts.Relationship) facts.Currentness {
	if c, ok := b.classR[string(r.Type)+"\x00"+r.From+"\x00"+r.To]; ok {
		return c.Primary
	}
	return facts.CurrentnessUnknown
}
