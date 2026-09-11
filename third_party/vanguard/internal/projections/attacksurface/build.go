package attacksurface

import (
	"net"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
)

// Build contracts a facts view into the attack-surface graph. source is the compact
// collection verdict for the capture the view was folded from, supplied by the caller
// because the manifest that holds it is not something a pure contraction may read; it
// is nil when the caller has no manifest, and the artifact then states nothing about
// source completeness.
//
// It is pure and deterministic: it reads only the view, sorts every working set before
// it renders, and derives no time from a clock. Building twice, building after a replay,
// and building from the value or pointer form of the same events all produce byte-
// identical JSON, because the view itself is already normalized on all three counts.
//
// It always returns a graph. A structurally defective result - a dangling edge, a lost
// finding, an asset type with no contraction rule - is reported in [Graph.Integrity] and
// surfaced by [Graph.Err], so a caller writing artifacts can refuse to write while a
// caller inspecting the graph can still see what went wrong.
func Build(v facts.View, source *SourceCollection) *Graph {
	b := newBuilder(v)
	b.buildDomainNodes()
	b.buildIPNodes()
	b.buildServiceNodes()
	b.buildWebSurfaceNodes()
	b.buildEdges()
	b.foldRecords()
	b.foldCertificates()
	b.foldProviders()
	b.foldTechnologies()
	b.foldFacets()
	b.attachFindings()
	g := b.graph()
	// The collection verdict is metadata about the acquisition, so it is attached to
	// the finished graph rather than fed into the contraction: no node, edge, facet,
	// or finding may depend on how the collection ended.
	g.SourceCollection = source
	return g
}

// builder holds the working state of one contraction. Every map in it is an index; the
// rendered output is built from sorted slices so no map iteration order can reach it.
type builder struct {
	v    facts.View
	root string

	nodes map[string]*Node // typed node id -> node
	edges map[string]*Edge // type\x00from\x00to -> edge

	assets map[string]facts.Asset           // facts type\x00key -> asset
	obs    map[string][]facts.Observation   // facts asset key -> observations
	ev     map[string]facts.Evidence        // evidence id -> evidence
	classA map[string]facts.ClassifiedAsset // facts type\x00key -> classification
	classR map[string]facts.ClassifiedRelationship

	// nodeOf maps a facts asset (typed) to the node it contracted into. It is what
	// makes finding attachment, facet folding, and edge remapping agree with each
	// other instead of each re-deriving the mapping.
	nodeOf map[string]string
	// originOf maps an endpoint URL to the web-surface origin it grouped under.
	originOf map[string]string
	// folded records the facts assets a folding rule already accounted for, so an
	// asset that contributed to several nodes is counted once.
	folded map[string]bool

	outcomes   map[facts.AssetType]*AssetOutcome
	violations []IntegrityViolation
	unmapped   []Finding

	consumedRels int
	attached     int
}

func newBuilder(v facts.View) *builder {
	b := &builder{
		v:        v,
		root:     v.RootTarget,
		nodes:    map[string]*Node{},
		edges:    map[string]*Edge{},
		assets:   make(map[string]facts.Asset, len(v.Assets)),
		obs:      v.ObservationsByAsset(),
		ev:       v.EvidenceByID(),
		classA:   v.ClassifiedAssets(),
		classR:   v.ClassifiedRelationships(),
		nodeOf:   map[string]string{},
		originOf: map[string]string{},
		folded:   map[string]bool{},
		outcomes: map[facts.AssetType]*AssetOutcome{},
	}
	for _, a := range v.Assets {
		b.assets[typedKey(a.Type, a.Key)] = a
	}
	b.declareOutcomes()
	return b
}

// typedKey is the facts identity of an asset: its type and key together.
func typedKey(t facts.AssetType, key string) string { return string(t) + "\x00" + key }

// contractionRules states, once, what happens to every facts asset type. The switch in
// [builder.declareOutcomes] is exhaustive over this list, so an asset type added upstream
// shows up as an undecided_asset_type violation instead of silently disappearing.
var contractionRules = []struct {
	Type    facts.AssetType
	Outcome Outcome
	Reason  string
}{
	{facts.AssetDomain, OutcomeRetained, "the scan root becomes a Domain node of kind root"},
	{facts.AssetSubdomain, OutcomeRetained, "becomes an in-scope Domain node of kind subdomain"},
	{facts.AssetExternalDomain, OutcomeRetained,
		"becomes an external Domain node: visible as a referenced destination, never counted in scope"},
	{facts.AssetIPAddress, OutcomeRetained, "becomes an IPAddress node"},
	{facts.AssetService, OutcomeRetained, "becomes a Service node keyed by the canonical host/port/transport"},
	{facts.AssetEndpoint, OutcomeFolded,
		"grouped by normalized URL origin into a WebSurface node; the URL survives as an observed path"},
	{facts.AssetTechnology, OutcomeFolded,
		"attached to the IP, Service, or WebSurface the source relationship named, keeping runs and host-observed distinct"},
	{facts.AssetCertificate, OutcomeFolded,
		"summarized as a coverage facet on each name the certificate covers; live deployment is never inferred"},
	{facts.AssetDNSRecord, OutcomeFolded, "folded into a record facet on the owning Domain node"},
	{facts.AssetMailService, OutcomeFolded,
		"reuses or creates the Domain node for the exchanger host and is reached by mail_routes_to"},
	{facts.AssetProvider, OutcomeFolded,
		"folded into the provider attribution facet of each address it hosts, or into the netblock facet when only a prefix names it"},
	{facts.AssetNetblock, OutcomeFolded, "folded into the provider attribution facet of each address it contains"},
}

// declareOutcomes seeds the accounting with one entry per facts asset type and counts the
// assets present in the view, so the summary lists every type whether the scan produced
// one or not.
func (b *builder) declareOutcomes() {
	for _, rule := range contractionRules {
		b.outcomes[rule.Type] = &AssetOutcome{AssetType: rule.Type, Outcome: rule.Outcome, Reason: rule.Reason}
	}
	for _, a := range b.v.Assets {
		out, ok := b.outcomes[a.Type]
		if !ok {
			b.violate(ViolationUndecidedAssetType, string(a.Type),
				"the facts vocabulary gained an asset type with no contraction rule; decide whether it is retained, folded, or excluded")
			continue
		}
		out.Count++
	}
}

// violate records one integrity defect.
func (b *builder) violate(kind IntegrityViolationKind, subject, detail string) {
	b.violations = append(b.violations, IntegrityViolation{Kind: kind, Subject: subject, Detail: detail})
}

// ---------------------------------------------------------------- node construction

// buildDomainNodes turns every facts name asset into a Domain node. The three facts name
// types collapse here and keep their distinction as Kind and Scope: whether a name is in
// scope is a property of the name, not a different kind of thing.
func (b *builder) buildDomainNodes() {
	for _, t := range []facts.AssetType{facts.AssetDomain, facts.AssetSubdomain, facts.AssetExternalDomain} {
		for _, a := range b.v.AssetsByType(t) {
			n := b.ensureDomainNode(a.Key)
			b.absorb(n, a)
			b.outcomes[t].Contracted++
		}
	}
}

// ensureDomainNode returns the Domain node for a name, creating it if some other rule
// (a mail exchanger, a TLS assessed name) needs a name the facts graph never made an
// asset of.
func (b *builder) ensureDomainNode(name string) *Node {
	id := nodeID(NodeDomain, name)
	if n, ok := b.nodes[id]; ok {
		return n
	}
	kind, scope := b.classifyName(name)
	n := &Node{ID: id, Type: NodeDomain, Key: name, Label: name, Scope: scope, Kind: kind}
	b.nodes[id] = n
	return n
}

// classifyName decides a name's kind and scope against the scan root. It mirrors the
// facts scope rule exactly rather than re-inventing one, so the two artifacts cannot
// disagree about what is in scope.
func (b *builder) classifyName(name string) (DomainKind, Scope) {
	switch {
	case b.root != "" && name == b.root:
		return DomainKindRoot, ScopeInScope
	case b.root != "" && strings.HasSuffix(name, "."+b.root):
		return DomainKindSubdomain, ScopeInScope
	case b.root == "":
		// Without a root there is nothing to judge scope against, and calling an
		// unjudged name external would understate the surface. The facts graph
		// falls back to a shape heuristic for the same reason.
		if strings.Count(name, ".") <= 1 {
			return DomainKindRoot, ScopeInScope
		}
		return DomainKindSubdomain, ScopeInScope
	default:
		return DomainKindExternal, ScopeExternal
	}
}

// buildIPNodes turns every facts IPAddress asset into a node. An address's scope follows
// the names that reach it: an address only external names resolve to is not the target's
// surface, while an address discovered without any name at all entered the scan through
// the target and stays in scope.
func (b *builder) buildIPNodes() {
	inScopeNames := map[string]bool{}
	externalNames := map[string]bool{}
	for _, r := range b.v.Relationships {
		if r.Type != facts.RelResolvesTo {
			continue
		}
		if n, ok := b.nodes[nodeID(NodeDomain, r.From)]; ok && n.Scope == ScopeInScope {
			inScopeNames[r.To] = true
		} else if ok {
			externalNames[r.To] = true
		}
	}
	for _, a := range b.v.AssetsByType(facts.AssetIPAddress) {
		scope := ScopeInScope
		if !inScopeNames[a.Key] && externalNames[a.Key] {
			scope = ScopeExternal
		}
		n := &Node{ID: nodeID(NodeIPAddress, a.Key), Type: NodeIPAddress, Key: a.Key,
			Label: a.Key, Scope: scope}
		b.nodes[n.ID] = n
		b.absorb(n, a)
		b.outcomes[facts.AssetIPAddress].Contracted++
	}
}

// buildServiceNodes turns every facts Service asset into a node, inheriting the scope of
// the address it listens on.
func (b *builder) buildServiceNodes() {
	for _, a := range b.v.AssetsByType(facts.AssetService) {
		scope := ScopeInScope
		if ip, ok := a.Attributes["ip"].(string); ok {
			if host, found := b.nodes[nodeID(NodeIPAddress, ip)]; found {
				scope = host.Scope
			}
		}
		n := &Node{ID: nodeID(NodeService, a.Key), Type: NodeService, Key: a.Key,
			Label: serviceLabel(a), Scope: scope}
		b.nodes[n.ID] = n
		b.absorb(n, a)
		b.outcomes[facts.AssetService].Contracted++
	}
}

// serviceLabel renders "203.0.113.10:443/tcp", which reads better than the canonical id
// while the canonical id remains the node key.
func serviceLabel(a facts.Asset) string {
	ip, _ := a.Attributes["ip"].(string)
	transport, _ := a.Attributes["transport"].(string)
	port := 0
	switch p := a.Attributes["port"].(type) {
	case int:
		port = p
	case float64:
		port = int(p)
	}
	if ip == "" || port == 0 {
		return a.Key
	}
	if transport == "" {
		return ip + ":" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port) + "/" + transport
}

// buildWebSurfaceNodes groups the facts Endpoint assets by normalized URL origin. Fifty
// paths on one origin are one thing to assess, and drawing fifty nodes for them buries
// the topology the graph exists to show. Each URL survives as a sorted path observation
// with the response detail that URL actually carried, so nothing one path reported can
// overwrite what another reported.
func (b *builder) buildWebSurfaceNodes() {
	for _, a := range b.v.AssetsByType(facts.AssetEndpoint) {
		o, ok := parseOrigin(a.Key)
		if !ok {
			// The facts graph quarantines an endpoint URL it cannot parse, so this
			// is only reachable if that guard is removed upstream.
			b.violate(ViolationUncontractedAsset, "Endpoint "+a.Key,
				"the endpoint URL has no parseable origin, so it belongs to no web surface")
			continue
		}
		n, exists := b.nodes[nodeID(NodeWebSurface, o.origin)]
		if !exists {
			n = &Node{ID: nodeID(NodeWebSurface, o.origin), Type: NodeWebSurface, Key: o.origin,
				Label: o.origin, Scope: b.hostScope(o.host, o.isIP),
				Attributes: map[string]any{"scheme": o.scheme, "host": o.host, "port": o.port}}
			b.nodes[n.ID] = n
		}
		b.absorb(n, a)
		b.originOf[a.Key] = o.origin
		b.addPath(n, o, a)
		b.outcomes[facts.AssetEndpoint].Contracted++
	}
}

// hostScope returns the scope of the host an origin addresses, so a web surface on a
// third-party name is not counted as the target's own.
func (b *builder) hostScope(host string, isIP bool) Scope {
	t := NodeDomain
	if isIP {
		t = NodeIPAddress
	}
	if n, ok := b.nodes[nodeID(t, host)]; ok {
		return n.Scope
	}
	_, scope := b.classifyName(host)
	return scope
}

// addPath records one URL on its origin with the response detail that URL carried. The
// retained URL is the origin plus the path, with the fragment dropped: a fragment is a
// client-side instruction the server never sees, so two URLs differing only by fragment
// are one request and must not read as two.
func (b *builder) addPath(n *Node, o originParts, a facts.Asset) {
	p := PathObservation{Path: o.path, URL: o.origin + o.path, Sources: append([]string(nil), a.Sources...)}
	switch sc := a.Attributes["status_code"].(type) {
	case int:
		p.StatusCode = sc
	case float64:
		p.StatusCode = int(sc)
	}
	p.Title, _ = a.Attributes["title"].(string)
	p.Server, _ = a.Attributes["server"].(string)
	p.AuthType, _ = a.Attributes["auth_type"].(string)
	n.Paths = append(n.Paths, p)
}

// absorb records one facts asset's contribution to a node: its provenance, its sources,
// its seen window, its classification, and (for a retained one-to-one node) its
// attributes. It is the single place a node learns anything from a facts asset, so a
// contraction rule cannot accidentally take a stronger currentness than an input had.
func (b *builder) absorb(n *Node, a facts.Asset) {
	b.nodeOf[typedKey(a.Type, a.Key)] = n.ID
	n.FactsAssetKeys = appendUnique(n.FactsAssetKeys, a.Key)
	n.Sources = unionSorted(n.Sources, a.Sources)
	if !a.FirstSeen.IsZero() && (n.FirstSeen.IsZero() || a.FirstSeen.Before(n.FirstSeen)) {
		n.FirstSeen = a.FirstSeen
	}
	if a.LastSeen.After(n.LastSeen) {
		n.LastSeen = a.LastSeen
	}
	if n.Type != NodeWebSurface {
		// A web surface is a group, so one member endpoint's status or title must
		// not become a property of the origin; those live on the path list instead.
		for k, v := range a.Attributes {
			if n.Attributes == nil {
				n.Attributes = map[string]any{}
			}
			if _, present := n.Attributes[k]; !present {
				n.Attributes[k] = v
			}
		}
	}
	if c, ok := b.classA[typedKey(a.Type, a.Key)]; ok {
		if currentnessRank(c.Primary) > currentnessRank(n.Primary) {
			n.Primary = c.Primary
		}
		n.Badges = unionSorted(n.Badges, c.Badges)
		n.ObservationIDs = unionSorted(n.ObservationIDs, c.ObservationIDs)
	}
	if n.Primary == "" {
		n.Primary = facts.CurrentnessUnknown
	}
	// A node nothing observed directly exists only because something pointed at it.
	// Saying so is the difference between a discovered surface and a referenced one.
	if len(b.obs[a.Key]) > 0 {
		n.ReferencedOnly = false
	} else if len(n.FactsAssetKeys) == 1 {
		n.ReferencedOnly = true
	}
}

// ---------------------------------------------------------------- edge construction

// buildEdges contracts the facts relationships that survive as edges and counts the ones
// that fold into nodes, so the summary can prove every input relationship was considered.
func (b *builder) buildEdges() {
	for _, r := range b.v.Relationships {
		switch r.Type {
		case facts.RelSubdomainOf:
			b.addEdge(r, EdgeSubdomainOf, b.domainRef(r.From), b.domainRef(r.To))
		case facts.RelResolvesTo:
			b.addEdge(r, EdgeResolvesTo, b.domainRef(r.From), b.ipRef(r.To))
		case facts.RelCnameTo:
			b.addEdge(r, EdgeCnameTo, b.domainRef(r.From), b.domainRef(r.To))
		case facts.RelPtrTo:
			b.addEdge(r, EdgePtrTo, b.ipRef(r.From), b.domainRef(r.To))
		case facts.RelHasMX:
			b.addEdge(r, EdgeMailRoutesTo, b.domainRef(r.From), b.mailRef(r.To))
		case facts.RelExposesService:
			b.addEdge(r, EdgeExposesService, b.ipRef(r.From), b.serviceRef(r.To))
		case facts.RelServesEndpoint:
			b.addEdge(r, EdgeServesWebSurface, b.hostRef(r.From), b.surfaceRef(r.To))
		case facts.RelRedirectsTo:
			b.addEdge(r, EdgeRedirectsTo, b.surfaceRef(r.From), b.hostRef(r.To))
		case facts.RelHasNS, facts.RelHasTXT, facts.RelHasDNSRecord,
			facts.RelHostedByProvider, facts.RelBelongsToASN,
			facts.RelRunsTechnology, facts.RelHostObservedTechnology,
			facts.RelCertCoversName:
			// Folded by the dedicated passes, which need the record, provider,
			// technology, or certificate asset behind the edge and not just its key.
			b.consumedRels++
		case facts.RelFindingAffectsAsset, facts.RelFindingSupportedByEvidence:
			// Findings attach to nodes rather than travelling as edges; the
			// finding pass consumes both.
			b.consumedRels++
		default:
			b.violate(ViolationUndecidedAssetType, string(r.Type),
				"the facts vocabulary gained a relationship type with no contraction rule")
		}
	}
	b.deriveTLSAssessedFor()
	b.deriveMissingSurfaceEdges()
}

// domainRef, ipRef, serviceRef, mailRef, surfaceRef, and hostRef resolve one endpoint of
// a facts relationship to the node it contracted into. An empty result means the endpoint
// named nothing this graph retained, which addEdge reports as a dangling edge.
func (b *builder) domainRef(key string) string {
	for _, t := range []facts.AssetType{facts.AssetDomain, facts.AssetSubdomain, facts.AssetExternalDomain} {
		if id, ok := b.nodeOf[typedKey(t, key)]; ok {
			return id
		}
	}
	return ""
}

func (b *builder) ipRef(key string) string { return b.nodeOf[typedKey(facts.AssetIPAddress, key)] }

func (b *builder) serviceRef(key string) string { return b.nodeOf[typedKey(facts.AssetService, key)] }

// mailRef resolves a mail exchanger to a Domain node, creating it when the exchanger is a
// host the facts graph only ever saw as a MailService. The wrapper type does not survive:
// an exchanger is a name, and a second node type for it would split one name in two.
func (b *builder) mailRef(key string) string {
	if id := b.domainRef(key); id != "" {
		b.nodeOf[typedKey(facts.AssetMailService, key)] = id
		b.outcomes[facts.AssetMailService].Contracted++
		return id
	}
	a, ok := b.assets[typedKey(facts.AssetMailService, key)]
	if !ok {
		return ""
	}
	n := b.ensureDomainNode(key)
	b.absorb(n, a)
	b.outcomes[facts.AssetMailService].Contracted++
	return n.ID
}

func (b *builder) surfaceRef(endpointKey string) string {
	origin, ok := b.originOf[endpointKey]
	if !ok {
		return ""
	}
	return nodeID(NodeWebSurface, origin)
}

// hostRef resolves the host side of an endpoint edge, which the facts graph derives from
// a URL authority and so may be either a name or an address.
func (b *builder) hostRef(key string) string {
	if id := b.ipRef(key); id != "" {
		return id
	}
	return b.domainRef(key)
}

// addEdge merges one contracted edge. Two facts relationships that contract onto the same
// pair - fifty endpoints on one origin served by one name - become one edge whose
// confidence and currentness are the strongest either input already carried. The merge
// takes a maximum over existing claims and never manufactures a grade, so a set of
// passive claims contracts into a passive edge.
func (b *builder) addEdge(r facts.Relationship, t EdgeType, from, to string) {
	b.consumedRels++
	if from == "" || to == "" {
		b.violate(ViolationDanglingEdge, string(r.Type)+" "+r.From+" -> "+r.To,
			"a relationship endpoint contracted into no node")
		return
	}
	currentness := facts.CurrentnessUnknown
	if c, ok := b.classR[string(r.Type)+"\x00"+r.From+"\x00"+r.To]; ok {
		currentness = c.Primary
	}
	k := string(t) + "\x00" + from + "\x00" + to
	ex, ok := b.edges[k]
	if !ok {
		e := &Edge{Type: t, From: from, To: to, Confidence: r.Confidence, Currentness: currentness,
			Mode: r.Mode, Metadata: r.Metadata, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
		e.EvidenceIDs = appendUnique(nil, r.EvidenceID)
		e.SourceEventIDs = appendUnique(nil, r.SourceEventID)
		e.Sources = unionSorted(nil, assertionSources(r.Assertions))
		b.edges[k] = e
		return
	}
	if confidenceRank(r.Confidence) > confidenceRank(ex.Confidence) {
		ex.Confidence = r.Confidence
		ex.Mode = r.Mode
	}
	if currentnessRank(currentness) > currentnessRank(ex.Currentness) {
		ex.Currentness = currentness
	}
	ex.EvidenceIDs = appendUnique(ex.EvidenceIDs, r.EvidenceID)
	ex.SourceEventIDs = appendUnique(ex.SourceEventIDs, r.SourceEventID)
	ex.Sources = unionSorted(ex.Sources, assertionSources(r.Assertions))
	if !r.FirstSeen.IsZero() && (ex.FirstSeen.IsZero() || r.FirstSeen.Before(ex.FirstSeen)) {
		ex.FirstSeen = r.FirstSeen
	}
	if r.LastSeen.After(ex.LastSeen) {
		ex.LastSeen = r.LastSeen
	}
	// The metadata of the merged relationships is kept per contributing edge rather
	// than blended: two redirect chains from one origin disagree routinely, and a
	// merged map would read as one chain that never happened.
	if len(r.Metadata) > 0 {
		if ex.Metadata == nil {
			ex.Metadata = map[string]any{}
		}
		for k, v := range r.Metadata {
			if _, present := ex.Metadata[k]; !present {
				ex.Metadata[k] = v
			}
		}
	}
}

// deriveTLSAssessedFor emits the name edges a TLS assessment explicitly claims. It reads
// the assessment's own assessed-names metadata and nothing else: the names that happen to
// resolve to the service's address are not what the scanner measured, and inferring the
// edge from them would attach a certificate verdict to names nobody tested. An assessment
// that names only the address, or names nothing, produces no edge and stays a facet.
func (b *builder) deriveTLSAssessedFor() {
	for _, o := range b.v.Observations {
		if o.Type != "tls_security_assessed" {
			continue
		}
		svc := b.serviceRef(o.AssetKey)
		if svc == "" {
			continue
		}
		for _, name := range stringsOf(o.Metadata["assessed_names"]) {
			target := b.domainRef(name)
			if target == "" {
				target = b.ensureDomainNode(name).ID
			}
			k := string(EdgeTLSAssessedFor) + "\x00" + svc + "\x00" + target
			if ex, ok := b.edges[k]; ok {
				ex.EvidenceIDs = appendUnique(ex.EvidenceIDs, evidenceOf(o))
				ex.SourceEventIDs = appendUnique(ex.SourceEventIDs, o.RawEventID)
				ex.Sources = unionSorted(ex.Sources, []string{o.Source})
				continue
			}
			b.edges[k] = &Edge{Type: EdgeTLSAssessedFor, From: svc, To: target,
				Confidence: o.Confidence, Currentness: o.Currentness, Mode: o.Mode,
				Sources:        unionSorted(nil, []string{o.Source}),
				EvidenceIDs:    appendUnique(nil, evidenceOf(o)),
				SourceEventIDs: appendUnique(nil, o.RawEventID),
				FirstSeen:      o.CapturedAt, LastSeen: o.CapturedAt,
				Metadata: map[string]any{"assessed_name": name, "server_name": o.Metadata["server_name"]}}
		}
	}
}

// deriveMissingSurfaceEdges joins a web surface whose endpoints all arrived without a
// serves_endpoint edge - a technology fingerprint that named a URL no probe reported, for
// example. The authority in the URL is the host the request addressed by construction, so
// the edge is sound, but nothing observed the pairing, so it is emitted at the weakest
// grading available and says in its metadata that it was derived from the authority.
func (b *builder) deriveMissingSurfaceEdges() {
	served := map[string]bool{}
	for _, e := range b.edges {
		if e.Type == EdgeServesWebSurface {
			served[e.To] = true
		}
	}
	for _, id := range sortedNodeIDs(b.nodes) {
		n := b.nodes[id]
		if n.Type != NodeWebSurface || served[n.ID] {
			continue
		}
		host, _ := n.Attributes["host"].(string)
		target := b.hostRef(host)
		if target == "" {
			continue
		}
		b.edges[string(EdgeServesWebSurface)+"\x00"+target+"\x00"+n.ID] = &Edge{
			Type: EdgeServesWebSurface, From: target, To: n.ID,
			Confidence: facts.ConfidenceLow, Currentness: facts.CurrentnessUnknown,
			Metadata: map[string]any{"derived_from": "url_authority"},
		}
	}
}

// ---------------------------------------------------------------- graph assembly

// graph renders the builder's working state into the sorted, deterministic artifact.
func (b *builder) graph() *Graph {
	nodes := make([]Node, 0, len(b.nodes))
	inScope, external := 0, 0
	for _, id := range sortedNodeIDs(b.nodes) {
		n := *b.nodes[id]
		n.Paths = mergePaths(n.Paths)
		sortFindings(n.Findings)
		sortFacets(n.Facets)
		sortTechnologies(n.Technologies)
		if n.Scope == ScopeExternal {
			external++
		} else {
			inScope++
		}
		nodes = append(nodes, n)
	}

	edges := make([]Edge, 0, len(b.edges))
	for _, k := range sortedEdgeKeys(b.edges) {
		edges = append(edges, *b.edges[k])
	}

	g := &Graph{
		ScanID:           b.v.ScanID,
		RootTarget:       b.root,
		GeneratedAt:      b.v.GeneratedAt,
		AnalysisAsOf:     b.v.AnalysisAsOf.At,
		AnalysisPartial:  b.v.AnalysisAsOf.Partial,
		DataView:         dataView,
		Edges:            edges,
		UnmappedFindings: b.unmapped,
	}
	// The four arrays are always allocated, empty included: an absent key would leave a
	// reader unable to tell a kind the scan found none of from one the writer skipped.
	g.Domains, g.IPAddresses = []Node{}, []Node{}
	g.Services, g.WebSurfaces = []Node{}, []Node{}
	for _, n := range nodes {
		switch n.Type {
		case NodeDomain:
			g.Domains = append(g.Domains, n)
		case NodeIPAddress:
			g.IPAddresses = append(g.IPAddresses, n)
		case NodeService:
			g.Services = append(g.Services, n)
		case NodeWebSurface:
			g.WebSurfaces = append(g.WebSurfaces, n)
		}
	}
	sortFindings(g.UnmappedFindings)
	if g.UnmappedFindings == nil {
		g.UnmappedFindings = []Finding{}
	}
	g.ContractionSummary = b.summary(g, inScope, external)
	g.Integrity = b.validate(g)
	return g
}

// summary accounts for every input and every output of the contraction.
func (b *builder) summary(g *Graph, inScope, external int) ContractionSummary {
	byNode := map[string]int{}
	for _, n := range g.AllNodes() {
		byNode[string(n.Type)]++
	}
	byEdge := map[string]int{}
	for _, e := range g.Edges {
		byEdge[string(e.Type)]++
	}
	b.countStandalone()
	assets := make([]AssetOutcome, 0, len(b.outcomes))
	for _, rule := range contractionRules {
		assets = append(assets, *b.outcomes[rule.Type])
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].AssetType < assets[j].AssetType })
	return ContractionSummary{
		Assets:                  assets,
		NodesByType:             typeCounts(byNode),
		EdgesByType:             typeCounts(byEdge),
		InScopeNodes:            inScope,
		ExternalNodes:           external,
		FactsRelationships:      len(b.v.Relationships),
		ContractedRelationships: b.consumedRels,
		FindingsTotal:           len(b.v.FindingCandidates),
		FindingsAttached:        b.attached,
		FindingsUnmapped:        len(b.unmapped),
		IssueCount:              len(b.v.Issues),
		UnmappedEventTypes:      len(b.v.Coverage.UnmappedByType),
	}
}

// countStandalone records, per asset type, how many assets the facts graph left with no
// relationship to fold through. Together with Contracted it closes the accounting:
// Count == Contracted + Standalone for every type, so a type whose contracted number is
// lower than its count says why in the artifact itself instead of leaving a reader to
// wonder whether something was lost.
func (b *builder) countStandalone() {
	connected := b.factsConnected()
	for _, a := range b.v.Assets {
		k := typedKey(a.Type, a.Key)
		if b.folded[k] || b.nodeOf[k] != "" || connected[a.Key] {
			continue
		}
		if out, ok := b.outcomes[a.Type]; ok {
			out.Standalone++
		}
	}
}

// factsConnected reports which asset keys the facts graph joined to something. The two
// finding edge types are excluded: a finding is a claim about an asset, not a place to
// contract the asset through, so an asset whose only edge is a finding is still standing
// on its own as far as the topology is concerned.
func (b *builder) factsConnected() map[string]bool {
	connected := make(map[string]bool, len(b.v.Assets))
	for _, r := range b.v.Relationships {
		switch r.Type {
		case facts.RelFindingAffectsAsset, facts.RelFindingSupportedByEvidence:
			continue
		default:
			connected[r.From] = true
			connected[r.To] = true
		}
	}
	return connected
}

// ---------------------------------------------------------------- URL origins

// originParts is a normalized HTTP(S) origin with the path the URL carried.
type originParts struct {
	origin string
	scheme string
	host   string
	port   int
	isIP   bool
	path   string
}

// parseOrigin normalizes an endpoint URL into the origin that identifies its web surface.
//
// The default port for the scheme is dropped, so a tool that wrote ":443" and one that
// did not land on one surface. An IPv6 authority stays bracketed, because that is the
// only spelling a URL accepts. The fragment never contributes: it is a client-side
// instruction the server never sees, so two URLs differing only by fragment are one
// request. The query does contribute to the path, because a query is part of what was
// requested and two different queries routinely return different pages.
func parseOrigin(rawURL string) (originParts, bool) {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return originParts{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return originParts{}, false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	isIP := net.ParseIP(host) != nil
	port := defaultPort(scheme)
	if p := u.Port(); p != "" {
		n, convErr := strconv.Atoi(p)
		if convErr != nil {
			return originParts{}, false
		}
		port = n
	}
	authority := host
	if isIP && strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	origin := scheme + "://" + authority
	if port != defaultPort(scheme) {
		origin += ":" + strconv.Itoa(port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return originParts{origin: origin, scheme: scheme, host: host, port: port, isIP: isIP, path: path}, true
}

// defaultPort returns the port an HTTP(S) URL implies when it names none.
func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// ---------------------------------------------------------------- ordering helpers

func sortedNodeIDs(m map[string]*Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedEdgeKeys(m map[string]*Edge) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func typeCounts(m map[string]int) []TypeCount {
	out := make([]TypeCount, 0, len(m))
	for k, v := range m {
		out = append(out, TypeCount{Type: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// mergePaths sorts a surface's path observations and collapses the ones that report
// exactly the same thing, unioning their sources.
//
// Two observations of one path that disagree - a different status, a different server -
// are kept as separate rows on purpose. The disagreement is information about the origin,
// and merging them would let whichever the sort happened to put first speak for both.
func mergePaths(in []PathObservation) []PathObservation {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Path != in[j].Path {
			return in[i].Path < in[j].Path
		}
		if in[i].StatusCode != in[j].StatusCode {
			return in[i].StatusCode < in[j].StatusCode
		}
		if in[i].Server != in[j].Server {
			return in[i].Server < in[j].Server
		}
		if in[i].Title != in[j].Title {
			return in[i].Title < in[j].Title
		}
		return in[i].AuthType < in[j].AuthType
	})
	out := make([]PathObservation, 0, len(in))
	for _, p := range in {
		if n := len(out); n > 0 && samePathObservation(out[n-1], p) {
			out[n-1].Sources = unionSorted(out[n-1].Sources, p.Sources)
			continue
		}
		out = append(out, p)
	}
	return out
}

// samePathObservation reports whether two observations say the same thing about one path.
func samePathObservation(a, b PathObservation) bool {
	return a.Path == b.Path && a.StatusCode == b.StatusCode && a.Server == b.Server &&
		a.Title == b.Title && a.AuthType == b.AuthType
}

func sortFacets(f []Facet) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Kind != f[j].Kind {
			return f[i].Kind < f[j].Kind
		}
		if f[i].ObservationID != f[j].ObservationID {
			return f[i].ObservationID < f[j].ObservationID
		}
		return f[i].Statement < f[j].Statement
	})
}

func sortTechnologies(t []Technology) {
	sort.Slice(t, func(i, j int) bool {
		if t[i].Key != t[j].Key {
			return t[i].Key < t[j].Key
		}
		return t[i].Relation < t[j].Relation
	})
}

// sortFindings orders findings strongest first, so the first line of a node is the worst
// thing about it, and ties break by id so the order is stable.
func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		si, sj := severityRank(f[i].Severity), severityRank(f[j].Severity)
		if si != sj {
			return si > sj
		}
		return f[i].ID < f[j].ID
	})
}

func severityRank(s events.Severity) int {
	switch s {
	case events.SeverityCritical:
		return 5
	case events.SeverityHigh:
		return 4
	case events.SeverityMedium:
		return 3
	case events.SeverityLow:
		return 2
	case events.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(c facts.Confidence) int {
	switch c {
	case facts.ConfidenceHigh:
		return 3
	case facts.ConfidenceMedium:
		return 2
	case facts.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// currentnessRank orders the facts currentness vocabulary strongest first so a merge can
// keep the strongest class an input already carried. It never produces a class no input
// had, which is what keeps contraction from upgrading a passive claim.
func currentnessRank(c facts.Currentness) int {
	switch c {
	case facts.CurrentnessLiveVerified:
		return 6
	case facts.CurrentnessCurrentlyResolved:
		return 5
	case facts.CurrentnessValidUnverified:
		return 4
	case facts.CurrentnessRecentPassive:
		return 3
	case facts.CurrentnessHistoricalOnly:
		return 2
	case facts.CurrentnessUnknown:
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------- small helpers

// appendUnique appends a non-empty value that is not already present, keeping the slice
// sorted so the rendered artifact is stable.
func appendUnique(in []string, v string) []string {
	if v == "" {
		return in
	}
	for _, s := range in {
		if s == v {
			return in
		}
	}
	in = append(in, v)
	sort.Strings(in)
	return in
}

// unionSorted returns the sorted, de-duplicated union of two string slices.
func unionSorted(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// assertionSources returns the distinct sources behind a relationship's assertions.
func assertionSources(as []facts.TemporalAssertion) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.Source)
	}
	return out
}

// stringsOf coerces an attribute value that should be a string set into one, tolerating
// the []any form a JSON round trip produces.
func stringsOf(v any) []string {
	switch tv := v.(type) {
	case []string:
		return tv
	case []any:
		out := make([]string, 0, len(tv))
		for _, item := range tv {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// evidenceOf returns the evidence id paired with an observation id, which the facts
// package builds from the same event id and discriminator.
func evidenceOf(o facts.Observation) string {
	return strings.Replace(o.ID, "obs:", "ev:", 1)
}

// firstNonZero returns the first non-zero time, used where a facet prefers the source's
// own observation time and falls back to the capture time.
func firstNonZero(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}
