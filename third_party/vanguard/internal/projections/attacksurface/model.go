package attacksurface

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
)

// dataView states what this artifact is, in the same vocabulary the facts file uses. The
// contraction removes node kinds, never evidence: everything a folded node carried is
// still addressable through the observation and evidence ids it kept.
const dataView = events.DataViewCompleteHistory

// NodeType is the kind of a retained attack-surface node. There are exactly four, and the
// list is closed on purpose: an analyst reasons about names, addresses, listening
// services, and web origins, and every other fact the scan produced is a property of one
// of those four rather than a thing to be laid out and clicked on.
type NodeType string

const (
	// NodeDomain is one DNS name, whatever its scope. The facts Domain, Subdomain, and
	// ExternalDomain types collapse here and keep the distinction as Kind and Scope,
	// because "is this name in scope" is an attribute of a name, not a different kind
	// of thing that deserves its own node shape.
	NodeDomain NodeType = "Domain"
	// NodeIPAddress is one IPv4 or IPv6 address.
	NodeIPAddress NodeType = "IPAddress"
	// NodeService is one listening service, keyed by the canonical host/port/transport.
	NodeService NodeType = "Service"
	// NodeWebSurface is one HTTP(S) origin: scheme, host, and port. Individual URLs
	// contract onto it as observed paths, because fifty paths on one origin are one
	// thing to assess and fifty nodes to draw.
	NodeWebSurface NodeType = "WebSurface"
)

// EdgeType is the kind of a retained attack-surface edge.
type EdgeType string

const (
	// EdgeSubdomainOf links a name to its parent name.
	EdgeSubdomainOf EdgeType = "subdomain_of"
	// EdgeResolvesTo links a name to an address it resolves to.
	EdgeResolvesTo EdgeType = "resolves_to"
	// EdgeCnameTo links a name to its alias target.
	EdgeCnameTo EdgeType = "cname_to"
	// EdgePtrTo links an address to the name its reverse lookup returned. It stays
	// distinct from EdgeResolvesTo for the reason the facts edge does: a PTR record is
	// the address operator's label, not a forward resolution.
	EdgePtrTo EdgeType = "ptr_to"
	// EdgeMailRoutesTo links a domain to the name of its mail exchanger. The facts
	// MailService wrapper node does not survive: a mail exchanger is a host name, and
	// giving it a second node type would split one name across two identities.
	EdgeMailRoutesTo EdgeType = "mail_routes_to"
	// EdgeExposesService links an address to a service listening on it.
	EdgeExposesService EdgeType = "exposes_service"
	// EdgeServesWebSurface links the host named in a URL authority to the web origin
	// it serves. It is the contracted form of the facts serves_endpoint edge.
	EdgeServesWebSurface EdgeType = "serves_web_surface"
	// EdgeRedirectsTo links a web origin to the host its redirect response pointed at.
	EdgeRedirectsTo EdgeType = "redirects_to"
	// EdgeTLSAssessedFor links a service to a name a TLS assessment explicitly says it
	// covered. It is derived only from the assessment's own assessed-names metadata,
	// never from what happens to resolve to the service's address.
	EdgeTLSAssessedFor EdgeType = "tls_assessed_for"
)

// Scope says whether a node is part of the assessed attack surface or merely referenced
// by it. External nodes stay visible - a redirect to a third party is exactly the kind of
// thing an analyst must see - but they never count toward an in-scope total.
type Scope string

const (
	// ScopeInScope marks a node inside the assessed root.
	ScopeInScope Scope = "in_scope"
	// ScopeExternal marks a node outside the assessed root that the surface references.
	ScopeExternal Scope = "external"
)

// DomainKind records which facts name type a Domain node came from, so the contraction
// that merged three node types into one is reversible by a reader.
type DomainKind string

const (
	// DomainKindRoot is the scan root itself.
	DomainKindRoot DomainKind = "root"
	// DomainKindSubdomain is a name under the scan root.
	DomainKindSubdomain DomainKind = "subdomain"
	// DomainKindExternal is a name outside the scan root.
	DomainKindExternal DomainKind = "external"
)

// Node is one retained thing in the contracted graph.
//
// A node carries three separate kinds of detail and keeps them separate on purpose.
// Attributes are what the thing is. Facets are what other sources folded onto it, each
// one still naming the observations and evidence it came from. Findings are the raised
// weaknesses that concern it. Flattening the three into one property bag would make the
// difference between "this address is in AS15169" and "this address has a critical
// finding" a matter of reading the key name.
type Node struct {
	// ID is the typed identity, "<Type>:<Key>", unique across the whole graph. Edges
	// address nodes by it, so a name and an address that happened to share a key
	// string could never be confused for one another.
	//
	// It carries no scan id and no event id: the same domain, address, service, or web
	// origin gets the same node ID in every session that observes it, so two captures of
	// one estate can be joined node for node. Graph.ScanID and the folded facets'
	// observation and evidence references carry the session provenance instead.
	ID   string   `json:"id"`
	Type NodeType `json:"type"`
	// Key is the untyped identity within the type: the name, the address, the
	// canonical service id, or the normalized origin.
	Key string `json:"key"`
	// Label is what a viewer renders. It is the key for everything except a service,
	// where "203.0.113.10:443/tcp" reads better than the canonical id.
	Label string `json:"label"`
	Scope Scope  `json:"scope"`
	// Kind further classifies a Domain node; it is empty on the other types.
	Kind DomainKind `json:"kind,omitempty"`
	// ReferencedOnly marks a node no source ever observed directly: it exists because
	// something else pointed at it. A CNAME target nobody resolved and a redirect
	// destination nobody probed are real parts of the picture and dishonest to count
	// as discovered surface.
	ReferencedOnly bool `json:"referenced_only,omitempty"`
	// Primary is the single currentness class the node counts under, taken from the
	// facts classification of the assets that contracted into it. Contraction never
	// computes a stronger class than one of its inputs already carried.
	Primary facts.Currentness `json:"primary_currentness"`
	// Badges are every other piece of temporal evidence about the contributing assets,
	// so the exclusive class does not hide the corroboration behind it.
	Badges  []string `json:"badges,omitempty"`
	Sources []string `json:"sources,omitempty"`
	// Attributes are the identity-level properties of the thing itself.
	Attributes map[string]any `json:"attributes,omitempty"`
	// Facets are the folded facts: registration, DNS policy records, certificate
	// coverage, provider attribution, host profile, TLS and SSH posture, and the rest.
	Facets []Facet `json:"facets,omitempty"`
	// Technologies are the products attributed to this node, each stating whether it
	// was fingerprinted on the thing itself or merely seen on its host.
	Technologies []Technology `json:"technologies,omitempty"`
	// Findings are the raised weaknesses that concern this node, strongest first.
	Findings []Finding `json:"findings,omitempty"`
	// Paths are the observed URL paths on a web surface, sorted; empty elsewhere.
	Paths []PathObservation `json:"paths,omitempty"`
	// ObservationIDs and EvidenceIDs are the full provenance chain back into
	// the facts graph beside it. Nothing is summarized away that cannot be looked up.
	ObservationIDs []string `json:"observation_ids,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	// FactsAssetKeys names every facts asset that contracted into this node, so a
	// reader can always walk back to the uncontracted graph.
	FactsAssetKeys []string  `json:"facts_asset_keys,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitzero"`
	LastSeen       time.Time `json:"last_seen,omitzero"`
}

// Facet is one folded fact attached to a retained node: what kind of claim it is, what it
// says, how strongly it is believed, how current it is, and where it came from.
//
// A facet is never merged with another facet of the same kind. Two sources that disagree
// about a registrar produce two facets, because the disagreement is information and a
// merge would silently pick a winner.
type Facet struct {
	// Kind names the class of claim, matching the facts observation type it came from
	// so the two artifacts are greppable against each other.
	Kind string `json:"kind"`
	// Statement is the evidence sentence, retained verbatim.
	Statement   string            `json:"statement,omitempty"`
	Confidence  facts.Confidence  `json:"confidence,omitempty"`
	Currentness facts.Currentness `json:"currentness,omitempty"`
	Source      string            `json:"source,omitempty"`
	Mode        events.Phase      `json:"mode,omitempty"`
	// Values is the observation metadata: the registrar, the TLS section states, the
	// ASN and prefix, whatever the claim actually carried.
	Values        map[string]any `json:"values,omitempty"`
	ObservationID string         `json:"observation_id,omitempty"`
	EvidenceID    string         `json:"evidence_id,omitempty"`
	// SourceObservedAt is when the source says it saw this, absent when it never said.
	SourceObservedAt time.Time `json:"source_observed_at,omitzero"`
}

// TechnologyRelation says how a product was attributed to a node, which is the whole
// reason technology folds onto nodes instead of staying a node itself.
type TechnologyRelation string

const (
	// TechRuns means a fingerprint of the thing itself identified the product.
	TechRuns TechnologyRelation = "runs"
	// TechHostObserved means a passive source saw the product on the host with no
	// mapping to any port. It never becomes TechRuns during contraction: nothing in
	// such a claim identifies which listening service carries the product.
	TechHostObserved TechnologyRelation = "host_observed"
)

// Technology is one product attributed to a node, carrying the canonical identity from
// the facts graph plus every version, category, and CPE that accumulated on it.
type Technology struct {
	Key        string             `json:"key"`
	Relation   TechnologyRelation `json:"relation"`
	Versions   []string           `json:"versions,omitempty"`
	Categories []string           `json:"categories,omitempty"`
	CPEs       []string           `json:"cpes,omitempty"`
	// Confidence and Currentness are the ones the source relationship carried; the
	// contraction copies them and never raises either.
	Confidence  facts.Confidence  `json:"confidence"`
	Currentness facts.Currentness `json:"currentness,omitempty"`
	Sources     []string          `json:"sources,omitempty"`
	EvidenceIDs []string          `json:"evidence_ids,omitempty"`
}

// Finding is a raised weakness attached to the retained node it concerns.
type Finding struct {
	ID          string           `json:"id"`
	Rule        string           `json:"rule"`
	Title       string           `json:"title,omitempty"`
	Category    string           `json:"category,omitempty"`
	Severity    events.Severity  `json:"severity"`
	Confidence  facts.Confidence `json:"confidence"`
	EvidenceIDs []string         `json:"evidence_ids,omitempty"`
	// FactsAssetKey is the asset the finding was raised against in the facts graph.
	// It is preserved verbatim even when the finding attached to a different node -
	// a certificate finding lands on the names the certificate covers - so the
	// original subject is never lost to the remap.
	FactsAssetKey string `json:"facts_asset_key"`
	// AttachmentRule names why this finding landed where it did, so an attachment an
	// analyst finds surprising is explainable without re-deriving the contraction.
	AttachmentRule string `json:"attachment_rule,omitempty"`
}

// PathObservation is one URL observed on a web origin, with what the response said.
// Paths are a list rather than a merged summary because two paths on one origin routinely
// answer differently, and collapsing them to a single status or title would let one
// arbitrary response overwrite the others.
type PathObservation struct {
	Path       string   `json:"path"`
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code,omitempty"`
	Title      string   `json:"title,omitempty"`
	Server     string   `json:"server,omitempty"`
	AuthType   string   `json:"auth_type,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// Edge is one retained relationship between two nodes, addressed by typed node id.
type Edge struct {
	Type EdgeType `json:"type"`
	From string   `json:"from"`
	To   string   `json:"to"`
	// Confidence and Currentness are the strongest a contributing facts edge carried.
	// Contraction takes a maximum over claims that already existed; it never invents a
	// grade, so a merge of passive edges stays passive.
	Confidence  facts.Confidence  `json:"confidence"`
	Currentness facts.Currentness `json:"currentness,omitempty"`
	Mode        events.Phase      `json:"mode,omitempty"`
	Sources     []string          `json:"sources,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
	EvidenceIDs []string          `json:"evidence_ids,omitempty"`
	// SourceEventIDs are the raw events behind every contributing claim.
	SourceEventIDs []string  `json:"source_event_ids,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitzero"`
	LastSeen       time.Time `json:"last_seen,omitzero"`
}

// Outcome is what the contraction decided to do with one facts asset type.
type Outcome string

const (
	// OutcomeRetained means assets of the type became nodes.
	OutcomeRetained Outcome = "retained"
	// OutcomeFolded means assets of the type became attributes, facets, technologies,
	// paths, or findings on a retained node. Nothing was discarded.
	OutcomeFolded Outcome = "folded"
	// OutcomeExcluded means assets of the type are deliberately absent from this view
	// and remain fully addressable in the facts artifact.
	OutcomeExcluded Outcome = "excluded"
)

// AssetOutcome accounts for one facts asset type: how many there were, what happened to
// them, and why. Every type in the facts vocabulary appears exactly once, present in the
// scan or not, so a new asset type cannot slip through without a decision.
type AssetOutcome struct {
	AssetType facts.AssetType `json:"asset_type"`
	Outcome   Outcome         `json:"outcome"`
	Count     int             `json:"count"`
	// Contracted counts how many of Count were actually attached somewhere. For a
	// retained type it is the node count; for a folded type it is the number that
	// found a host node.
	Contracted int `json:"contracted"`
	// Standalone counts how many of Count the facts graph itself joined to nothing,
	// so the contraction had no relationship to fold them through. A certificate
	// covering only wildcard names is the standing example: a wildcard is a zone
	// directive rather than an asset, so there is no name to carry the coverage.
	//
	// The field exists so the accounting closes as an identity a reader can check:
	// Count == Contracted + Standalone. Without it, a legitimately isolated asset and
	// a lost one would look identical - both a number smaller than Count - and the
	// promise that nothing disappears quietly would rest on trust. An asset the facts
	// graph did join to something and the contraction still dropped breaks the
	// identity and is reported as an uncontracted_asset violation.
	Standalone int    `json:"standalone"`
	Reason     string `json:"reason"`
}

// TypeCount is a sorted count entry, used for node and edge type breakdowns.
type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// ContractionSummary is the full accounting of what the contraction did, so a reader can
// prove nothing vanished between the two artifacts.
type ContractionSummary struct {
	// Assets accounts for every facts asset type.
	Assets []AssetOutcome `json:"assets"`
	// NodesByType and EdgesByType are the resulting graph's shape.
	NodesByType []TypeCount `json:"nodes_by_type"`
	EdgesByType []TypeCount `json:"edges_by_type"`
	// InScopeNodes and ExternalNodes split the node total by scope.
	InScopeNodes  int `json:"in_scope_nodes"`
	ExternalNodes int `json:"external_nodes"`
	// FactsRelationships and ContractedRelationships account for the input edges: how
	// many the facts graph held and how many the contraction consumed, whether by
	// becoming an edge or by folding into a node.
	FactsRelationships      int `json:"facts_relationships"`
	ContractedRelationships int `json:"contracted_relationships"`
	// FindingsTotal, FindingsAttached, and FindingsUnmapped account for the findings.
	FindingsTotal    int `json:"findings_total"`
	FindingsAttached int `json:"findings_attached"`
	FindingsUnmapped int `json:"findings_unmapped"`
	// IssueCount and UnmappedEventTypes are scan-health totals, carried as counts only.
	// Scan faults are not attack topology and do not belong among the nodes; the facts
	// and issues reports hold the detail.
	IssueCount         int `json:"issue_count"`
	UnmappedEventTypes int `json:"unmapped_event_types"`
}

// Graph is the contracted attack surface: the artifact this package exists to produce.
type Graph struct {
	ScanID     string `json:"scan_id"`
	RootTarget string `json:"root_target,omitempty"`
	// GeneratedAt is inherited from the facts view, which derives it from the stream
	// rather than a clock, so the artifact is byte-stable across rebuilds.
	GeneratedAt time.Time `json:"generated_at"`
	// AnalysisAsOf and AnalysisPartial are the facts cutoff, restated here because a
	// currentness label is meaningless without the instant it was measured against.
	AnalysisAsOf    time.Time `json:"analysis_as_of"`
	AnalysisPartial bool      `json:"analysis_partial,omitempty"`
	// DataView states that the contraction removed node kinds, not evidence. It
	// describes this artifact's filtering, not whether collection completed; that is
	// SourceCollection.
	DataView string `json:"data_view"`
	// SourceCollection is the compact collection outcome of the collection this
	// surface was contracted from: how it ended and how many health-bearing events it
	// observed. It is copied from the projector's one mapping of the capture
	// manifest, never derived here, and it is deliberately compact - the exact problem
	// rows live once, in the operator report - so this artifact states the same verdict
	// without becoming a second ledger of it. Nil when the caller had no manifest.
	SourceCollection *SourceCollection `json:"source_collection,omitempty"`
	// The retained nodes are held in one array per node type rather than in a single
	// mixed array. There are exactly four types and the list is closed, so a reader who
	// wants the addresses can take the addresses instead of filtering a heterogeneous
	// list by a discriminator, and the file states the shape of the surface at the top
	// level. Each array is present even when empty, so an absent kind reads as "the scan
	// found none" rather than as a key someone forgot to write.
	Domains            []Node             `json:"domains"`
	IPAddresses        []Node             `json:"ip_addresses"`
	Services           []Node             `json:"services"`
	WebSurfaces        []Node             `json:"web_surfaces"`
	Edges              []Edge             `json:"edges"`
	ContractionSummary ContractionSummary `json:"contraction_summary"`
	// UnmappedFindings are the findings with no defensible retained target. They are
	// listed in full rather than counted, because a lost finding is the one kind of
	// contraction loss that could hurt someone.
	UnmappedFindings []Finding       `json:"unmapped_findings"`
	Integrity        IntegrityReport `json:"integrity"`
}

// SourceCollection is the compact source-collection verdict carried into the
// surface artifacts. It says how the collection ended and how much it lost, and
// points at the operator report for the rows behind the total. It changes no node,
// edge, finding, or integrity value: a collection loss is a statement about what was
// looked at, never about what was found.
type SourceCollection struct {
	// Status is the source collection's recorded status.
	Status string `json:"status"`
	// HealthTotal is the number of health-bearing tool events it observed.
	HealthTotal int `json:"health_total"`
}

// Incomplete reports whether the collection behind this surface is known to have
// lost work or stopped short of a clean conclusion.
func (s SourceCollection) Incomplete() bool {
	return s.Status != "succeeded" || s.HealthTotal > 0
}

// IntegrityViolationKind names one class of structural defect in a contracted graph.
type IntegrityViolationKind string

const (
	// ViolationDuplicateNode marks two nodes sharing one typed id.
	ViolationDuplicateNode IntegrityViolationKind = "duplicate_node"
	// ViolationDuplicateEdge marks two edges sharing one (type, from, to) identity,
	// which means a merge policy was missing rather than that the graph has a cycle.
	ViolationDuplicateEdge IntegrityViolationKind = "duplicate_edge"
	// ViolationDanglingEdge marks an edge whose endpoint names no node.
	ViolationDanglingEdge IntegrityViolationKind = "dangling_edge"
	// ViolationIsolatedNode marks a retained node no edge touches and whose type
	// carries no documented reason to stand alone.
	ViolationIsolatedNode IntegrityViolationKind = "isolated_node"
	// ViolationLostFinding marks a finding that neither attached to a node nor landed
	// in the unmapped list.
	ViolationLostFinding IntegrityViolationKind = "lost_finding"
	// ViolationUndecidedAssetType marks a facts asset type the contraction has no rule
	// for. It fires the moment a new asset type appears upstream, which is exactly
	// when it is cheap to decide what should happen to it.
	ViolationUndecidedAssetType IntegrityViolationKind = "undecided_asset_type"
	// ViolationUncontractedAsset marks assets of a folded type that found no host
	// node, which is silent data loss.
	ViolationUncontractedAsset IntegrityViolationKind = "uncontracted_asset"
)

// IntegrityViolation is one structural defect, named precisely enough to act on.
type IntegrityViolation struct {
	Kind    IntegrityViolationKind `json:"kind"`
	Subject string                 `json:"subject"`
	Detail  string                 `json:"detail"`
}

// IntegrityReport is the verdict on a contracted graph's structure. It is embedded in the
// artifact rather than kept beside it, so the file always states its own soundness.
type IntegrityReport struct {
	// Violations is always rendered, empty included. An absent key would leave a
	// reader unable to tell a sound graph from one whose verdict was never computed.
	Violations []IntegrityViolation `json:"violations"`
	// IsolatedByDesign counts, per node type, the isolated nodes a documented rule
	// permits. They are legitimate but worth seeing in one place.
	IsolatedByDesign []TypeCount `json:"isolated_by_design,omitempty"`
}

// AllNodes returns every retained node, in type order and sorted within each type. It is
// how the renderers and the integrity check walk the graph: they reason about all four
// kinds at once, and splitting the artifact by type should not force every one of them to
// name the four arrays.
func (g *Graph) AllNodes() []Node {
	out := make([]Node, 0, len(g.Domains)+len(g.IPAddresses)+len(g.Services)+len(g.WebSurfaces))
	out = append(out, g.Domains...)
	out = append(out, g.IPAddresses...)
	out = append(out, g.Services...)
	out = append(out, g.WebSurfaces...)
	return out
}

// nodeID builds the typed node identity used by every edge endpoint.
func nodeID(t NodeType, key string) string { return string(t) + ":" + key }
