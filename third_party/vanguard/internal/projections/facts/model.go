package facts

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Confidence grades how strongly a fact is supported. Passive third-party intelligence
// is medium; a direct DNS answer or an active confirmation is high; a weak passive
// fingerprint (an OS guess) is low.
type Confidence string

const (
	// ConfidenceLow marks a weak signal (for example a passive OS fingerprint).
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium marks passive third-party intelligence.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh marks a direct DNS answer or an active confirmation.
	ConfidenceHigh Confidence = "high"
)

// Currentness states what one observation, asset, or relationship proves about current
// state. It is kept separate from Confidence: trustworthy historical evidence can have
// high confidence while remaining historical for current-state analysis.
//
// The six values are exhaustive and mutually exclusive, and they are listed in
// precedence order: an asset supported by several kinds of evidence takes the strongest
// class it qualifies for, and the weaker evidence survives as a badge rather than being
// lost. One vocabulary serves both the observation level and the asset level so the two
// halves of the model cannot drift apart.
type Currentness string

const (
	// CurrentnessLiveVerified marks behavior Vanguard directly observed: an active
	// probe received a positive response during the scan.
	CurrentnessLiveVerified Currentness = "live_verified"
	// CurrentnessCurrentlyResolved marks a successful DNS collection that returned a
	// positive record during the scan.
	CurrentnessCurrentlyResolved Currentness = "currently_resolved"
	// CurrentnessValidUnverified marks a genuine validity interval that covers the
	// as-of time without any live proof that the subject is served. It applies only
	// where a source actually declares an interval, never to a point observation.
	CurrentnessValidUnverified Currentness = "valid_unverified"
	// CurrentnessRecentPassive marks a provider observation inside that provider's
	// declared freshness window, with no confirmation by Vanguard.
	CurrentnessRecentPassive Currentness = "recent_passive"
	// CurrentnessHistoricalOnly marks bounded evidence that ended before the as-of
	// time, with nothing newer corroborating it. The subject is retained in full.
	CurrentnessHistoricalOnly Currentness = "historical_only"
	// CurrentnessUnknown marks evidence that exists but supports no safe reading of
	// current state. It never means absent, historical, or clean.
	CurrentnessUnknown Currentness = "currentness_unknown"
)

// currentnessPrecedence orders the classes strongest-first, so a classifier that
// collects every applicable class can take the winner without restating the order.
var currentnessPrecedence = []Currentness{
	CurrentnessLiveVerified,
	CurrentnessCurrentlyResolved,
	CurrentnessValidUnverified,
	CurrentnessRecentPassive,
	CurrentnessHistoricalOnly,
	CurrentnessUnknown,
}

// AssetType is the kind of a graph node that represents a thing that exists.
type AssetType string

const (
	// AssetDomain is a registrable/root domain name.
	AssetDomain AssetType = "Domain"
	// AssetSubdomain is a name under a domain in scope.
	AssetSubdomain AssetType = "Subdomain"
	// AssetExternalDomain is a DNS name outside the scan root: a CNAME target or other
	// referenced name that is neither the root nor under it. It is kept in the complete
	// graph with its evidence and edges, but it is not the target's attack surface, so it
	// is not counted among the in-scope Domain/Subdomain assets.
	AssetExternalDomain AssetType = "ExternalDomain"
	// AssetIPAddress is an IPv4 or IPv6 address.
	AssetIPAddress AssetType = "IPAddress"
	// AssetService is a network service, keyed by the canonical ServiceID.
	AssetService AssetType = "Service"
	// AssetTechnology is a software product/technology.
	AssetTechnology AssetType = "Technology"
	// AssetProvider is an autonomous system / hosting provider.
	AssetProvider AssetType = "Provider"
	// AssetDNSRecord is a single DNS record materialized as a node.
	AssetDNSRecord AssetType = "DnsRecord"
	// AssetMailService is a mail exchanger host.
	AssetMailService AssetType = "MailService"
	// AssetNetblock is a routed CIDR prefix.
	AssetNetblock AssetType = "Netblock"
	// AssetCertificate is an X.509 certificate.
	AssetCertificate AssetType = "Certificate"
	// AssetEndpoint is an HTTP(S) endpoint (a URL that responded or was surfaced).
	AssetEndpoint AssetType = "Endpoint"
)

// RelationshipType is the kind of an edge between two assets.
type RelationshipType string

const (
	// RelSubdomainOf links a subdomain to its parent domain.
	RelSubdomainOf RelationshipType = "subdomain_of"
	// RelResolvesTo links a name to an IP it resolves to (A/AAAA).
	RelResolvesTo RelationshipType = "resolves_to"
	// RelCnameTo links a name to its CNAME target.
	RelCnameTo RelationshipType = "cname_to"
	// RelPtrTo links an IP address to the name its reverse lookup returned. It is
	// kept distinct from RelResolvesTo because a PTR record is the address owner's
	// claim about a name, not the name's forward resolution: the two disagree often
	// enough that merging them would invent forward records nobody observed.
	RelPtrTo RelationshipType = "ptr_to"
	// RelHasMX links a domain to a mail exchanger.
	RelHasMX RelationshipType = "has_mx"
	// RelHasNS links a domain to a nameserver record.
	RelHasNS RelationshipType = "has_ns"
	// RelHasDNSRecord links a zone owner to a DnsRecord node whose type has no dedicated
	// edge. A zone transfer dumps records of every type, so the generic edge keeps each
	// one joined to the name it belongs to without inventing typed semantics per record.
	RelHasDNSRecord RelationshipType = "has_dns_record"
	// RelHasTXT links a domain to a TXT record.
	RelHasTXT RelationshipType = "has_txt"
	// RelExposesService links an IP to a service it exposes.
	RelExposesService RelationshipType = "exposes_service"
	// RelHostedByProvider links an IP to its ASN/provider.
	RelHostedByProvider RelationshipType = "hosted_by_provider"
	// RelBelongsToASN links a netblock to its ASN/provider.
	RelBelongsToASN RelationshipType = "belongs_to_asn"
	// RelRunsTechnology links a service or endpoint to a technology it runs.
	RelRunsTechnology RelationshipType = "runs_technology"
	// RelHostObservedTechnology links an IP address to a technology a passive source
	// reported on the host without mapping it to any port. It is deliberately not
	// RelRunsTechnology: nothing in the claim says which listening service carries
	// the product, and pretending otherwise would manufacture a service fingerprint.
	RelHostObservedTechnology RelationshipType = "host_observed_technology"
	// RelServesEndpoint links the host named in an HTTP(S) endpoint's URL authority
	// to that endpoint. The host is the one the request actually addressed, so the
	// edge never widens to every IP the name has ever resolved to.
	RelServesEndpoint RelationshipType = "serves_endpoint"
	// RelRedirectsTo links the endpoint that returned a redirect response to the
	// normalized destination host referenced by its Location header.
	RelRedirectsTo RelationshipType = "redirects_to"
	// RelCertCoversName links a certificate to a name it covers.
	RelCertCoversName RelationshipType = "cert_covers_name"
	// RelFindingAffectsAsset links a finding candidate to the asset it concerns.
	RelFindingAffectsAsset RelationshipType = "finding_affects_asset"
	// RelFindingSupportedByEvidence links a finding candidate to a backing evidence node.
	RelFindingSupportedByEvidence RelationshipType = "finding_supported_by_evidence"
)

// Issue type tags for coverage/ingestion problems (never target risks).
const (
	// issueUnmappedEventType marks an event type with no facts normalizer yet.
	issueUnmappedEventType = "unmapped_event_type"
	// issueIncompletePassiveResult marks a truncated/incomplete passive source result.
	issueIncompletePassiveResult = "incomplete_passive_source_result"
	// issueQuarantine marks a malformed or non-materializable input (wildcard, invalid
	// parent, invalid IP), preserved as an issue rather than a silently dropped fact.
	issueQuarantine = "quarantine"
	// issueRecon passes an upstream IssueObserved (scan/tool error) through to the graph.
	issueRecon = "recon_issue"
	// issueInvertedValidityWindow marks a source-supplied validity interval that ends
	// before it starts. The window is clamped for ordering and both original bounds
	// stay on the assertion.
	issueInvertedValidityWindow = "inverted_validity_window"
)

// Attribute keys shared across normalizers, named once so the graph uses one spelling
// for each fact attribute.
const (
	attrFQDN           = "fqdn"
	attrIPVersion      = "ip_version"
	attrOwner          = "owner"
	attrHost           = "host"
	attrPriority       = "priority"
	attrValue          = "value"
	attrRecordType     = "record_type"
	attrResolver       = "resolver"
	attrQueryDomain    = "query_domain"
	attrPort           = "port"
	attrName           = "name"
	attrURL            = "url"
	attrStatusCode     = "status_code"
	attrProduct        = "product"
	attrASNNumber      = "asn_number"
	attrExposureSource = "exposure_source"
	attrExposureMode   = "exposure_mode"
	// exposureActive is the value both exposure attributes carry for something
	// Vanguard observed itself, as opposed to a provider's passive assertion.
	exposureActive = "active"
	attrTransport  = "transport"
	// Technology set attributes. They accumulate across every observation of the
	// same technology (see Graph.unionAssetSet) instead of being fixed by the first
	// one, so a version seen on a second endpoint or a CPE added by a second tool is
	// not lost.
	attrVersions   = "versions"
	attrCategories = "categories"
	attrCPEs       = "cpes"
	// attrPlatformCPEs holds operating-system and hardware CPEs inferred from a
	// service observation. Such CPEs describe host, not listening product.
	attrPlatformCPEs = "platform_cpes"
)

// Asset is a graph node: a thing that exists, deduplicated by canonical Key within its
// Type. Attributes are type-specific (for example ip_version, port, transport, asn_number).
//
// (Type, Key) is the whole identity, and it is deliberately session-independent: no scan
// id, event id, or capture time enters it. The same name, address, or service observed in
// two scans of the same estate produces the same pair, so assets can be joined across
// sessions by identity alone. Session provenance is not lost, it is just kept where it
// belongs: the graph's ScanID, and the observations, evidence, assertions, and event
// references that record who saw this and when. Joining two sessions by identity is not
// the same as merging their observations, which stay attributed to the session that
// captured them.
//
// FirstSeen and LastSeen are the compact ordering summary and nothing more: the min and
// max real-world instant across every assertion, with the scan time substituted where a
// source supplied no time. They are safe to sort and lay out by, and unsafe to read as a
// lifecycle, because two point observations five years apart produce the same pair as one
// genuine five-year validity interval. Assertions holds what each source actually claimed
// and TemporalSummary holds the precisely defined aggregates; read those to reason about
// time.
type Asset struct {
	Type       AssetType      `json:"type"`
	Key        string         `json:"key"`
	Attributes map[string]any `json:"attributes,omitempty"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Sources    []string       `json:"sources,omitempty"`
	// TemporalSummary is derived from Assertions when the graph is rendered; it is
	// empty during the fold.
	TemporalSummary
	Assertions []TemporalAssertion `json:"assertions,omitempty"`
}

// Observation is a claim by a source about an asset. Observations are never
// deduplicated: multiple sources reporting the same asset produce multiple observations.
type Observation struct {
	ID               string                 `json:"id"`
	Type             string                 `json:"type"`
	AssetKey         string                 `json:"asset_key"`
	Source           string                 `json:"source"`
	Mode             events.Phase           `json:"mode"`
	ObservationKind  events.ObservationKind `json:"observation_kind"`
	Confidence       Confidence             `json:"confidence"`
	Currentness      Currentness            `json:"currentness"`
	RawEventID       string                 `json:"raw_event_id"`
	CausedByEventID  string                 `json:"caused_by_raw_event_id,omitempty"`
	ToolCorrID       string                 `json:"tool_corr_id,omitempty"`
	CapturedAt       time.Time              `json:"captured_at"`
	SourceObservedAt time.Time              `json:"source_observed_at,omitzero"`
	ValidFrom        time.Time              `json:"valid_from,omitzero"`
	ValidUntil       time.Time              `json:"valid_until,omitzero"`
	LoggedAt         time.Time              `json:"logged_at,omitzero"`
	LiveVerifiedAt   time.Time              `json:"live_verified_at,omitzero"`
	Metadata         map[string]any         `json:"metadata,omitempty"`
}

// Evidence is a usable proof derived from an observation that can support a relationship
// or a later finding.
type Evidence struct {
	ID            string       `json:"id"`
	Type          string       `json:"type"`
	ObservationID string       `json:"observation_id"`
	Statement     string       `json:"statement"`
	Source        string       `json:"source"`
	Mode          events.Phase `json:"mode"`
	Confidence    Confidence   `json:"confidence"`
	RawEventID    string       `json:"raw_event_id"`
}

// Relationship is a graph edge between two assets, deduplicated by (Type, From, To).
//
// EvidenceID, Confidence, and Mode summarize the strongest assertion the edge carries, so
// an active probe upgrading a passive edge is visible at a glance. The upgrade never
// discards the weaker claim: Assertions keeps every one, which is what makes a historical
// cert_covers_name claim and a current DNS claim about the same pair separable after the
// merge. FirstSeen and LastSeen carry the same ordering-only caveat as on Asset.
type Relationship struct {
	Type          RelationshipType `json:"type"`
	From          string           `json:"from"`
	To            string           `json:"to"`
	EvidenceID    string           `json:"evidence_id,omitempty"`
	Confidence    Confidence       `json:"confidence"`
	Mode          events.Phase     `json:"mode"`
	SourceEventID string           `json:"source_event_id"`
	FirstSeen     time.Time        `json:"first_seen"`
	LastSeen      time.Time        `json:"last_seen"`
	Metadata      map[string]any   `json:"metadata,omitempty"`
	// TemporalSummary is derived from Assertions when the graph is rendered; it is
	// empty during the fold.
	TemporalSummary
	Assertions []TemporalAssertion `json:"assertions,omitempty"`
}

// FindingCandidate is an evidence-backed potential weakness, never asserted without a
// chain RawEvent -> Observation -> Evidence -> Finding. It reuses the FindingRaised id
// (rule + affected asset) so the same weakness from more than one event is one candidate.
type FindingCandidate struct {
	ID             string          `json:"id"`
	Rule           string          `json:"rule"`
	Category       string          `json:"category,omitempty"`
	Title          string          `json:"title,omitempty"`
	AssetKey       string          `json:"asset_key"`
	Confidence     Confidence      `json:"confidence"`
	Severity       events.Severity `json:"severity"`
	EvidenceIDs    []string        `json:"evidence_ids,omitempty"`
	References     []string        `json:"references,omitempty"`
	Recommendation string          `json:"recommendation,omitempty"`
	SourceEventID  string          `json:"source_event_id"`
	FirstSeen      time.Time       `json:"first_seen"`
	LastSeen       time.Time       `json:"last_seen"`
}

// Issue is a coverage or ingestion problem, kept separate from any target risk.
type Issue struct {
	Type       string          `json:"type"`
	Source     string          `json:"source,omitempty"`
	Severity   events.Severity `json:"severity"`
	Message    string          `json:"message"`
	RawEventID string          `json:"raw_event_id,omitempty"`
}
