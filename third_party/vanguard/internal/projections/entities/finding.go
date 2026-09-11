package entities

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// FindingCategory groups findings by the kind of weakness. It is an open
// vocabulary: new passive or active tools may introduce additional categories.
type FindingCategory string

const (
	// FindingTLS covers certificate and TLS configuration weaknesses.
	FindingTLS FindingCategory = "tls"
	// FindingDNS covers DNS configuration weaknesses.
	FindingDNS FindingCategory = "dns"
	// FindingExposure covers unintended exposure of data or services.
	FindingExposure FindingCategory = "exposure"
	// FindingMisconfig covers general security misconfigurations.
	FindingMisconfig FindingCategory = "misconfiguration"
	// FindingVulnerability covers known vulnerabilities (CVE-backed).
	FindingVulnerability FindingCategory = "vulnerability"
	// FindingReputation covers threat-intelligence / reputation weaknesses (for
	// example a domain flagged malicious by reputation engines).
	FindingReputation FindingCategory = "reputation"
)

// Asset kinds an AssetRef.Kind may take. Each kind fixes the canonical form of the
// AssetRef.ID that accompanies it, so a finding always names an asset a projection can
// materialize:
//
//   - AssetKindDomain: a normalized DNS name, lower-cased with no trailing dot.
//   - AssetKindIP: a canonical IP literal (net.IP.String form).
//   - AssetKindCertificate: the key [CertificateID] produces, never a raw serial.
//   - AssetKindService: the canonical [ServiceID] ("host/port/proto") of an observed
//     socket, whose host is the address the service was seen on.
//   - AssetKindEndpoint: the normalized URL [EndpointID] produces.
//   - AssetKindNetblock: a CIDR prefix.
const (
	AssetKindDomain      = "domain"
	AssetKindIP          = "ip"
	AssetKindCertificate = "certificate"
	AssetKindService     = "service"
	AssetKindEndpoint    = "endpoint"
	AssetKindNetblock    = "netblock"
)

// AssetRef points a finding at the asset it concerns.
//
// Endpoint and Service are distinct on purpose. A Service is a socket, keyed by the
// address it was observed on; a URL never proves which address served it, so a URL-scoped
// weakness is an Endpoint and keeps its scheme, explicit port, and path instead of being
// flattened into a socket the scan did not observe.
type AssetRef struct {
	// Kind is one of the AssetKind* constants.
	Kind string
	// ID is the canonical key of the asset for that Kind, as documented on the
	// AssetKind* constants. Use Host and Port to read a service id rather than
	// parsing it.
	ID string
}

// ServiceFacet is the structured service identity behind a service-kind finding: the
// product/version/CPE and socket the finding concerns, carried so threat scenarios and
// the threat scenarios match on data instead of re-parsing Evidence prose. Zero value for
// findings with no service identity (DNS, mail, certificate findings).
type ServiceFacet struct {
	// Port and Proto are the socket the finding concerns (the same identity the
	// asset's ServiceID carries); zero when not service-scoped.
	Port  int
	Proto string
	// Product and Version are the fingerprinted platform, for example "Microsoft-IIS"
	// and "10.0". A concrete Version lets a consumer distinguish builds.
	Product string
	Version string
	// CPEs are Common Platform Enumeration ids for the product, for example
	// "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"; empty when the detector
	// fingerprinted a product name but no CPE (an httpx technology match).
	CPEs []string
}

// IsZero reports whether the facet carries no service identity.
func (s ServiceFacet) IsZero() bool {
	return s.Port == 0 && s.Proto == "" && s.Product == "" && s.Version == "" && len(s.CPEs) == 0
}

// Reference links a finding to an external catalogue entry.
type Reference struct {
	// Kind is "CWE", "CVE", or "URL".
	Kind string
	// Value is the identifier or link (for example "CWE-295", "CVE-2021-1234").
	Value string
}

// EvidenceWindow bounds when one source's evidence for a finding was observed. Both
// ends are needed: the newest says whether anything still supports the finding as
// current, the oldest says whether any of what it rests on is already stale. Collapsing
// them to one instant lets a fresh confirmation hide a year-old claim from the same
// source.
type EvidenceWindow struct {
	First time.Time
	Last  time.Time
}

// Finding represents a potential weakness discovered against an asset. The same
// weakness may be reported by several tools; a Finding's ID is derived only from
// its rule and asset so that those reports collapse into one finding (with the
// contributing events accumulated in Provenance).
type Finding struct {
	// ID is a stable identifier (hash of rule + asset) used for deduplication.
	ID string
	// Rule is the short machine name of the check (for example "expired-cert").
	Rule string
	// Title is a human-readable summary.
	Title string
	// Category groups the finding.
	Category FindingCategory
	// Severity is the assessed severity, on the same scale as events.Severity.
	Severity int
	// Asset is the affected asset.
	Asset AssetRef
	// Evidence is the concrete observation that triggered the finding.
	Evidence string
	// Recommendation is suggested operator follow-up.
	Recommendation string
	// References are external catalogue links.
	References []Reference
	// KnownExploited marks a finding whose CVE is in the bundled known-exploited
	// (CISA KEV) snapshot: exploited in the wild, a strong prioritization signal.
	// The risk model up-weights it so it outranks an equal-severity finding with no
	// known exploit. Set by local, offline catalogue enrichment.
	KnownExploited bool
	// Confidence states how trustworthy the finding is. A directly observed
	// weakness (a completed TLS handshake, an open port from a connect scan) is
	// ConfidenceConfirmed; a derived or third-party-inferred one (a Shodan/Netlas
	// banner-CVE) is ConfidenceInferred and stays inferred until a later confirmed
	// report of the same rule+asset upgrades it. Empty is treated as confirmed. The
	// risk model down-weights
	// inferred findings so they do not outrank a confirmed finding of equal severity.
	Confidence Confidence
	// Locations are the concrete URLs/paths the finding concerns, as structured
	// data a validator can target directly (for example the exact dork-surfaced
	// URLs on a host). Empty for findings with no per-URL detail. Not part of the
	// dedup ID: a finding is keyed by rule + asset, and several events for the same
	// host+rule merge their Locations.
	Locations []string
	// Service is the structured service identity behind a service-kind finding,
	// carried so scenarios match on data instead of re-parsing
	// Evidence prose. Zero value for findings with no service identity.
	Service ServiceFacet
	// Provenance records how the finding was established. Multiple entries mean
	// several events (possibly from different tools) corroborated the finding.
	Provenance []Provenance
	// FirstSeen is when the finding was first raised.
	FirstSeen time.Time

	// EvaluatedAt is the analysis cutoff the temporal fields below were classified
	// against. Without it "historical" and "current" are unreadable: they are
	// statements about a reference time, not properties of the finding.
	EvaluatedAt time.Time
	// EvidenceObservedFirst and EvidenceObservedLast bound when the evidence behind
	// this finding was actually observed, across every event that merged into it.
	// They are zero when no contributing source supplied an observation time, which
	// is a real answer (unknown) and not the same as "observed at scan time".
	EvidenceObservedFirst time.Time
	EvidenceObservedLast  time.Time
	// LastCorroboratedAt is when Vanguard last recorded a claim supporting this
	// finding. It is the scan's own capture time, so it answers "when did we last
	// look", which is a different question from EvidenceObservedLast ("when did the
	// source last see it").
	LastCorroboratedAt time.Time
	// EvidenceObservedBySource bounds each contributing source's own evidence. Freshness
	// is a per-source policy question - a provider that rescans weekly and one that
	// rescans quarterly do not make equally current claims at the same age - so the
	// per-source windows are kept rather than collapsed into one.
	EvidenceObservedBySource map[string]EvidenceWindow
	// EvidenceKinds are the acquisition methods behind this finding (active_probe,
	// dns_answer, passive_snapshot, historical_log, ...), sorted and deduplicated.
	// More than one entry means several kinds of evidence merged into one finding.
	EvidenceKinds []string
	// TemporalStatus is how this finding's evidence relates to EvaluatedAt. It is a
	// dimension independent of Confidence (how trustworthy): an inferred finding can
	// be recent, a confirmed one can be old.
	TemporalStatus TemporalStatus
	// TemporalReason is the short machine-readable justification for TemporalStatus,
	// so a consumer can group or filter without re-deriving the classification.
	TemporalReason string
	// CurrentCorroboration is the strongest kind of support this finding has for
	// being current at EvaluatedAt.
	CurrentCorroboration Corroboration
}

// TemporalStatus states how a finding's evidence relates to the analysis cutoff.
// A complete historical record must not silently become a current risk statement,
// so every finding carries one of these regardless of how it was found.
type TemporalStatus string

const (
	// TemporalStatusCurrent marks a finding supported as current at the cutoff.
	TemporalStatusCurrent TemporalStatus = "current"
	// TemporalStatusHistorical marks a finding whose evidence is historical only.
	TemporalStatusHistorical TemporalStatus = "historical"
	// TemporalStatusMixed marks a finding combining current and historical evidence.
	TemporalStatusMixed TemporalStatus = "mixed"
	// TemporalStatusUnknown marks a finding whose evidence has no interpretable
	// time. It is never treated as current, historical, clean, or zero-risk; it
	// means the finding needs re-observation.
	TemporalStatusUnknown TemporalStatus = "unknown"
)

// Corroboration names the strongest kind of support a finding has for being current.
type Corroboration string

const (
	// CorroborationActive marks a direct probe that got a positive response.
	CorroborationActive Corroboration = "active"
	// CorroborationDNS marks a positive DNS answer during the scan.
	CorroborationDNS Corroboration = "dns"
	// CorroborationRecentPassive marks a third-party observation inside that
	// source's declared freshness window, with no Vanguard confirmation.
	CorroborationRecentPassive Corroboration = "recent_passive"
	// CorroborationValidityOnly marks a validity interval covering the cutoff with
	// no observation of the subject being served.
	CorroborationValidityOnly Corroboration = "validity_only"
	// CorroborationNone marks a finding with nothing supporting it as current.
	CorroborationNone Corroboration = "none"
)

// NewFinding constructs a Finding, enforcing non-empty Rule, Title, and
// Asset.ID, and computing a stable deduplication ID from the rule and asset.
func NewFinding(rule, title string, category FindingCategory, severity int, asset AssetRef, evidence, recommendation string, references []Reference, firstSeen time.Time) (Finding, error) {
	if rule == "" {
		return Finding{}, fmt.Errorf("finding rule must not be empty")
	}
	if title == "" {
		return Finding{}, fmt.Errorf("finding title must not be empty")
	}
	if asset.ID == "" {
		return Finding{}, fmt.Errorf("finding asset ID must not be empty")
	}
	return Finding{
		ID:             FindingID(rule, asset),
		Rule:           rule,
		Title:          title,
		Category:       category,
		Severity:       severity,
		Asset:          asset,
		Evidence:       evidence,
		Recommendation: recommendation,
		References:     append([]Reference(nil), references...),
		FirstSeen:      firstSeen,
	}, nil
}

// FindingID computes the stable deduplication ID for a rule/asset pair. Two
// findings with the same rule and asset share an ID regardless of which tool or
// event produced them.
func FindingID(rule string, asset AssetRef) string {
	sum := sha256.Sum256([]byte(rule + "|" + asset.Kind + "|" + asset.ID))
	return fmt.Sprintf("%x", sum)
}
