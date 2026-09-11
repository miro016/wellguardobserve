package events

import "time"

var _ DomainEvent = FindingRaised{}

// FindingRaised signals that a potential weakness was detected against an asset.
// It is deliberately distinct from IssueObserved: an issue is something wrong
// with our scan, a finding is something noteworthy about the target. Findings
// may be produced by passive or active tools; the same weakness reported by more
// than one tool collapses into a single Finding entity downstream.
type FindingRaised struct {
	EventMeta
	// Rule is the short machine name of the detector that raised the finding.
	Rule string
	// Title is a human-readable summary.
	Title string
	// FindingCategory groups the finding (for example "tls", "dns").
	FindingCategory string
	// AssetKind is the kind of affected asset ("domain", "ip", "certificate",
	// "service", "endpoint", "netblock"). Projection entities interpret the plain
	// wire value without becoming a collection dependency.
	AssetKind string
	// AssetID is the canonical key of the affected asset for that AssetKind, not a
	// free-form label. A projection that materializes the asset graph must be able to
	// find exactly one asset under this key, so a detector constructs it with the same
	// identity function the normalizer uses:
	//
	//   - "domain": normalized DNS name, lower-cased with no trailing dot.
	//   - "ip": canonical IP literal.
	//   - "certificate": canonical serial plus common name, never a raw serial.
	//   - "service": canonical "host/port/transport" of an observed socket, whose host
	//     is the address the service was seen on.
	//   - "endpoint": normalized absolute HTTP(S) URL, keeping explicit port and path.
	//   - "netblock": CIDR prefix.
	//
	// A URL-scoped weakness is an endpoint, never a service keyed by the URL host: an
	// HTTP response does not prove which address served it, and a hostname-shaped
	// socket key names a service asset that cannot exist. A detector that cannot build
	// a canonical key raises no finding rather than emitting a key nothing owns.
	AssetID string
	// Evidence is the concrete observation that triggered the finding.
	Evidence string
	// Recommendation is suggested operator follow-up.
	Recommendation string
	// References are external catalogue links, formatted (for example "CWE-200").
	References []string
	// KnownExploited marks a finding whose CVE is in the bundled known-exploited
	// (CISA KEV) snapshot. The risk model up-weights it. Set by offline enrichment.
	KnownExploited bool
	// Confidence is a plain wire value ("confirmed" or "inferred") interpreted by
	// projections. It
	// marks a derived or third-party-inferred finding (a banner-CVE) as "inferred";
	// empty is treated as confirmed. A later event reporting the same rule+asset
	// "confirmed" upgrades the folded finding.
	Confidence string
	// Locations are the concrete URLs/paths the finding concerns, as structured
	// data downstream consumers can target directly instead of parsing Evidence
	// text (for example the exact dork-surfaced URLs on a host). Empty for findings
	// with no per-URL detail.
	Locations []string
	// Service carries the structured service identity (product, version, CPEs, port)
	// the detector already held, so scenarios match on data
	// instead of parsing Evidence prose. Zero value for findings with no service
	// identity (DNS, mail, certificate findings).
	Service ServiceFacet
	// EvidenceObservedAt is when the evidence behind this finding was observed, which
	// is not the same instant as EventMeta.CapturedAt. CapturedAt says when Vanguard
	// recorded the claim during this scan; EvidenceObservedAt says when the subject was
	// actually seen. For an active probe the two coincide. For a provider-derived
	// finding it is the provider's own observation time (a Censys service scan_time, a
	// Shodan banner timestamp), which can be months older than the scan.
	//
	// Zero means the source supplied no observation time. It must stay zero in that
	// case: substituting the scan time would assert that the provider observed the
	// service during this scan, which is exactly the false-currentness claim this
	// field exists to prevent.
	EvidenceObservedAt time.Time
	// EvidenceObservationKind is how the evidence behind this finding was acquired -
	// the triggering event's ObservationKind, not the finding event's own (which is
	// always "derived", since a finding is derived from another event). It lets a
	// consumer tell a live-probe finding from one inferred off a historical log or a
	// passive third-party snapshot without parsing Evidence prose or guessing from
	// the source name.
	EvidenceObservationKind ObservationKind
}

// ServiceFacet is the structured service identity behind a service-kind finding: the
// product/version/CPE and socket it concerns. Projection entities interpret this
// plain event data. Zero value for findings with no service identity.
type ServiceFacet struct {
	// Port and Proto are the socket the finding concerns (the same identity the
	// asset's ServiceID carries); zero when not service-scoped.
	Port  int
	Proto string
	// Product and Version are the fingerprinted platform, for example "Microsoft-IIS"
	// and "10.0".
	Product string
	Version string
	// CPEs are Common Platform Enumeration ids, for example
	// "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"; empty when the detector
	// fingerprinted a product name but no CPE (an httpx technology match).
	CPEs []string
}

// At returns the time when the finding was raised.
func (e FindingRaised) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e FindingRaised) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e FindingRaised) String() string {
	return "finding " + e.Rule + " (" + e.Meta().Severity.String() + ") on " + e.AssetKind + " " + e.AssetID + ": " + e.Title
}

func (FindingRaised) isDomainEvent() {}
