package assetgraph

import "github.com/velgard-sk/vanguard/internal/projections/entities"

// Graph is the read-only view the threat scenarios and exploit-plan rules query. It
// exposes the inventory edges (so a rule can walk domain -> IP -> service -> cert),
// the findings indexed on each asset, and the few cross-asset facets the rules gate
// on. It is satisfied by the projection's concrete graph over the folded inventory
// and by small fakes in the rule packages' tests.
type Graph interface {
	// DomainIPs returns the addresses a domain resolves to: DNS-confirmed answers
	// only, empty when the domain is unknown or resolves to nothing. Passive
	// associations a provider attributes to the name (reverse links, cert SANs) are
	// deliberately excluded, so a walk that narrates "resolves to" never crosses an
	// address the name does not resolve to. That inferred breadth stays on the
	// inventory node (DomainNode.AssociatedIPs) for callers that want "seen near this
	// host"; no rule needs it today, so it is intentionally not exposed here.
	DomainIPs(domain string) []string
	// DomainCerts returns the serials of certificates covering a domain.
	DomainCerts(domain string) []string
	// IPDomains returns the names that resolve to an IP.
	IPDomains(ip string) []string
	// IPServices returns the service assets open on an IP, keyed as the inventory
	// keys them ("ip:port/proto").
	IPServices(ip string) []entities.AssetRef
	// IPNetblock returns the CIDR prefix an IP belongs to, or "" when unknown.
	IPNetblock(ip string) string
	// CertNames returns the names a certificate covers, looked up by the canonical
	// certificate asset id a finding carries (entities.CertificateID, not a raw
	// serial); ok is false when the id names no certificate in the inventory
	// (nothing to chain to).
	CertNames(certID string) (names []string, ok bool)

	// FindingAssets returns the assets of the given kind that carry at least one
	// finding, sorted by id. It replaces iterating a pre-built per-kind finding index.
	FindingAssets(kind string) []entities.AssetRef
	// Findings returns the rule -> finding map for an asset, nil when the asset
	// carries no finding.
	Findings(asset entities.AssetRef) map[string]*entities.Finding

	// HasAuthSurface reports whether a domain exposes a login/admin web surface by any
	// of its faces: observed on the domain itself (an active probe or an admin/auth
	// dork) or on any IP the name resolves to (an endpoint probed on a bare IP, which
	// has no domain node). The IP resolution is what lets an IP-hosted admin surface
	// reach the credential paths that key on the domain.
	HasAuthSurface(domain string) bool
	// LiveDomain reports whether a name is serving live (reachable) TLS by any of its
	// faces: its own reachable TlsPosture, or an IP it resolves to that served a
	// completed https response. The IP resolution lets a certificate served on an
	// address, not only on a name with its own TLS posture, count as live.
	LiveDomain(domain string) bool
	// NetblockCount is how many netblocks the scan observed.
	NetblockCount() int

	// HostIntel returns provider-asserted intelligence (CVEs and tags) folded onto an
	// IP, zero value when none was reported. It is inferred: a rule may chain it, but
	// it never outranks a directly observed finding of equal severity.
	HostIntel(ip string) entities.HostIntel
	// HostIntelIPs returns the IPs that carry provider-asserted CVEs, sorted, so a
	// consumer can seed corroboration from intel even when no finding was raised.
	HostIntelIPs() []string
	// FlaggedMalicious reports whether reputation engines flagged the domain malicious.
	// A scenario up-weights when an exposure lands on a reputation-flagged asset.
	FlaggedMalicious(domain string) bool
}
