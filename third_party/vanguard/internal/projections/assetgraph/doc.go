// Package assetgraph defines the read-only view of a scan's folded asset model
// that the threat scenario rules query.
//
// # Why an interface
//
// An attack vector is cross-asset: a downgraded domain lands on the web app the
// domain's IP serves, which discloses the build it runs. That path spans a domain,
// an IP, and a service. The threat rule package used to receive the asset model
// pre-flattened into per-asset finding maps plus a handful of
// hand-lifted facets, which folded the graph away before the rules ran, so a rule
// could not walk domain -> IP -> service -> cert and the most valuable multi-asset
// chains were unwritable.
//
// Graph replaces those flattened maps with a narrow, read-only view over the folded
// inventory. The rules stay pure - they receive an interface they cannot mutate,
// and a small fake satisfies it in each rule package's tests - but they gain edge
// walks instead of bespoke facets. A rule iterates the assets that carry findings,
// reads the findings on any asset, and walks the edges (a domain's IPs, an IP's
// services, a certificate's names) to reason across assets.
//
// # Facets resolve by any face
//
// The few cross-asset facets the graph still exposes resolve through the edges rather
// than being keyed to one asset kind. An auth surface (HasAuthSurface) or live TLS
// (LiveDomain) observed on a bare IP resolves to the names that IP serves, so a signal
// reaches a scenario regardless of which asset face observed it. Provider intel folds
// onto the IP as a HostIntel facet (CVEs and tags a passive source asserts), queryable
// by HostIntel/HostIntelIPs; a reputation verdict folds onto the domain, queryable by
// FlaggedMalicious. These are inferred and never outrank a directly observed finding.
//
// # Purity and determinism
//
// Graph is a deterministic view of the folded event stream: the projection builds
// it once per BuildThreats call and hands it to the rules, which remain pure
// functions of what they are handed. No event payloads move through
// this package; it is a read model only.
//
// # Asset identity
//
// Assets are keyed by [github.com/velgard-sk/vanguard/internal/projections/entities.AssetRef]
// (kind + id), the same key findings already carry, and every kind's id is the canonical
// form documented on the AssetKind constants.
//
// Service identity is the canonical
// [github.com/velgard-sk/vanguard/internal/projections/entities.ServiceID] ("host/port/proto") of an
// observed socket, so a port-scan finding and a provider port report on the same socket
// resolve to one service asset. Read a service id through AssetRef.Host and AssetRef.Port
// rather than parsing it.
//
// A URL-scoped weakness is an endpoint asset, keyed by
// [github.com/velgard-sk/vanguard/internal/projections/entities.EndpointID], not a service: an HTTP
// response does not name the address that served it. A rule that wants the host behind an
// endpoint reads it with EndpointHost, which returns what the URL asserts and nothing
// more; joining that host to an address is the graph's DomainIPs walk, not an assumption.
//
// A certificate asset is keyed by
// [github.com/velgard-sk/vanguard/internal/projections/entities.CertificateID], and CertNames takes
// that key rather than a bare serial.
package assetgraph
