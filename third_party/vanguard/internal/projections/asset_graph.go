package projections

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// assetGraph is the concrete assetgraph.Graph over a folded Projection: the
// inventory supplies the edges and a per-asset finding index the findings. It is
// built once per BuildThreats call and handed to the pure threat rule package, so
// that package walks the asset model through a narrow read-only view instead of
// receiving it pre-flattened.
type assetGraph struct {
	inv        *Inventory
	findingIdx map[entities.AssetRef]map[string]*entities.Finding
}

// assetGraph must satisfy the read-only graph the rule packages consume.
var _ assetgraph.Graph = (*assetGraph)(nil)

// AssetGraph returns the read-only asset graph over the folded read models. It is
// the exported entry point used to resolve a certificate (or other indirect) target
// through inventory relationships to an authorized contact host, mirroring how the
// rule packages receive the same view internally.
func (p *Projection) AssetGraph() assetgraph.Graph { return p.assetGraph() }

// assetGraph builds the read-only graph view over the folded read models. It
// returns the assetgraph.Graph interface (not the concrete type) so the rule
// packages receive the narrow view and never the projection's internals. The
// finding index is materialised once here, keyed by the finding's own asset ref, so
// the rules get O(1) "findings on this asset" without re-scanning Findings.All.
func (p *Projection) assetGraph() assetgraph.Graph {
	idx := make(map[entities.AssetRef]map[string]*entities.Finding)
	for _, f := range p.Findings.All {
		m := idx[f.Asset]
		if m == nil {
			m = make(map[string]*entities.Finding)
			idx[f.Asset] = m
		}
		m[f.Rule] = f
	}
	return &assetGraph{
		inv:        &p.Inventory,
		findingIdx: idx,
	}
}

func (g *assetGraph) DomainIPs(domain string) []string {
	if n, ok := g.inv.Domains[domain]; ok {
		return append([]string(nil), n.IPs...)
	}
	return nil
}

func (g *assetGraph) DomainCerts(domain string) []string {
	if n, ok := g.inv.Domains[domain]; ok {
		return append([]string(nil), n.CertSerials...)
	}
	return nil
}

func (g *assetGraph) IPDomains(ip string) []string {
	if n, ok := g.inv.IPs[ip]; ok {
		return append([]string(nil), n.Domains...)
	}
	return nil
}

func (g *assetGraph) IPServices(ip string) []entities.AssetRef {
	n, ok := g.inv.IPs[ip]
	if !ok {
		return nil
	}
	out := make([]entities.AssetRef, 0, len(n.Services))
	for _, key := range n.Services {
		out = append(out, entities.AssetRef{Kind: "service", ID: key})
	}
	return out
}

func (g *assetGraph) IPNetblock(ip string) string {
	if n, ok := g.inv.IPs[ip]; ok {
		return n.Netblock
	}
	return ""
}

func (g *assetGraph) CertNames(certID string) ([]string, bool) {
	// A certificate finding references the canonical certificate asset key
	// ("cert:<serial>|<common-name>"), while the inventory indexes certificates by
	// canonical serial alone. Extract the serial from the key rather than treating the
	// whole key, or a common-name-only key, as a serial.
	serial, ok := entities.CertSerialFromID(certID)
	if !ok {
		return nil, false
	}
	n, ok := g.inv.Certificates[serial]
	if !ok {
		return nil, false
	}
	return append([]string(nil), n.Domains...), true
}

func (g *assetGraph) FindingAssets(kind string) []entities.AssetRef {
	var out []entities.AssetRef
	for asset := range g.findingIdx {
		if asset.Kind == kind {
			out = append(out, asset)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (g *assetGraph) Findings(asset entities.AssetRef) map[string]*entities.Finding {
	return g.findingIdx[asset]
}

// HasAuthSurface reports whether the domain presents a login/admin surface by any of
// its faces: observed on the domain node itself, or on any IP the name resolves to
// (an endpoint probed on a bare IP folds its surface onto the IP node). A nil node is
// nil-safe. This resolution is what lets an IP-hosted IIS admin surface reach the
// credential paths that key on the domain.
func (g *assetGraph) HasAuthSurface(domain string) bool {
	dNode := g.inv.Domains[domain]
	if dNode.HasAuthSurface() {
		return true
	}
	if dNode == nil {
		return false
	}
	for _, ip := range dNode.IPs {
		if g.inv.IPs[ip].HasAuthSurface() {
			return true
		}
	}
	return false
}

// LiveDomain reports whether the name is serving live TLS by any of its faces: its
// own reachable TlsPosture, or an IP it resolves to that served a completed https
// response (a bare-IP endpoint). The IP resolution is what lets a certificate served
// on an address, not just on a name with its own TLS posture, count as live.
func (g *assetGraph) LiveDomain(domain string) bool {
	dNode, ok := g.inv.Domains[domain]
	if ok && dNode.TlsPosture != nil && dNode.TlsPosture.Reachable {
		return true
	}
	if !ok {
		return false
	}
	for _, ip := range dNode.IPs {
		if g.inv.IPs[ip].ServesLiveTLS() {
			return true
		}
	}
	return false
}

func (g *assetGraph) NetblockCount() int { return len(g.inv.Netblocks) }

// HostIntel returns a copy of the IP's folded host-intel facet, zero value when the
// address is unknown or carries no intel.
func (g *assetGraph) HostIntel(ip string) entities.HostIntel {
	if n, ok := g.inv.IPs[ip]; ok && n.HostIntel != nil {
		return *n.HostIntel
	}
	return entities.HostIntel{}
}

// HostIntelIPs returns the addresses carrying provider-asserted CVEs, sorted, so
// consumers iterate them deterministically.
func (g *assetGraph) HostIntelIPs() []string {
	var out []string
	for ip, n := range g.inv.IPs {
		if n.HostIntel != nil && len(n.HostIntel.CVEs) > 0 {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// FlaggedMalicious reports whether any reputation engine flagged the domain malicious.
func (g *assetGraph) FlaggedMalicious(domain string) bool {
	n, ok := g.inv.Domains[domain]
	return ok && n.Reputation != nil && n.Reputation.Malicious > 0
}
