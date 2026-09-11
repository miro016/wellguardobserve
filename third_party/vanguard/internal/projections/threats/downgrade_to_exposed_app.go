package threats

import (
	"fmt"
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// DowngradeToExposedApp fires when a domain with weak transport security serves, or
// resolves to infrastructure that serves, a build-disclosing web application. It is the
// cross-asset counterpart to TransportDowngrade (which stays domain-local): it joins the
// interception weakness on the name with the exploitable application reachable through it.
//
// The join is on what the endpoint URL itself names, never on an invented serving address.
// An endpoint keyed by the domain is the name's own web face; an endpoint keyed by one of
// the addresses the name resolves to is reached through that resolution. An HTTP response
// does not prove which address served a hostname URL, so no such claim is made: an address
// enters the trail only when the endpoint URL is itself addressed by it.
//
// This is the path the model previously could not draw. A domain-level transport downgrade
// and the exposed app rendered as unrelated items because the two scenarios shared no
// reachable key, so the eight-item vissim.no case fragmented instead of collapsing into
// the single path it is: intercept the downgraded channel, arrive at the exposed
// application, map its disclosed build to known exploits.
func DowngradeToExposedApp(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	// One pass over the build-disclosing endpoints, indexed by the host their URL names,
	// so each downgraded domain resolves its reachable applications without rescanning.
	exposedByHost := map[string][]exposedEndpoint{}
	for _, asset := range g.FindingAssets(entities.AssetKindEndpoint) {
		ver := g.Findings(asset)["version-disclosure"]
		if ver == nil {
			continue
		}
		host, ok := entities.EndpointHost(asset.ID)
		if !ok {
			continue
		}
		exposedByHost[host] = append(exposedByHost[host], exposedEndpoint{asset: asset, finding: ver})
	}

	for _, dAsset := range g.FindingAssets(entities.AssetKindDomain) {
		weak := g.Findings(dAsset)["weak-tls-version"]
		if weak == nil {
			continue
		}
		domain := dAsset.ID

		// The name's own web face, plus the applications on the addresses it resolves to.
		var exposed []exposedEndpoint
		seen := map[string]bool{}
		ipSet := map[string]bool{}
		for _, e := range exposedByHost[domain] {
			if seen[e.asset.ID] {
				continue
			}
			seen[e.asset.ID] = true
			exposed = append(exposed, e)
		}
		for _, ip := range g.DomainIPs(domain) {
			for _, e := range exposedByHost[ip] {
				if seen[e.asset.ID] {
					continue
				}
				seen[e.asset.ID] = true
				ipSet[ip] = true
				exposed = append(exposed, e)
			}
		}
		if len(exposed) == 0 {
			continue
		}
		sortExposed(exposed)

		// Assemble the multi-asset trail: the domain, the addresses that reach an
		// exposed endpoint, then the endpoints themselves.
		assets := []entities.AssetRef{assetRef(entities.AssetKindDomain, domain)}
		for _, ip := range sortedKeys(ipSet) {
			assets = append(assets, assetRef(entities.AssetKindIP, ip))
		}
		ev := []string{evidence(weak)}
		contributing := []*entities.Finding{weak}
		for _, e := range exposed {
			assets = append(assets, e.asset)
			ev = append(ev, evidence(e.finding))
			contributing = append(contributing, e.finding)
		}

		out = append(out, ThreatScenario{
			Name:       "Transport downgrade onto exposed app",
			Severity:   int(events.SeverityHigh),
			Narrative:  fmt.Sprintf("%s exposes weak transport security and reaches a build-disclosing application (%s); a network attacker can downgrade the channel to intercept it, then land on the exposed app and map its disclosed build to known exploits.", domain, exposed[0].asset.ID),
			Summary:    "A domain with weak transport security reaches a build-disclosing application; a network attacker can downgrade the channel to intercept it, then land on the exposed app and map its disclosed build to known exploits.",
			Assets:     assets,
			Evidence:   ev,
			References: []string{attckAiTM, "MITRE ATT&CK T1190", "CWE-319", cweInfoExposure},
		}.withChain(contributing...))
	}
	return out
}

// exposedEndpoint pairs a build-disclosing endpoint asset with the version-disclosure
// finding that made it one, so the scenario keeps the two in step while sorting.
type exposedEndpoint struct {
	asset   entities.AssetRef
	finding *entities.Finding
}

// sortExposed orders the exposed endpoints by asset id, keeping the scenario's assets and
// evidence stable across replays.
func sortExposed(e []exposedEndpoint) {
	sort.Slice(e, func(i, j int) bool { return e[i].asset.ID < e[j].asset.ID })
}

// sortedKeys returns the keys of a set in ascending order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
