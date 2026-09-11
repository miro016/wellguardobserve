package findings

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// cweInfoExposure is CWE-200 (Exposure of Sensitive Information): the weakness
// class for software that advertises its exact version to anonymous clients.
const cweInfoExposure = "CWE-200"

// clientSideTechCategories are fingerprint-database categories whose members run
// in the visitor's browser or are published by construction. A WordPress site
// serves its plugin, theme, and bundled script versions in asset URLs that every
// visitor already fetches, so "disclosure" describes nothing the operator could
// suppress, and the volume buries the server-side finding on the same endpoint
// (one 2026-09-02 estate: seven client-side products against one
// "Microsoft ASP.NET 4.0.30319").
//
// Matching is on the category rather than the product name because the category
// arrives on the event from the fingerprint database and keeps working as that
// database grows, where a name blocklist would rot with every new plugin.
var clientSideTechCategories = map[string]struct{}{
	"javascript libraries": {},
	"seo":                  {},
	"wordpress plugins":    {},
	"wordpress themes":     {},
}

// VersionDisclosure raises an info finding when an endpoint advertises the exact
// version of its server software or framework (for example "Microsoft-IIS 10.0"
// in the Server header, or a build in X-Powered-By). An exact version lets an
// attacker map the host straight to the known CVEs for that build, so suppressing
// the banner is a cheap hardening win.
//
// It fires only when a concrete Version was fingerprinted: a bare technology name
// (no version) is a stack hint, not a disclosure, and flagging it would be noise.
// Client-side components (clientSideTechCategories) are skipped for the same
// reason - their versions are public by construction, not a banner an operator
// can generalize.
func VersionDisclosure(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TechnologyFingerprinted)
	if !ok {
		return nil
	}
	if strings.TrimSpace(e.Version) == "" {
		return nil
	}
	if isClientSideTechnology(e.Categories) {
		return nil
	}
	endpointID, ok := endpointAssetID(e.URL)
	if !ok {
		// A URL that cannot be normalized owns no Endpoint asset; raising a finding
		// against it would name a target the graph does not hold.
		return nil
	}
	f := events.FindingRaised{
		Rule:            "version-disclosure",
		Title:           "Software version disclosed",
		FindingCategory: string(entities.FindingExposure),
		AssetKind:       assetEndpoint,
		AssetID:         endpointID,
		Evidence:        fmt.Sprintf("%s advertises %s %s, revealing the exact build to anonymous clients", e.URL, e.Technology, e.Version),
		Recommendation:  "Suppress or generalize version banners (Server, X-Powered-By) so the exact build is not advertised.",
		References:      []string{cweInfoExposure},
		Locations:       []string{e.URL},
		Service:         serviceFacet(e.URL, e.Technology, e.Version, nil),
	}
	f.Severity = events.SeverityInfo
	return []events.FindingRaised{f}
}

// isClientSideTechnology reports whether any category classifies the technology as
// browser-side. Any match suppresses rather than requiring all of them: a product
// carrying one server-side-looking category alongside a browser-side one (Elementor
// is "Page builders" and "WordPress plugins") is still a browser-side product, and a
// tool that reports no categories at all is never suppressed.
func isClientSideTechnology(categories []string) bool {
	for _, c := range categories {
		if _, ok := clientSideTechCategories[strings.ToLower(strings.TrimSpace(c))]; ok {
			return true
		}
	}
	return false
}
