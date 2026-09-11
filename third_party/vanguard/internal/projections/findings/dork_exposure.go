package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// dorkRule describes the finding raised for a web-search dork category. Benign
// categories (for example a plain site: query) have no entry and raise nothing.
type dorkRule struct {
	rule     string
	title    string
	severity events.Severity
}

// dorkRules maps a websearch dork category to the finding it raises. Categories
// absent from this map are treated as data-only (no finding). The category keys
// match the websearch tool's category constants.
var dorkRules = map[string]dorkRule{
	"config":    {"dork-config-exposure", "Configuration or environment files exposed to search", events.SeverityHigh},
	"backup":    {"dork-backup-exposure", "Backup or database dump files exposed to search", events.SeverityHigh},
	"indexof":   {"dork-open-directory", "Open directory listing exposed to search", events.SeverityHigh},
	"admin":     {"dork-admin-interface", "Admin or management interface exposed to search", events.SeverityMedium},
	"auth":      {"dork-auth-endpoint", "Authentication endpoint exposed to search", events.SeverityMedium},
	"api":       {"dork-api-endpoint", "API endpoint exposed to search", events.SeverityLow},
	"wordpress": {"dork-wordpress-path", "WordPress path exposed to search", events.SeverityLow},
	"preprod":   {"dork-preprod-environment", "Pre-production environment exposed to search", events.SeverityLow},
}

// DorkExposure raises a finding per sensitive dork category found in a web-search
// result, keyed on the concrete host the URLs live on rather than the queried
// root. Two hosts produce two findings; many URLs on one host in one category
// collapse into one (the finding ID is rule + host). The matching URLs are carried
// as structured Locations so downstream consumers can target them directly, and
// the evidence lists them for a human reader. A host outside the scanned root is
// dropped: it is not the target's attack surface, so a dork hit there (often
// search-result chrome or an unrelated third party) is not a finding about the
// customer. Benign categories are ignored.
func DorkExposure(evt events.DomainEvent) []events.FindingRaised {
	w, ok := evt.(events.WebAssetsDiscovered)
	if !ok || len(w.Assets) == 0 {
		return nil
	}

	// Group URLs by (host, category), keeping only categories that map to a finding.
	type hostCat struct{ host, category string }
	urlsBy := make(map[hostCat][]string)
	for _, a := range w.Assets {
		if _, ok := dorkRules[a.Category]; !ok {
			continue
		}
		host := a.Host
		if host == "" {
			// A URL with no parseable host falls back to the queried root so the hit
			// is still surfaced rather than dropped.
			host = w.Domain
		}
		k := hostCat{host: host, category: a.Category}
		urlsBy[k] = append(urlsBy[k], a.URL)
	}
	if len(urlsBy) == 0 {
		return nil
	}

	keys := make([]hostCat, 0, len(urlsBy))
	for k := range urlsBy {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].category < keys[j].category
	})

	findings := make([]events.FindingRaised, 0, len(keys))
	for _, k := range keys {
		// A host outside the scanned root is not the target's attack surface, so a
		// dork hit there says nothing about the customer; drop it rather than raise
		// a finding against an unrelated third party.
		if !hostInScope(k.host, w.Domain) {
			continue
		}
		urls := append([]string(nil), urlsBy[k]...)
		sort.Strings(urls)
		dr := dorkRules[k.category]
		f := events.FindingRaised{
			Rule:            dr.rule,
			Title:           dr.title,
			FindingCategory: string(entities.FindingExposure),
			AssetKind:       assetDomain,
			AssetID:         k.host,
			Evidence:        fmt.Sprintf("%d URL(s) surfaced via Google dork on %s: %s", len(urls), k.host, strings.Join(urls, ", ")),
			Recommendation:  "Review the exposed URLs and remove or access-restrict anything not meant to be public or indexed.",
			References:      []string{"CWE-200"},
			Locations:       urls,
		}
		f.Severity = dr.severity
		findings = append(findings, f)
	}
	return findings
}

// hostInScope reports whether host is the queried root or a subdomain of it. It
// mirrors the orchestrator's in-scope host test; the small duplication keeps the
// findings package free of an orchestration import.
func hostInScope(host, root string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	root = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(root), "."))
	if root == "" {
		return false
	}
	return host == root || strings.HasSuffix(host, "."+root)
}
