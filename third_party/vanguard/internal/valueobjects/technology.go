package valueobjects

import (
	"regexp"
	"strings"
)

// Technology is a normalized reference to one identified software product. Several
// tools fingerprint the same product and each spells it its own way: the WappalyzerGo
// catalogue says "IIS", a raw Server header says "Microsoft-IIS", and nmap's service
// database says "Microsoft IIS httpd". Every consumer that has to decide whether two
// reports are about the same thing - the inventory merge, the facts asset key, the
// data-quality comparison - must decide it identically, or one report becomes several
// assets. [NormalizeTechnology] is that single decision.
type Technology struct {
	// Name is the display name in the reporting tool's own casing, with any version
	// suffix removed. It is what an operator reads; it is never a match key.
	Name string
	// Version is the product version, taken from the reported version field or split
	// out of the reported name. Empty when unknown.
	Version string
	// Key is the canonical identity: lower-cased, whitespace-collapsed, and mapped
	// through the alias table. Two reports of one product share a Key even when their
	// Names differ. Empty when the input names nothing usable.
	Key string
}

// HasVersion reports whether a concrete version is known.
func (t Technology) HasVersion() bool { return t.Version != "" }

// technologyAliases maps a spelling to the canonical Key. It is deliberately small and
// evidence-driven: every entry is a collision seen in a real capture, not a guess at
// what tools might one day emit. A speculative alias is worse than none, because it
// can silently merge two genuinely different products.
var technologyAliases = map[string]string{
	"iis":                         keyMicrosoftIIS,
	"microsoft iis":               keyMicrosoftIIS,
	"microsoft iis httpd":         keyMicrosoftIIS,
	"microsoft asp.net":           "asp.net",
	"application request routing": "arr",
	"apache http server":          "apache",
	"apache httpd":                "apache",
	"jquery_ui":                   "jquery ui",
}

// keyMicrosoftIIS is the canonical key for Microsoft's web server, which four tools
// spell four ways and so needs the most alias entries.
const keyMicrosoftIIS = "microsoft-iis"

// technologyVersionSuffixRe matches a version glued onto the end of a product name,
// as "Microsoft-IIS/10.0", "ARR/3.0", "WordPress 7.0.3", or "Apache/2.4.7 (Ubuntu)".
// Tools that build a display string instead of filling a version field produce these,
// and a name carrying its own version can never match the same product reported
// properly.
//
// The version must contain a dot. A bare trailing number is far more often part of the
// product name ("HTTP/3", "Windows Server 2019", "jQuery UI") than a version, and
// splitting those would invent products that do not exist.
var technologyVersionSuffixRe = regexp.MustCompile(`(?i)^(.*?)[/ ](\d+(?:\.[0-9a-z_-]+)+)(?:\s+\([^)]*\))?$`)

// opaqueHexVersionRe matches a cache-busting asset hash that a fingerprint rule
// captured as a version. It identifies one file, not a software release, so keeping it
// would invent a version-disclosure finding and a cross-tool conflict out of nothing.
var opaqueHexVersionRe = regexp.MustCompile(`(?i)^[0-9a-f]{7,40}$`)

// NormalizeTechnology canonicalizes one reported technology. It trims and collapses
// whitespace, splits a version out of the name when the reporter glued one on, drops an
// opaque asset hash masquerading as a version, and maps the result through the alias
// table.
//
// It never merges a version into the name, and never discards a known version: two
// tools reporting different versions of one product is a real disagreement that must
// stay visible to the comparison that looks for it.
func NormalizeTechnology(name, version string) Technology {
	name = strings.Join(strings.Fields(name), " ")
	version = strings.TrimSpace(version)

	// A reported version wins over one glued to the name; only split when there is
	// nothing better, so "nginx/1.0" reported with Version "1.25" is not downgraded.
	if version == "" {
		if m := technologyVersionSuffixRe.FindStringSubmatch(name); len(m) == 3 {
			if trimmed := strings.TrimSpace(m[1]); trimmed != "" {
				name, version = trimmed, m[2]
			}
		}
	}
	if opaqueHexVersionRe.MatchString(version) {
		version = ""
	}

	key := strings.ToLower(name)
	if alias, ok := technologyAliases[key]; ok {
		key = alias
	}
	if key == "" || key == "unknown" {
		return Technology{}
	}
	return Technology{Name: name, Version: version, Key: key}
}
