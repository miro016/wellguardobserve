package wappalyzer

import (
	"net/http"
	"regexp"
	"sort"
	"strings"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
)

// fingerprint runs the embedded database against a response and returns the matches
// in a deterministic order. Upstream hands back an unordered map keyed either "name"
// or "name:version", so all of the ordering and parsing lives here: the same response
// must always produce the same slice, or replay and scan diffs turn into noise.
func fingerprint(engine *wappalyzergo.Wappalyze, headers http.Header, body []byte) []Technology {
	matches := engine.FingerprintWithInfo(headers, body)
	out := make([]Technology, 0, len(matches))
	for key, info := range matches {
		name, version := splitAppVersion(key)
		version = sanitizeVersion(version)
		if name == "" {
			continue
		}
		out = append(out, Technology{
			Name:       name,
			Version:    version,
			Categories: sortedSet(info.Categories),
			CPEs:       sortedSet([]string{info.CPE}),
			Evidence:   EvidenceSignature,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if l, r := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); l != r {
			return l < r
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// sanitizeVersion drops opaque asset hashes captured by upstream rules as versions.
// They may identify a cache-busted CSS/JS file, but they do not identify a software
// release and must not trigger version-disclosure findings.
func sanitizeVersion(version string) string {
	version = strings.TrimSpace(version)
	if opaqueHexVersionRe.MatchString(version) {
		return ""
	}
	return version
}

// splitAppVersion parses an upstream match key. The key is "name" when the matching
// rule extracted no version and "name:version" when it did (upstream's
// FormatAppVersion). It mirrors upstream's own parse - split into exactly two parts -
// so a name that itself contains a colon is treated as a plain name here as well,
// rather than being silently truncated.
func splitAppVersion(key string) (name, version string) {
	key = strings.TrimSpace(key)
	parts := strings.Split(key, ":")
	if len(parts) != 2 {
		return key, ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

// sortedSet trims, drops empties, dedups, and sorts. Every set the tool reports goes
// through it so the consumer never has to normalize, and so two probes of the same
// response compare equal.
func sortedSet(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			set[v] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// headerNames returns the response header names, canonical form, sorted. Values are
// dropped on purpose: the consumer needs to know which headers were present, and the
// values are the part that can carry session tokens or other secrets.
func headerNames(h http.Header) []string {
	if len(h) == 0 {
		return nil
	}
	out := make([]string, 0, len(h))
	for name := range h {
		out = append(out, http.CanonicalHeaderKey(name))
	}
	sort.Strings(out)
	return out
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// opaqueHexVersionRe matches cache-busting asset hashes that upstream fingerprint
// rules sometimes expose through their version capture. A hash identifies one file,
// not a software release, so persisting it as Version creates false version-disclosure
// findings and noisy cross-tool conflicts.
var opaqueHexVersionRe = regexp.MustCompile(`(?i)^[0-9a-f]{7,40}$`)

// extractTitle returns the <title> text of an HTML body, empty when absent. It is a
// best-effort regex read of bytes already fetched, not an HTML parser.
func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// passwordInputRe matches an HTML password input, tolerating quote style and spacing.
var passwordInputRe = regexp.MustCompile(`(?i)type\s*=\s*["']?password`)

// hasPasswordInput reports whether the body contains an HTML password input, a
// best-effort login-surface signal. It reads bytes the probe already fetched, so it
// adds no traffic.
func hasPasswordInput(body []byte) bool {
	return passwordInputRe.Match(body)
}
