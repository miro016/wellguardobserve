package websearch

import (
	"net"
	"net/url"
	"strings"
)

// Rejection reasons form the closed vocabulary used by the per-query
// diagnostics. They describe why an upstream SERP row could not become a target
// asset; none of them means the search itself failed.
const (
	// reasonInvalidRoot marks a query whose root domain is not a normalized DNS
	// name, so ownership cannot be decided at all.
	reasonInvalidRoot = "invalid_root"
	// reasonInvalidURL marks a row whose link does not parse as an absolute
	// http(s) URL.
	reasonInvalidURL = "invalid_url"
	// reasonEmptyHost marks a row whose URL carries no host component.
	reasonEmptyHost = "empty_host"
	// reasonIPLiteral marks a row addressed by IP literal: a search result cannot
	// prove the target owns that address, so it is never an asset.
	reasonIPLiteral = "ip_literal"
	// reasonUnrelatedHost marks a row on a host that is neither the root nor one
	// of its subdomains. This is the signature of a search engine that ignored or
	// reinterpreted the site: operator.
	reasonUnrelatedHost = "unrelated_host"
	// reasonResultCap marks an otherwise accepted row dropped because the query
	// already returned MaxResultsPerQuery assets.
	reasonResultCap = "result_cap"
)

// normalizeDNSName lowercases name and removes one trailing dot, so
// "API.Example.COM." and "api.example.com" compare equal.
func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// normalizeRoot returns the comparable form of root, or "" when root is not a
// usable registrable DNS name (empty, single label, an IP literal, or carrying
// URL punctuation).
func normalizeRoot(root string) string {
	r := normalizeDNSName(root)
	if r == "" || !strings.Contains(r, ".") {
		return ""
	}
	if strings.ContainsAny(r, "/:@ \t") {
		return ""
	}
	if net.ParseIP(r) != nil {
		return ""
	}
	return r
}

// classifyResult decides whether a SERP row may become a target asset. It
// returns the normalized host (empty when it could not be determined) and an
// empty reason when the row is accepted, otherwise one of the rejection reasons
// above.
//
// Ownership is exact-root equality or a label-boundary suffix match, so
// "example.com.attacker.test" is never owned by "example.com". Matching uses
// url.Hostname, never the raw authority, so user-info and port confusion cannot
// smuggle a foreign host past the check.
func classifyResult(rawURL, root string) (host, reason string) {
	nroot := normalizeRoot(root)
	if nroot == "" {
		return "", reasonInvalidRoot
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", reasonInvalidURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", reasonInvalidURL
	}
	host = normalizeDNSName(u.Hostname())
	if host == "" {
		return "", reasonEmptyHost
	}
	if net.ParseIP(host) != nil {
		return host, reasonIPLiteral
	}
	if host == nroot || strings.HasSuffix(host, "."+nroot) {
		return host, ""
	}
	return host, reasonUnrelatedHost
}
