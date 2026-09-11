package dataquality

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Normalisation is where comparison correctness lives: the same fact arrives from
// different providers in slightly different shapes (trailing dots, case, padded
// registrar punctuation, IPv4-mapped IPv6). Centralising the normalisers here, and
// testing them, keeps "agreement" and "conflict" honest. All normalisers are pure
// and return "" for empty/unusable input so extractors can skip blanks uniformly.

// normalizeDomain lowercases a domain name and drops the root trailing dot, so
// "Example.COM." and "example.com" compare equal.
func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

// normalizeIP canonicalises an IP address (collapsing IPv4-mapped IPv6 and
// zero-padding), falling back to the trimmed input when it does not parse.
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// normalizeRegistrar lowercases, drops "," and "." punctuation, and collapses
// whitespace, so "MarkMonitor, Inc." and "markmonitor inc" compare equal.
func normalizeRegistrar(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(",", " ", ".", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// normalizeEndpointURL canonicalises an endpoint URL so the same page reported by
// two tools compares equal: the scheme and host lower-case, and a bare trailing root
// slash collapses ("https://Example.com/" and "https://example.com" are one
// endpoint). A non-root path is left alone - it may be a distinct resource.
func normalizeEndpointURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.ToLower(s)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Path == "/" && u.RawQuery == "" && u.Fragment == "" {
		u.Path = ""
	}
	return u.String()
}

// technologyComparisonTokens returns product identity plus exact version when one
// exists. Including the bare identity makes "nginx" a subset of "nginx 1.25.3"
// instead of a false conflict, while two different concrete versions still conflict.
//
// Identity comes from [valueobjects.NormalizeTechnology], the same decision the
// inventory merge and the facts asset key use. This comparison used to own a private
// copy of that logic, which is how the analyzer could report clean agreement on the
// very endpoints the operator report showed duplicated: two answers to one question.
func technologyComparisonTokens(name, version string) []string {
	tech := valueobjects.NormalizeTechnology(name, version)
	if tech.Key == "" {
		return nil
	}
	if !tech.HasVersion() {
		return []string{tech.Key}
	}
	return []string{tech.Key, tech.Key + " " + strings.ToLower(tech.Version)}
}

// normalizeService renders a port/protocol pair as the canonical "port/proto"
// token used to compare exposed services across providers. It is for services
// Vanguard observed itself, where an empty protocol means tcp by contract;
// provider-reported transports go through [normalizeProviderService].
func normalizeService(port int, proto string) string {
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%d/%s", port, proto)
}

// normalizeProviderService renders a provider-reported port/transport pair as the
// same token, except that a provider which named no transport yields "port/unknown".
// Folding it into "port/tcp" instead would make a service of unclear transport
// compare equal to a confirmed TCP one, which is a manufactured agreement rather
// than an observed one.
func normalizeProviderService(port int, transport string) string {
	transport = strings.ToLower(strings.TrimSpace(transport))
	if transport == "" {
		transport = "unknown"
	}
	return fmt.Sprintf("%d/%s", port, transport)
}
