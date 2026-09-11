package scandiff

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Comparison correctness lives in normalization: the same fact arrives in slightly
// different shapes between two runs (trailing dots, case, IPv4-mapped IPv6, padded
// registrar text, URL default ports). Centralizing the normalizers here, and
// testing them, keeps identity and payload equality honest across scans. All
// normalizers are pure and return "" for empty/unusable input so extractors can
// skip blanks uniformly.
//
// These mirror internal/projections/dataquality/normalize.go. They are duplicated rather than
// shared per the repo's "duplicate until three instances" rule; extract a shared
// package only when a third consumer appears.

// normalizeDomain lowercases a domain name and drops the root trailing dot, so
// "Example.COM." and "example.com" compare equal.
func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	return s
}

// normalizeIP canonicalizes an IP address (collapsing IPv4-mapped IPv6 and
// zero-padding), falling back to the trimmed input when it does not parse.
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// normalizeService renders a port/protocol pair as the canonical "port/proto"
// token used to compare exposed services across scans. It is for services Vanguard
// observed itself, where an empty protocol means tcp by contract; provider-reported
// transports go through [normalizeProviderService].
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

// defaultPorts maps a scheme to the port it implies, so a URL that spells out the
// default port compares equal to one that omits it.
var defaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
	"ftp":   "21",
	"ws":    "80",
	"wss":   "443",
}

// normalizeURL lowercases the scheme and host, drops the default port for the
// scheme, and drops a trailing slash on an empty path, so "https://Host:443/" and
// "https://host" compare equal. Input that does not parse falls back to the
// lowercased, trimmed string.
func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(s)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != defaultPorts[u.Scheme] {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String()
}

// normalizeText lowercases and collapses internal whitespace, for free-text fields
// where spacing and case carry no meaning (titles, banners, registrar names).
func normalizeText(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// Service evidence carries request-time markers that are meaningful in raw logs
// but not when deciding whether the observed service changed.
var (
	httpDateHeaderPattern = regexp.MustCompile(`(?im)^date:[^\r\n]*(?:\r?\n|$)`)
	nmapDateTokenPattern  = regexp.MustCompile(`(?i)%d=[^%\s]*`)
	nmapTimeTokenPattern  = regexp.MustCompile(`(?i)%time=[^%\s]*`)
)

// normalizeServiceBanner removes known request-time evidence before applying the
// ordinary text normalization. The raw event remains untouched; this view exists
// only so HTTP response dates and nmap fingerprint timestamps do not become
// semantic scan changes.
func normalizeServiceBanner(s string) string {
	s = httpDateHeaderPattern.ReplaceAllString(s, "")
	s = nmapDateTokenPattern.ReplaceAllString(s, "")
	s = nmapTimeTokenPattern.ReplaceAllString(s, "")
	return normalizeText(s)
}

// normalizeInt renders an integer as a stable decimal token for set-valued fields.
func normalizeInt(n int) string { return strconv.Itoa(n) }

// normalizeBool renders a boolean as a stable token.
func normalizeBool(b bool) string { return strconv.FormatBool(b) }
