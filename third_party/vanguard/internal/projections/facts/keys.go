package facts

import (
	"net"
	"strconv"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// normalizeFQDN lower-cases, trims, and strips a trailing dot from a DNS name.
func normalizeFQDN(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// isWildcard reports whether a name is a wildcard, which is not materialized as a
// concrete asset.
func isWildcard(s string) bool {
	return s == "*" || strings.HasPrefix(s, "*.")
}

// normalizeIP parses s and returns its canonical string form and IP version (4 or 6).
// ok is false for an unparseable address, so the caller emits an issue rather than a
// bogus IPAddress asset.
func normalizeIP(s string) (canonical string, version int, ok bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", 0, false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), 4, true
	}
	return ip.String(), 6, true
}

// normalizeActiveTransport lower-cases the transport of a service Vanguard observed
// itself. An empty value reads as tcp: the active scanner reported nothing but TCP
// services before the UDP pass existed, and those older captures left the field empty
// rather than spelling it out, so the contract - not a guess - establishes the
// transport. Provider-reported transports get [normalizeProviderTransport] instead.
func normalizeActiveTransport(s string) string {
	if t := strings.ToLower(strings.TrimSpace(s)); t != "" {
		return t
	}
	return entities.ProtocolTCP
}

// normalizeProviderTransport lower-cases a transport a passive provider reported. A
// provider that named none leaves the transport unknown, and unknown is carried
// through as itself: reading it as tcp would let a service of unclear transport key
// the same asset as a confirmed TCP service and satisfy every TCP-only rule.
//
// ok is false for a non-empty value that is neither tcp nor udp, so the caller
// quarantines it with the offending text rather than inventing a transport for it.
func normalizeProviderTransport(s string) (string, bool) {
	switch t := strings.ToLower(strings.TrimSpace(s)); t {
	case "":
		return entities.ProtocolUnknown, true
	case entities.ProtocolTCP, entities.ProtocolUDP:
		return t, true
	default:
		return "", false
	}
}

// normalizeProtocol lower-cases an application protocol, defaulting an empty value to
// "unknown" (an unknown open port is still a reported service).
func normalizeProtocol(s string) string {
	if p := strings.ToLower(strings.TrimSpace(s)); p != "" {
		return p
	}
	return "unknown"
}

// normalizeProduct returns the canonical Technology asset key for a product name. ok
// is false for an empty or "unknown" product, which must not become an asset.
//
// It delegates to [valueobjects.NormalizeTechnology] so every producer of a Technology
// asset - the active fingerprints, the Censys product list, the provider host facets -
// keys on one identity. A passive provider naming a product differently from an active
// probe must still land on the same node.
func normalizeProduct(s string) (string, bool) {
	key := valueobjects.NormalizeTechnology(s, "").Key
	return key, key != ""
}

// providerKey is the canonical Provider asset key for an ASN number.
func providerKey(asn int) string {
	return "asn:" + strconv.Itoa(asn)
}

// dnsRecordKey is the canonical DnsRecord asset key: owner|type|value. Only the record
// types whose literal value is the modeled subject (NS, TXT) get a node, so the key needs
// no discriminator beyond the value itself.
func dnsRecordKey(owner, recordType, value string) string {
	return owner + "|" + recordType + "|" + value
}

// parseASNString parses an ASN in the "AS15169" or "15169" form Shodan/Netlas report.
// ok is false for a missing or malformed value, so no Provider asset is created.
func parseASNString(s string) (int, bool) {
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// mapEventConfidence maps the events-package confidence string (confirmed/inferred) to a
// facts Confidence. A confirmed or empty value is high; an inferred provider assertion is
// medium.
func mapEventConfidence(s string) Confidence {
	if strings.EqualFold(strings.TrimSpace(s), "inferred") {
		return ConfidenceMedium
	}
	return ConfidenceHigh
}

// assetTypeFor classifies a DNS name relative to the scan root. With a known root, the
// exact root is a Domain, any name under it is a Subdomain, and any other name is an
// ExternalDomain: it is outside the target's scope (a CNAME target on a provider,
// another tenant's name on a shared certificate), kept in the graph but never counted as
// in-scope attack surface. Without root context (for example in a unit test with no
// ScanStarted) scope cannot be judged, so the name falls back to a shape heuristic: at
// most one dot is a Domain, anything deeper a Subdomain.
func assetTypeFor(name, root string) AssetType {
	switch {
	case root == "":
		if strings.Count(name, ".") <= 1 {
			return AssetDomain
		}
		return AssetSubdomain
	case name == root:
		return AssetDomain
	case strings.HasSuffix(name, "."+root):
		return AssetSubdomain
	default:
		return AssetExternalDomain
	}
}
