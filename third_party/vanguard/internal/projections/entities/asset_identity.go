package entities

import (
	"fmt"
	"net"
	neturl "net/url"
	"strings"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// EndpointID returns the canonical asset key of an HTTP(S) endpoint: a stable absolute
// URL that retains its path, query, and fragment evidence. It is the one identity every
// producer of an endpoint reference uses - the facts normalizers that materialize the
// Endpoint asset and the detector rules that raise an AssetKindEndpoint finding - so a
// finding's target always names a node the graph actually holds.
//
// It deliberately keeps an explicit port. A URL that named :443 and one that did not are
// different strings from the tool that reported them, and collapsing them here would
// rewrite what the source said; the host edge is derived from the authority either way,
// so connectivity does not depend on the collapse.
//
// An error is returned rather than a best-effort key, because a malformed URL that became
// an asset id would name an asset nothing can materialize. Callers fail closed: a
// normalizer quarantines the event, a detector raises no finding.
func EndpointID(raw string) (string, error) {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("URL has no host")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("URL scheme %q is not HTTP or HTTPS", u.Scheme)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	switch {
	case u.Port() != "":
		u.Host = net.JoinHostPort(host, u.Port())
	case strings.Contains(host, ":"):
		u.Host = "[" + host + "]"
	default:
		u.Host = host
	}
	return u.String(), nil
}

// EndpointHost returns the normalized host of a canonical endpoint asset key: the name or
// address the URL's authority names, unbracketed. ok is false for a key that is not a
// canonical endpoint id, so a caller joining an endpoint to the topology degrades rather
// than inventing a host.
//
// The host is what the URL itself asserts, nothing more. It is not a claim that the name
// resolves to any particular address; an endpoint keyed by a name never implies a serving
// IP.
func EndpointHost(id string) (string, bool) {
	u, err := neturl.Parse(strings.TrimSpace(id))
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), true
}

// CertificateID returns the canonical Certificate asset key: the canonical serial plus the
// normalized common name, falling back through the common name alone and the issuer when
// those are missing.
//
// It is the source-independent identity of a certificate, so the same leaf seen via CT
// (crt.sh) and via a live TLS handshake lands on one asset. The two producers format the
// issuer differently (a full RDN DN from CT versus a lossy "O CN" string from the live
// probe), so the issuer cannot converge and is not part of the key; the canonical serial
// plus the leaf common name is. A serial is unique per issuer, and the common name removes
// any residual cross-CA collision, so the pair identifies the leaf without the issuer. The
// raw issuer and serial strings are retained as asset attributes by the producer.
func CertificateID(issuer, serial, commonName string) string {
	cn := strings.ToLower(strings.TrimSpace(commonName))
	canon := valueobjects.CanonicalCertSerial(serial)
	switch {
	case canon != "" && cn != "":
		return "cert:" + canon + "|" + cn
	case canon != "":
		return "cert:" + canon
	case cn != "":
		return "cn:" + cn
	default:
		return "cert-issuer:" + strings.ToLower(strings.TrimSpace(issuer))
	}
}

// CertSerialFromID extracts the canonical serial from a certificate asset key produced by
// [CertificateID]. ok is false for a key with no serial component (a common-name-only or
// issuer-only key), so a consumer that indexes certificates by serial skips it instead of
// looking up a common name as if it were a serial.
func CertSerialFromID(id string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(id), "cert:")
	if !ok || rest == "" {
		return "", false
	}
	if serial, _, cut := strings.Cut(rest, "|"); cut {
		return serial, serial != ""
	}
	return rest, true
}
