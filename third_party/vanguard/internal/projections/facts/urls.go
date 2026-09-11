package facts

import (
	neturl "net/url"
	"strings"
)

// httpURLHost extracts a normalized host from an already-normalized URL together with
// the graph asset type it must be materialized as. An IP literal authority (including
// a bracketed IPv6 one) is an IPAddress; a name is typed against the scan root by
// [assetTypeFor], so a cross-root host stays an ExternalDomain.
func httpURLHost(rawURL, root string) (host string, assetType AssetType, ipVersion int, ok bool) {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", "", 0, false
	}
	host = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, version, valid := normalizeIP(host); valid {
		return ip, AssetIPAddress, version, true
	}
	if host == "" || isWildcard(host) || strings.ContainsAny(host, " \t\r\n/\\") {
		return "", "", 0, false
	}
	return host, assetTypeFor(host, root), 0, true
}

// hostAssetAttributes returns the identity attributes for a URL host: the address form
// for an IP literal, the name form otherwise.
func hostAssetAttributes(host string, ipVersion int) map[string]any {
	if ipVersion > 0 {
		return map[string]any{"ip": host, attrIPVersion: ipVersion}
	}
	return map[string]any{attrFQDN: host}
}
