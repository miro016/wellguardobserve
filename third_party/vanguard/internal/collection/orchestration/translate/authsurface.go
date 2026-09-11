package translate

import (
	"fmt"
	"strings"
)

// knownAuthSchemes are the WWW-Authenticate schemes mapped to their own auth type;
// any other advertised scheme still counts as a surface but is recorded generically.
var knownAuthSchemes = map[string]bool{
	"basic": true, "digest": true, "bearer": true, "negotiate": true, "ntlm": true,
}

// detectAuthSurface classifies the authentication surface visible in a probe
// response from data the probe already fetched: a WWW-Authenticate challenge, a
// login form (a password input on the body), or a bare 401/403. It returns the
// auth type and a short evidence string, or empty strings when no surface is seen.
// It makes no request - it only reads the response.
func detectAuthSurface(status int, wwwAuthenticate string, hasLoginForm bool) (authType, evidence string) {
	if scheme := authScheme(wwwAuthenticate); scheme != "" {
		return scheme, "WWW-Authenticate: " + truncate(strings.TrimSpace(wwwAuthenticate), 120)
	}
	if hasLoginForm {
		if status == 401 || status == 403 {
			return "form", fmt.Sprintf("HTTP %d + login form", status)
		}
		return "form", "login form (password input)"
	}
	if status == 401 || status == 403 {
		return "protected", fmt.Sprintf("HTTP %d", status)
	}
	return "", ""
}

// authScheme returns the normalized auth scheme from a WWW-Authenticate value: the
// leading token for a known scheme, "protected" for an unrecognised one (still a
// real challenge), or "" when the header is absent.
func authScheme(wwwAuthenticate string) string {
	fields := strings.Fields(strings.TrimSpace(wwwAuthenticate))
	if len(fields) == 0 {
		return ""
	}
	token := strings.ToLower(fields[0])
	if knownAuthSchemes[token] {
		return token
	}
	return "protected"
}

// truncate caps s to at most n bytes, keeping evidence strings bounded and valid
// UTF-8 (a trailing partial rune is dropped).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
