package webinfo

import "regexp"

// passwordInputRe matches an HTML password input, tolerating quote style and
// spacing: type=password, type="password", type='password'. It is a best-effort
// login-form signal, not an HTML parser.
var passwordInputRe = regexp.MustCompile(`(?i)type\s*=\s*["']?password`)

// HasPasswordInput reports whether body contains an HTML password input field, a
// best-effort signal that the page exposes a login form. It scans bytes the caller
// already fetched and makes no request, so it adds no traffic.
func HasPasswordInput(body []byte) bool {
	return passwordInputRe.Match(body)
}
