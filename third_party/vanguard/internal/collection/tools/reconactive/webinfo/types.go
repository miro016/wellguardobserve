package webinfo

import (
	"net/http"

	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// Result holds the active web reconnaissance data for one domain: the HTTP probe
// outcome and the detected technology stack.
type Result struct {
	Domain string
	HTTP   *HTTPResult
	Stack  *StackResult
	// RedirectTrail is the shared result contract for followed and rejected
	// decisions from every HTTP request this probe made.
	RedirectTrail []scopecheck.RedirectObservation
	// LoginForm is true when the fetched page body contained a password input, a
	// best-effort signal that the page exposes a login form. Derived from the body
	// the probe already fetched for stack detection; no extra request is made.
	LoginForm bool
}

// HTTPResult holds HTTP probe results.
type HTTPResult struct {
	FinalURL   string
	StatusCode int
	StatusText string
	// Redirects records followed and rejected redirect decisions made by the HEAD
	// metadata request.
	Redirects      []scopecheck.RedirectObservation
	Headers        []Header
	ServerSoftware string
	TLSVersion     string
	TLSCipher      string
}

// Header is a single HTTP response header.
type Header struct {
	Name  string
	Value string
}

// StackResult holds the detected technology stack.
type StackResult struct {
	CMS         string
	Plugins     []string
	PoweredBy   string
	Server      string
	CDN         string
	Hosting     string
	JSLibs      []string
	CSSLibs     []string
	ExternalSvc []ExternalService
}

// ExternalService describes a third-party service loaded by the page.
type ExternalService struct {
	Domain string
	Type   string
}

// PageData holds fetched page data used for stack analysis.
type PageData struct {
	Headers http.Header
	Body    []byte
	BaseURL string
	// RedirectTrail records redirect decisions made by this page GET.
	RedirectTrail []scopecheck.RedirectObservation
}
