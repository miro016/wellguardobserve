package wappalyzer

import "github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"

// EvidenceSignature is the evidence text attached to every technology this tool
// reports. The upstream API reports that a fingerprint matched, not which rule
// matched or with what confidence, so the text stays generic rather than claiming
// precision the library does not provide.
const EvidenceSignature = "wappalyzer header/cookie/body signature"

// Result is one domain's fingerprint outcome: everything the orchestrator needs to
// build an endpoint event and its technology events, and nothing more. The response
// body is not part of it - it is discarded once fingerprinting is done.
type Result struct {
	// Domain is the requested domain, normalized (trimmed, lower-cased, no trailing dot).
	Domain string
	// FinalURL is the URL that produced the fingerprinted response, after redirects.
	// It is the endpoint identity; the URL the probe started from is in the events.
	FinalURL string
	// Scheme is the scheme that succeeded, "https" or "http". It is "http" only when
	// the HTTPS attempt failed.
	Scheme string
	// StatusCode is the final response status. Any status is a valid fingerprint
	// input, so this is often not 200.
	StatusCode int
	// Title is the <title> text of the final response, empty when absent.
	Title string
	// Server is the Server response header value, empty when absent.
	Server string
	// Headers are the response header names present on the final response, canonical
	// form, sorted. Values are deliberately dropped: the consumer needs to know which
	// headers exist, and header values are the part that can carry secrets.
	Headers []string
	// WWWAuthenticate is the WWW-Authenticate challenge value, empty when absent. It
	// is a server-advertised authentication scheme, not user data, and the consumer
	// classifies the endpoint's authentication surface from it.
	WWWAuthenticate string
	// LoginForm reports whether the response body contained an HTML password input, a
	// best-effort login-surface signal read from bytes already fetched.
	LoginForm bool
	// BodyBytes is how many body bytes were read, after the cap. It is a size signal
	// for operators; the bytes themselves are gone.
	BodyBytes int
	// Redirects is how many redirect hops were followed to reach FinalURL.
	Redirects int
	// RedirectTrail is the shared result contract for followed and rejected
	// decisions in request order.
	RedirectTrail []scopecheck.RedirectObservation
	// Technologies are the identified technologies, sorted by name then version, with
	// no duplicate name/version pair.
	Technologies []Technology
}

// Technology is one identified technology on the probed endpoint.
type Technology struct {
	// Name is the technology name as the fingerprint database spells it, for example
	// "nginx" or "WordPress".
	Name string
	// Version is the version the fingerprint extracted, empty when the match carried
	// none. Most matches carry none.
	Version string
	// Categories are the database's classifications, for example "Web servers", sorted
	// and deduped. Empty when the fingerprint has no category.
	Categories []string
	// CPEs are Common Platform Enumeration identifiers, sorted and deduped. Upstream
	// carries at most one per fingerprint, so this is empty or a single entry today;
	// it is a slice because the consuming domain event models it as a set.
	CPEs []string
	// Evidence is always [EvidenceSignature]. It is carried per technology so the
	// consumer does not have to know this tool's constant.
	Evidence string
}
