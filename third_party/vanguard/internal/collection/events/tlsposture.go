package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = TlsPostureDiscovered{}

// TlsPostureDiscovered signals that an active HTTPS probe enumerated a domain's
// TLS protocol support and HSTS policy. Like MailSecurity and BreachExposure it
// is a facet of the owning Domain rather than a standalone asset: it captures how
// the name negotiates TLS (which versions it still accepts, and whether HSTS is
// enforced), distinct from the certificate itself (carried by the reused
// CertificateDiscovered event). The active leaf certificate is translated
// separately so it feeds the existing certificate detectors and asset graph.
type TlsPostureDiscovered struct {
	EventMeta
	Domain     string
	RemoteAddr string
	// Reachable is true when the HTTPS endpoint actually answered (a TLS handshake
	// or the HTTPS GET completed). When false the probe never connected (port
	// closed, host unreachable, DNS miss) and the all-unsupported Versions and
	// absent HSTS must be read as "not probed", not as a clean posture. The
	// orchestrator still emits the event so the coverage gap is recorded rather
	// than silently dropped.
	Reachable bool
	Versions  []valueobjects.TlsVersion
	HSTS      valueobjects.HstsPolicy
	// ChainState says whether the certificate chain the endpoint served was
	// validated. ChainTrusted and ChainError are meaningful only when it is tested:
	// with any other state a false ChainTrusted means the probe never judged the
	// chain, which must never read as an untrusted one.
	ChainState AssessmentState
	// ChainTrusted reports whether a path from the served chain to a trusted root
	// was built and accepted for this name, and ChainError is the concrete failure
	// when it was not.
	ChainTrusted bool
	ChainError   string
}

// At returns the capture time recorded in the event envelope.
func (e TlsPostureDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e TlsPostureDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e TlsPostureDiscovered) String() string {
	if !e.Reachable {
		return fmt.Sprintf("TLS posture for %s not probed (endpoint unreachable)", e.Domain)
	}
	supported := 0
	for _, v := range e.Versions {
		if v.Supported {
			supported++
		}
	}
	return fmt.Sprintf("discovered TLS posture for %s (%d version(s) supported, HSTS: %t)", e.Domain, supported, e.HSTS.Present)
}

func (TlsPostureDiscovered) isDomainEvent() {}
