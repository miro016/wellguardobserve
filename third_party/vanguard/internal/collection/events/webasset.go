package events

import (
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

var _ DomainEvent = WebAssetsDiscovered{}

// WebAssetsDiscovered signals that a web-search (Google dork) pass surfaced a set
// of URLs for a domain. Like MailSecurity and BreachExposure it is a facet of the
// owning Domain rather than a standalone asset: it is an independent passive view
// of what a search engine already exposes about the domain, kept for coverage and
// exposure analysis. The result hosts are separately emitted as
// DnsDomainNameDiscovered so newly seen names enter the asset graph; this event
// carries the dork hits themselves. An empty Assets slice is not emitted; the
// orchestrator only translates a non-empty result.
type WebAssetsDiscovered struct {
	EventMeta
	Domain string
	Assets []valueobjects.WebAsset
}

// At returns the capture time recorded in the event envelope.
func (e WebAssetsDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e WebAssetsDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e WebAssetsDiscovered) String() string {
	return fmt.Sprintf("discovered %d web asset(s) for %s via search", len(e.Assets), e.Domain)
}

func (WebAssetsDiscovered) isDomainEvent() {}
