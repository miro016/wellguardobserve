package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// WebAssets aggregates the URLs a web-search (Google dork) pass surfaced for the
// host node it hangs on. Like MailSecurity and BreachExposure it is a facet of a
// Domain rather than a standalone asset, and is an independent passive view of
// what a search engine already exposes. Each hit is attached to the node for the
// host it actually lives on, so a subdomain's exposure is judged against the
// subdomain rather than the apex. The hits are kept here as data; the
// orchestrator's detector turns the sensitive categories (config, backup, open
// directory listings, and so on) into findings.
type WebAssets struct {
	// Assets are the in-scope discovered URLs for this host, in discovery order.
	Assets []valueobjects.WebAsset
	// OutOfScope holds hits whose host is outside the scanned root (third-party
	// sites that appeared in the search results). They are recorded here on the
	// queried root's node, flagged as out of scope rather than silently folded in
	// with the root's own assets, so risk and exposure analysis do not attribute a
	// third party's exposure to the target. Empty on a non-root host node.
	OutOfScope []valueobjects.WebAsset
	// ResolvedAt is when the web-search pass was last run.
	ResolvedAt time.Time
}
