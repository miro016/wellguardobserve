package crawler

import (
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/crtsh"
)

// Config configures a CrawlerActor.
type Config struct {
	// CrtshClient performs certificate transparency lookups. Required.
	CrtshClient *crtsh.Client

	// MaxDepth determines how many levels of subdomains the crawler will follow.
	// A depth of 0 means only the provided root domain is searched.
	MaxDepth int

	// RestrictToRoot ensures the crawler only follows subdomains that belong to
	// the original root domain.
	RestrictToRoot bool

	// EventSink receives the crawler's own system events (CrawlStarted,
	// DomainNameFound, CertificateFound, SearchFailed, …). It must be safe for
	// concurrent use. It is mandatory.
	EventSink EventSink
}
