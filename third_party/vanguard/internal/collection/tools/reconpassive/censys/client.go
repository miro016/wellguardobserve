package censys

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const (
	// defaultMaxHosts is the default cap on hosts returned.
	defaultMaxHosts = 100

	// maxInflight caps concurrent Censys HTTP requests across the whole scan. The
	// Censys Platform enforces a concurrent-request limit (HTTP 429, "too many
	// active requests"); one Client is shared by every per-domain lookup, so this
	// cap keeps the tool under that wall regardless of the orchestrator's global
	// concurrency. Kept small and conservative: completeness over speed.
	maxInflight = 2

	// requestTimeout bounds one Search call, retries included, so a stalled request
	// cannot pin an orchestrator worker for the whole scan. It is larger than the
	// retry budget below so retries can complete before the timeout fires.
	requestTimeout = 30 * time.Second

	// toolName is the tool identifier used by all event types.
	toolName = "censys"

	// retrievalService and retrievalCacheEmbedded are the two values stamped on a
	// result's RetrievalSource and on the retrieval_source event attribute. They
	// mirror the events package's RetrievalSource vocabulary, which this package
	// cannot import; translation copies the value straight onto the domain event.
	retrievalService       = "service"
	retrievalCacheEmbedded = "cache_embedded"
)

// Mode selects where a Client's results come from. It is the single switch for the
// tool: there is no separate enable flag, so a mode cannot disagree with one.
type Mode string

const (
	// ModeDisabled means Censys does not run. No client is constructed, no tool log
	// is opened, and nothing is scheduled.
	ModeDisabled Mode = "disabled"
	// ModeEnabled queries the Censys API. It requires Config.APIKey and consumes the
	// paid-request budget. The embedded fixture is not consulted at all.
	ModeEnabled Mode = "enabled"
	// ModeEmbeddedCacheOnly answers from the compiled-in fixture and never reaches
	// Censys. It is a hard no-network contract: no SDK searcher is built, no API key
	// is required (a key that happens to be set changes nothing), no paid request is
	// consumed, and a lookup miss stays a miss instead of falling through to the API.
	ModeEmbeddedCacheOnly Mode = "embedded_cache_only"
)

// Modes lists the accepted mode values, for configuration validation and error
// messages.
func Modes() []Mode { return []Mode{ModeDisabled, ModeEnabled, ModeEmbeddedCacheOnly} }

// Enabled reports whether the mode runs the tool at all, so the caller constructs a
// client, opens its tool log, and schedules it. It tests for the running modes rather
// than "not disabled", so an unset or unrecognised mode is inert instead of being
// treated as a request to run something the constructor will then reject.
func (m Mode) Enabled() bool { return m == ModeEnabled || m == ModeEmbeddedCacheOnly }

// UsesService reports whether the mode reaches the Censys API. It gates the API-key
// requirement and the paid-request budget: cache-only work spends neither.
func (m Mode) UsesService() bool { return m == ModeEnabled }

// Config holds configuration for the Client.
type Config struct {
	// Mode selects the result source: the Censys API, the embedded fixture, or
	// nothing at all. It is required; there is no default.
	Mode Mode
	// APIKey is the Censys Personal Access Token (bearer token). It is required only
	// in ModeEnabled. The app injects it from the CENSYS_API_KEY environment variable
	// rather than the config file, so the secret stays out of the audit configuration.
	APIKey string
	// OrgID is the Censys organization ID to associate requests with (the SDK's
	// organization_id parameter, see
	// https://docs.censys.com/reference/get-started#step-3-find-and-use-your-organization-id-optional).
	// Optional: when empty, Censys processes the request against the
	// authenticated user's free wallet where applicable, which is what returns
	// a 403 for query types that require organization credits. Like APIKey, the
	// app injects it from the CENSYS_ORG_ID environment variable rather than the
	// config file.
	OrgID string
	// MaxHosts caps the hosts returned per domain. Zero falls back to defaultMaxHosts.
	MaxHosts int
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client searches the Censys GlobalData platform for the hosts associated with a
// domain. Given the registered root it returns the whole estate: Censys matches
// host.dns.names and host.services.cert.names by registered-domain suffix, so one
// query per type covers every subdomain. It runs the two CenQL queries, each tried
// independently, pages each to MaxHosts, deduplicates hosts by canonical IP, and
// merges services. Only the GlobalData.Search endpoint is used, which is available
// on all Censys tiers (a genuine 403 is a wallet/entitlement wall; the client
// reports each 403 and only stops using Censys once every query type has 403'd).
type Client struct {
	cfg      Config
	searcher searcher
	// cache is the embedded result fixture, non-nil only on a cache-only Client.
	// When set, the Client answers from compiled-in data and never builds an SDK
	// searcher, so it makes no request and consumes no paid-request budget.
	cache *cache
}

// New validates cfg and returns a Client for the configured mode: ModeEnabled builds
// the real Censys SDK searcher and requires an API key, ModeEmbeddedCacheOnly decodes
// and validates the compiled-in fixture instead (no key, no searcher, so malformed
// fixture data fails here rather than mid-scan). ModeDisabled is not a client: the
// caller must not construct one, and asking for it is a configuration error rather
// than a silently inert client.
func New(cfg Config) (*Client, error) {
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = defaultMaxHosts
	}
	switch cfg.Mode {
	case ModeEnabled:
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("censys: Config.APIKey is required")
		}
		return &Client{cfg: cfg, searcher: newSDKSearcher(cfg.APIKey, cfg.OrgID)}, nil
	case ModeEmbeddedCacheOnly:
		data, err := loadCache()
		if err != nil {
			return nil, err
		}
		return &Client{cfg: cfg, cache: data}, nil
	case ModeDisabled:
		return nil, fmt.Errorf("censys: Config.Mode %q does not construct a client", cfg.Mode)
	default:
		return nil, fmt.Errorf("censys: Config.Mode %q is invalid (one of: %s)", cfg.Mode, modeList())
	}
}

// modeList renders the accepted modes for an error message.
func modeList() string {
	names := make([]string, 0, len(Modes()))
	for _, m := range Modes() {
		names = append(names, string(m))
	}
	return strings.Join(names, ", ")
}

// searcher abstracts the Censys SDK for testability. It fetches one page of a
// CenQL query and returns the token for the next page ("" on the last page), so
// Client.Search can page an estate-wide query to completion.
type searcher interface {
	searchPage(ctx context.Context, query string, pageSize int64, pageToken string) (hits []rawHit, nextToken string, err error)
	// searchCertPage fetches one page of the certificate_v1 index for a cert.names
	// query, parallel to searchPage, returning the next-page token ("" on the last).
	searchCertPage(ctx context.Context, query string, pageSize int64, pageToken string) (hits []rawCertHit, nextToken string, err error)
}

// rawHit is a simplified host hit extracted from the SDK response.
type rawHit struct {
	IP                 string
	Services           []ServiceInfo
	ASN                *ASNInfo
	Location           *LocationInfo
	OS                 string
	Products           []string
	Vulns              []string
	Reputation         string
	Labels             []string
	NetworkAllocatedAt time.Time
	NetworkCIDRs       []string
}

// rawCertHit is a simplified certificate hit extracted from the SDK response, before
// the in-scope name filter. Names holds every SAN on the certificate.
type rawCertHit struct {
	FingerprintSHA256 string
	Names             []string
	CommonName        string
	IssuerDN          string
	SerialNumber      string
	NotBefore         time.Time
	NotAfter          time.Time
}

// isPaidPlanError reports whether err is a Censys 403, which on the free tier
// signals the GlobalData query requires a paid plan.
func isPaidPlanError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "403") || strings.Contains(msg, "Forbidden")
}

// isInsufficientBalanceError reports whether err is a Censys "insufficient balance"
// response (returned as HTTP 422): the account's query wallet is depleted. Like a 403 it is
// an account-level wall, not a per-query or per-domain failure, so the client treats it as
// provider-unavailable and stops using Censys for the rest of the scan instead of retrying
// the same empty wallet for every query and domain.
func isInsufficientBalanceError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "insufficient balance")
}

// isRateLimitError reports whether err is a Censys 429 (its concurrent-request /
// rate limit). The SDK retries 429 with backoff, so this only matches when the
// retries were exhausted and the 429 still bubbled up as a terminal failure.
func isRateLimitError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "429") ||
		strings.Contains(msg, "Too Many Requests") ||
		strings.Contains(msg, "too many active requests")
}

// unionStrings merges two string slices into a sorted, deduplicated slice, used to
// combine a host's software/CVE lists across the two query types.
func unionStrings(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	set := make(map[string]bool, len(a)+len(b))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		set[v] = true
	}
	return sortedSet(set)
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

// sortedSet returns the keys of a string set as a sorted slice.
func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
