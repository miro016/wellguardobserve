package censys

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

// CertResult is one CT-log certificate Censys returned for a domain, reduced to the
// fields the degraded-empty corroboration backfill needs to build a certificate
// record. Metadata fields absent on a given hit are left zero.
type CertResult struct {
	// FingerprintSHA256 is the certificate's SHA-256 fingerprint, its unique CT index
	// identifier, used to deduplicate certificates across sources.
	FingerprintSHA256 string
	// Names are the distinct in-scope SANs on this certificate (normalized and
	// filtered to the queried scope, the same rule the certspotter source applies).
	Names []string
	// CommonName is the subject common name, empty when the certificate carries none.
	CommonName string
	// IssuerDN is the issuer distinguished name.
	IssuerDN string
	// SerialNumber is the issuer-specific certificate serial (decimal string).
	SerialNumber string
	// NotBefore and NotAfter bound the certificate's validity; zero when unparseable.
	NotBefore time.Time
	NotAfter  time.Time
}

// DomainCertificates holds the CT-log certificates Censys has for a domain. It is the
// independent history source the degraded-empty corroboration consults: Present is
// true when Censys returned any certificate hit at all (before the in-scope SAN
// filter), so a host whose certificates are entirely historical still corroborates a
// crt.sh degraded-empty that the current-only certspotter source cannot.
type DomainCertificates struct {
	Domain string
	Certs  []CertResult
	// Names are the distinct in-scope SANs across every returned certificate, sorted.
	Names     []string
	Present   bool
	Truncated bool
	// RetrievalSource states where this result came from: "service" for a Censys API
	// answer, "cache_embedded" for the compiled-in fixture. The corroboration carries
	// it onto the names and certificates it backfills, so a recovered observation
	// records how its deciding data was obtained.
	RetrievalSource string
}

// Certificates queries the Censys certificate_v1 (CT-log) index for domain and
// returns the certificates whose SANs include domain or a subdomain. Unlike Search
// (which reads the live hosts dataset), this reads the certificate index, so it
// returns historical certificates too - the independent CT history that corroborates
// a degraded crt.sh empty even for a host whose certificates are all expired (where
// the current-only certspotter source returns nothing).
//
// Present is true when Censys returned any certificate hit at all, before the
// in-scope SAN filter, so it is the "not certless" signal the corroboration consumes.
// A 403 wall returns toolerr.ErrProviderUnavailable (tripping the orchestrator's
// circuit breaker); a terminal 429 emits CertRateLimited and returns a non-fatal error.
func (c *Client) Certificates(ctx context.Context, domain string) (*DomainCertificates, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("censys: domain is empty")
	}
	c.emit(ctx, CertSearchStarted{Domain: domain})

	if c.cache != nil {
		return c.cachedCertificates(ctx, domain), nil
	}

	const label = "certificate names"
	query := fmt.Sprintf("cert.names: %q", domain)

	hits, capped, err := c.searchAllCerts(ctx, query)
	if err != nil {
		return nil, c.handleCertError(ctx, domain, label, query, err)
	}

	present := len(hits) > 0
	certs, names := buildCerts(hits, domain)

	c.emit(ctx, CertQuerySucceeded{Domain: domain, Label: label, Query: query, Hits: len(hits)})
	c.emit(ctx, CertSearchCompleted{Domain: domain, Certs: len(certs), Truncated: capped, RetrievalSource: retrievalService})

	return &DomainCertificates{
		Domain:          domain,
		Certs:           certs,
		Names:           names,
		Present:         present,
		Truncated:       capped,
		RetrievalSource: retrievalService,
	}, nil
}

// cachedCertificates answers a certificate-history search from the embedded fixture
// in ModeEmbeddedCacheOnly. A miss returns nil - no result at all, which the
// corroboration treats as a source it could not consult. It is deliberately not an
// empty result (that would assert Censys has no certificates for the domain, the
// exact claim the corroboration acts on) and not an error, and it never falls through
// to the API. No certificate history is staged yet, so this currently always misses.
func (c *Client) cachedCertificates(ctx context.Context, domain string) *DomainCertificates {
	result, ok := c.cache.certificatesFor(domain)
	if !ok {
		c.emit(ctx, CertCacheMiss{Domain: domain})
		c.emit(ctx, CertSearchCompleted{Domain: domain, RetrievalSource: retrievalCacheEmbedded})
		return nil
	}
	result.RetrievalSource = retrievalCacheEmbedded
	c.emit(ctx, CertCacheHit{Domain: domain, Certs: len(result.Certs), Names: len(result.Names)})
	c.emit(ctx, CertSearchCompleted{
		Domain:          domain,
		Certs:           len(result.Certs),
		Truncated:       result.Truncated,
		RetrievalSource: retrievalCacheEmbedded,
	})
	return result
}

// handleCertError emits the right event for a failed certificate query and returns
// the error to propagate. A context error propagates untouched (mirroring Search,
// with no spurious failure event); a 403 wall becomes ErrProviderUnavailable so the
// orchestrator trips its breaker; a terminal 429 emits CertRateLimited; anything else is
// a generic CertQueryFailed.
func (c *Client) handleCertError(ctx context.Context, domain, label, query string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case isInsufficientBalanceError(err):
		c.emit(ctx, CertInsufficientBalance{Domain: domain, Label: label})
		c.emit(ctx, CertSearchCompleted{Domain: domain, RetrievalSource: retrievalService})
		return fmt.Errorf("censys: account has insufficient balance: %w", toolerr.ErrProviderUnavailable)
	case isPaidPlanError(err):
		c.emit(ctx, CertPaidPlanRequired{Domain: domain, Label: label})
		c.emit(ctx, CertSearchCompleted{Domain: domain, RetrievalSource: retrievalService})
		return fmt.Errorf("censys: %s requires a paid plan: %w", label, toolerr.ErrProviderUnavailable)
	case isRateLimitError(err):
		c.emit(ctx, CertRateLimited{Domain: domain, Label: label, Query: query, Err: err})
		c.emit(ctx, CertSearchCompleted{Domain: domain, RetrievalSource: retrievalService})
		return fmt.Errorf("censys: certificate query rate limited: %w", err)
	default:
		c.emit(ctx, CertQueryFailed{Domain: domain, Label: label, Query: query, Err: err})
		c.emit(ctx, CertSearchCompleted{Domain: domain, RetrievalSource: retrievalService})
		return err
	}
}

// searchAllCerts pages the certificate query, accumulating hits up to MaxHosts (the
// same cap the host path uses; a handful of certs per name is the norm, so there is
// no separate knob). The bool reports whether the cap cut the results short.
func (c *Client) searchAllCerts(ctx context.Context, query string) ([]rawCertHit, bool, error) {
	limit := c.cfg.MaxHosts
	pageSize := int64(100)
	if limit < 100 {
		pageSize = int64(limit)
	}

	var (
		out   []rawCertHit
		token string
	)
	for {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		hits, next, err := c.searcher.searchCertPage(ctx, query, pageSize, token)
		if err != nil {
			return nil, false, err
		}
		out = append(out, hits...)
		if len(out) >= limit {
			return out[:limit], len(out) > limit || next != "", nil
		}
		if next == "" {
			return out, false, nil
		}
		token = next
	}
}

// buildCerts converts raw certificate hits to sorted CertResults and the distinct
// in-scope SAN union across them. Each cert's Names and the union are filtered to the
// queried scope (a shared cert's out-of-scope SANs are dropped); Present is computed
// by the caller from the raw hit count, so this filter never changes it.
func buildCerts(hits []rawCertHit, domain string) (certs []CertResult, names []string) {
	certs = make([]CertResult, 0, len(hits))
	unionSet := make(map[string]bool)
	for i := range hits {
		h := hits[i]
		names := certNamesInScope(h.Names, domain)
		for _, n := range names {
			unionSet[n] = true
		}
		certs = append(certs, CertResult{
			FingerprintSHA256: h.FingerprintSHA256,
			Names:             names,
			CommonName:        h.CommonName,
			IssuerDN:          h.IssuerDN,
			SerialNumber:      h.SerialNumber,
			NotBefore:         h.NotBefore,
			NotAfter:          h.NotAfter,
		})
	}
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].FingerprintSHA256 < certs[j].FingerprintSHA256
	})
	return certs, sortedSet(unionSet)
}

// certNamesInScope normalizes certificate SAN names (lowercase, strip a wildcard
// prefix and trailing dot) and keeps the distinct ones in scope for domain (the root
// or a subdomain), sorted. It mirrors the certspotter client's SAN filtering so the
// two CT sources apply the same scope rule.
func certNamesInScope(names []string, domain string) []string {
	set := make(map[string]bool)
	for _, name := range names {
		n := strings.ToLower(strings.TrimSpace(name))
		n = strings.TrimPrefix(n, "*.")
		n = strings.TrimSuffix(n, ".")
		if n == "" {
			continue
		}
		if n == domain || strings.HasSuffix(n, "."+domain) {
			set[n] = true
		}
	}
	return sortedSet(set)
}
