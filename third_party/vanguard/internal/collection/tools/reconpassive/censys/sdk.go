package censys

import (
	"context"
	"fmt"
	"strings"
	"time"

	censyssdkgo "github.com/censys/censys-sdk-go"
	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	"github.com/censys/censys-sdk-go/retry"
)

// sdkSearcher implements searcher using the real Censys SDK. The SDK client is
// built once and reused (it is safe for concurrent use); inflight caps the number
// of concurrent Censys HTTP requests so the tool stays under the Platform's
// concurrent-request limit.
type sdkSearcher struct {
	client   *censyssdkgo.SDK
	inflight chan struct{}
}

// newSDKSearcher builds the shared SDK client with retry, timeout, and security
// configured up front. The client retries transient 429/5xx responses with
// bounded backoff, so a concurrency spike recovers instead of dropping a domain.
func newSDKSearcher(apiKey, orgID string) *sdkSearcher {
	opts := []censyssdkgo.SDKOption{
		censyssdkgo.WithSecurity(apiKey),
		censyssdkgo.WithTimeout(requestTimeout),
		censyssdkgo.WithRetryConfig(retryConfig()),
	}
	if orgID != "" {
		opts = append(opts, censyssdkgo.WithOrganizationID(orgID))
	}
	return &sdkSearcher{
		client:   censyssdkgo.New(opts...),
		inflight: make(chan struct{}, maxInflight),
	}
}

// retryConfig retries the transient failures the Search endpoint marks retryable
// (429 and 5xx) with bounded exponential backoff. The budget is capped
// (MaxElapsedTime) so a hard wall fails the call within seconds rather than
// stalling the scan - completeness-first, but not retrying forever. Intervals are
// milliseconds.
func retryConfig() retry.Config {
	return retry.Config{
		Strategy: "backoff",
		Backoff: &retry.BackoffStrategy{
			InitialInterval: 500,
			MaxInterval:     5000,
			Exponent:        1.5,
			MaxElapsedTime:  20000,
		},
		RetryConnectionErrors: true,
	}
}

func (s *sdkSearcher) searchPage(ctx context.Context, query string, pageSize int64, pageToken string) ([]rawHit, string, error) {
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}

	body := components.SearchQueryInputBody{
		Query:    query,
		PageSize: censyssdkgo.Pointer(pageSize),
	}
	if pageToken != "" {
		body.PageToken = censyssdkgo.Pointer(pageToken)
	}
	res, err := s.client.GlobalData.Search(ctx, operations.V3GlobaldataSearchQueryRequest{SearchQueryInputBody: body})
	if err != nil {
		return nil, "", fmt.Errorf("censys search: %w", err)
	}
	env := res.ResponseEnvelopeSearchQueryResponse
	if env == nil || env.Result == nil {
		return nil, "", nil
	}
	return extractHits(env.Result.Hits), env.Result.NextPageToken, nil
}

func (s *sdkSearcher) searchCertPage(ctx context.Context, query string, pageSize int64, pageToken string) ([]rawCertHit, string, error) {
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}

	body := components.SearchQueryInputBody{
		Query:    query,
		PageSize: censyssdkgo.Pointer(pageSize),
	}
	if pageToken != "" {
		body.PageToken = censyssdkgo.Pointer(pageToken)
	}
	res, err := s.client.GlobalData.Search(ctx, operations.V3GlobaldataSearchQueryRequest{SearchQueryInputBody: body})
	if err != nil {
		return nil, "", fmt.Errorf("censys search: %w", err)
	}
	env := res.ResponseEnvelopeSearchQueryResponse
	if env == nil || env.Result == nil {
		return nil, "", nil
	}
	return extractCertHits(env.Result.Hits), env.Result.NextPageToken, nil
}

// extractHits converts SDK hits to a rawHit slice, skipping hits without a host IP.
func extractHits(hits []components.SearchQueryHit) []rawHit {
	var out []rawHit
	for _, h := range hits {
		if h.HostV1 == nil {
			continue
		}
		host := h.HostV1.Resource
		if host.IP == nil || *host.IP == "" {
			continue
		}

		services, products, vulns := extractServices(host.Services)
		rh := rawHit{
			IP:         *host.IP,
			Services:   services,
			Products:   products,
			Vulns:      vulns,
			Reputation: extractReputation(host.Reputation),
			Labels:     extractLabels(host.Labels),
			ASN:        extractASN(host.AutonomousSystem),
			Location:   extractLocation(host.Location),
		}
		if host.OperatingSystem != nil && host.OperatingSystem.Product != nil {
			rh.OS = *host.OperatingSystem.Product
		}
		// whois.network carries the routed network's allocation date and CIDRs: a genuine
		// real-world time that dates the host's provider at allocation, not at scan time.
		if w := host.Whois; w != nil && w.Network != nil {
			rh.NetworkAllocatedAt = parseCertTime(w.Network.Created)
			rh.NetworkCIDRs = append([]string(nil), w.Network.Cidrs...)
		}
		out = append(out, rh)
	}
	return out
}

// extractCertHits converts SDK hits to rawCertHit, skipping any hit without a
// certificate_v1 asset. Parsed-metadata fields absent on a hit are left zero rather
// than failing the extraction.
func extractCertHits(hits []components.SearchQueryHit) []rawCertHit {
	var out []rawCertHit
	for i := range hits {
		if hits[i].CertificateV1 == nil {
			continue
		}
		cert := hits[i].CertificateV1.Resource
		rc := rawCertHit{Names: cert.Names}
		if cert.FingerprintSha256 != nil {
			rc.FingerprintSHA256 = *cert.FingerprintSha256
		}
		if p := cert.Parsed; p != nil {
			if p.IssuerDn != nil {
				rc.IssuerDN = *p.IssuerDn
			}
			if p.SerialNumber != nil {
				rc.SerialNumber = *p.SerialNumber
			}
			if p.Subject != nil && len(p.Subject.CommonName) > 0 {
				rc.CommonName = p.Subject.CommonName[0]
			}
			if vp := p.ValidityPeriod; vp != nil {
				rc.NotBefore = parseCertTime(vp.NotBefore)
				rc.NotAfter = parseCertTime(vp.NotAfter)
			}
		}
		out = append(out, rc)
	}
	return out
}

// parseCertTime parses an RFC-3339 timestamp from an SDK string pointer, returning
// the zero time when the pointer is nil or the value does not parse.
func parseCertTime(s *string) time.Time {
	if s == nil || *s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// extractServices converts SDK services to ServiceInfo and aggregates the host's
// software products and CVE ids across them (from each service's software list and
// its exposures/compromises risk lists), mirroring the shodan/netlas facets so the
// cross-provider merge and the vulnerability rule treat all three uniformly.
func extractServices(svcs []components.Service) (services []ServiceInfo, products, vulns []string) {
	prodSet := map[string]bool{}
	vulnSet := map[string]bool{}
	for i := range svcs {
		svc := &svcs[i]
		si := ServiceInfo{ObservedAt: parseCertTime(svc.ScanTime)}
		if svc.Port != nil {
			si.Port = *svc.Port
		}
		if svc.Protocol != nil {
			si.Protocol = *svc.Protocol
		}
		if svc.TransportProtocol != nil {
			// Censys states the transport per service; anything but an explicit tcp or
			// udp stays unknown rather than being defaulted to tcp.
			si.Transport = normalizeTransport(string(*svc.TransportProtocol))
		}
		services = append(services, si)

		for j := range svc.Software {
			if p := softwareProduct(&svc.Software[j]); p != "" {
				prodSet[p] = true
			}
		}
		for j := range svc.Exposures {
			if id := cveID(&svc.Exposures[j]); id != "" {
				vulnSet[id] = true
			}
		}
		for j := range svc.Compromises {
			if id := cveID(&svc.Compromises[j]); id != "" {
				vulnSet[id] = true
			}
		}
	}
	return services, sortedSet(prodSet), sortedSet(vulnSet)
}

// extractReputation returns the host-level reputation score level Censys reports
// ("malicious", "high_risk", ...), empty when Censys reports none. It is already
// present in the search hit, so surfacing it costs no extra call; the reputation
// rule turns a risky verdict into a finding.
func extractReputation(rep *components.Reputation) string {
	if rep == nil || rep.ScoreLevel == nil {
		return ""
	}
	return string(*rep.ScoreLevel)
}

// extractLabels returns the sorted, deduplicated label values Censys assigned to a
// host (for example "login-page", "remote-access"), empty when none. Labels
// describe the exposed surface and ride along in the search hit already.
func extractLabels(labels []components.Label) []string {
	if len(labels) == 0 {
		return nil
	}
	set := map[string]bool{}
	for i := range labels {
		if labels[i].Value != nil && *labels[i].Value != "" {
			set[*labels[i].Value] = true
		}
	}
	return sortedSet(set)
}

// extractASN reads the autonomous-system attribution from a host, nil when absent.
func extractASN(as *components.Routing) *ASNInfo {
	if as == nil {
		return nil
	}
	asn := &ASNInfo{}
	if as.Asn != nil {
		asn.Number = *as.Asn
	}
	if as.Name != nil {
		asn.Name = *as.Name
	}
	if as.Description != nil {
		asn.Description = *as.Description
	}
	return asn
}

// extractLocation reads the geographic location from a host, nil when absent.
func extractLocation(loc *components.Location) *LocationInfo {
	if loc == nil {
		return nil
	}
	li := &LocationInfo{}
	if loc.Country != nil {
		li.Country = *loc.Country
	}
	if loc.City != nil {
		li.City = *loc.City
	}
	return li
}

// softwareProduct returns a display product name for a Censys software attribute,
// preferring the product, then the vendor. Empty when neither is set.
func softwareProduct(a *components.Attribute) string {
	if a == nil {
		return ""
	}
	if a.Product != nil && *a.Product != "" {
		return *a.Product
	}
	if a.Vendor != nil {
		return *a.Vendor
	}
	return ""
}

// cveID returns the uppercased CVE identifier a risk represents, or "" when the
// risk is not a CVE. Censys carries the identifier in the risk's id (occasionally
// its name); only well-formed CVE ids are kept so they can join the KEV catalogue
// and the cross-provider CVE merge, and non-CVE Censys risks are ignored.
func cveID(r *components.Risk) string {
	for _, cand := range []*string{r.ID, r.Name} {
		if cand == nil {
			continue
		}
		s := strings.TrimSpace(*cand)
		if len(s) >= 4 && strings.EqualFold(s[:4], "CVE-") {
			return strings.ToUpper(s)
		}
	}
	return ""
}
