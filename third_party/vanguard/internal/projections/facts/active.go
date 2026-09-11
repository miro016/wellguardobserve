package facts

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// applyService folds a ServiceDiscovered event: an actively confirmed Service asset
// keyed by the canonical ServiceID (so it merges with a passive provider service on the
// same socket and upgrades the exposes_service edge to high/active), plus a
// runs_technology link when nmap fingerprinted a product.
func (g *Graph) applyService(e events.ServiceDiscovered) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid service IP %q", e.IP), RawEventID: m.EventID})
		return
	}
	if e.Port < 1 || e.Port > 65535 {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid service port %d on %s", e.Port, ip), RawEventID: m.EventID})
		return
	}
	g.ensureIP(m, ip, version)
	transport := normalizeActiveTransport(e.Protocol)
	sid := entities.NewServiceID(ip, e.Port, transport).String()
	attrs := map[string]any{"ip": ip, attrPort: e.Port, attrTransport: transport,
		attrExposureSource: exposureActive, attrExposureMode: exposureActive}
	if e.Service != "" {
		attrs["service"] = e.Service
	}
	g.upsertAsset(Asset{Type: AssetService, Key: sid, Attributes: attrs,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	disc := "service:" + sid
	serviceMetadata := map[string]any{"service": e.Service, attrProduct: e.Product, "version": e.Version}
	if len(e.CPEs) > 0 {
		serviceMetadata[attrCPEs] = append([]string(nil), e.CPEs...)
	}
	g.addObsEvidenceWithCurrentness(m, sid, "service_observed", "active_service_evidence", disc,
		fmt.Sprintf("%s confirmed %s/%d open on %s.", m.Source, transport, e.Port, ip), ConfidenceHigh,
		liveVerifiedCurrentness(m.ObservationKind, true), serviceMetadata)
	g.upsertRelationship(Relationship{Type: RelExposesService, From: ip, To: sid,
		EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceHigh, Mode: m.Phase,
		SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
	productCPEs, platformCPEs := splitServiceCPEs(e.CPEs)
	g.unionAssetSet(AssetIPAddress, ip, attrPlatformCPEs, platformCPEs)
	g.addTechnology(m, sid, e.Product, e.Version, nil, productCPEs, ConfidenceHigh)
}

// applyHTTPEndpoint folds an HttpEndpointDiscovered event: the Endpoint asset (keyed by
// the normalized URL) with its status, server, and observed authentication surface, the
// host named in the URL authority, and the serves_endpoint edge that joins the two.
//
// The host edge is what makes an endpoint part of the graph rather than an island. It is
// derived from the URL authority alone, because that is the host the request addressed:
// attaching the endpoint to every address the name has ever resolved to would claim far
// more than one HTTP response proved. runs_technology and redirects_to stay independent
// of it - they may corroborate the endpoint, but the endpoint is connected without them.
func (g *Graph) applyHTTPEndpoint(e events.HttpEndpointDiscovered) {
	m := e.Meta()
	url, err := entities.EndpointID(e.URL)
	if err != nil {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid HTTP endpoint URL %q: %s", e.URL, err), RawEventID: m.EventID})
		return
	}
	host, hostType, hostVersion, ok := httpURLHost(url, g.rootTarget)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("HTTP endpoint URL %q has no materializable host", e.URL), RawEventID: m.EventID})
		return
	}
	attrs := map[string]any{attrURL: url, attrStatusCode: e.StatusCode}
	if e.Server != "" {
		attrs["server"] = e.Server
	}
	if e.Title != "" {
		attrs["title"] = e.Title
	}
	if e.AuthType != "" {
		attrs["auth_type"] = e.AuthType
	}
	g.upsertAsset(Asset{Type: AssetEndpoint, Key: url, Attributes: attrs,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	g.upsertAsset(Asset{Type: hostType, Key: host, Attributes: hostAssetAttributes(host, hostVersion),
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	disc := "endpoint:" + url
	g.addObsEvidenceWithCurrentness(m, url, "http_endpoint_observed", "http_endpoint_evidence", disc,
		fmt.Sprintf("%s reported HTTP %d at %s.", m.Source, e.StatusCode, url), ConfidenceHigh,
		liveVerifiedCurrentness(m.ObservationKind, true), map[string]any{attrStatusCode: e.StatusCode, "server": e.Server,
			"auth_type": e.AuthType, "auth_evidence": e.AuthEvidence})
	g.upsertRelationship(Relationship{Type: RelServesEndpoint, From: host, To: url,
		EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceHigh, Mode: m.Phase,
		SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// applyTechnology folds a TechnologyFingerprinted event: the Technology asset and a
// runs_technology edge from the endpoint it was seen on.
func (g *Graph) applyTechnology(e events.TechnologyFingerprinted) {
	m := e.Meta()
	// The URL goes through the same normalizer applyHTTPEndpoint uses, so a fingerprint
	// and a probe of one URL spelled two ways land on one Endpoint node and the
	// runs_technology edge attaches to the node the serves_endpoint edge connected. A
	// technology with no usable URL still becomes an asset, attached to nothing here.
	url := ""
	if strings.TrimSpace(e.URL) != "" {
		normalized, err := entities.EndpointID(e.URL)
		if err != nil {
			g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
				Message: fmt.Sprintf("invalid technology URL %q: %s", e.URL, err), RawEventID: m.EventID})
		} else {
			url = normalized
			g.upsertAsset(Asset{Type: AssetEndpoint, Key: url,
				Attributes: map[string]any{attrURL: url},
				FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
		}
	}
	g.addTechnology(m, url, e.Technology, e.Version, e.Categories, e.CPEs, ConfidenceHigh)
}

// applyTLSPosture folds a TlsPostureDiscovered event as a posture observation on the
// domain (supported versions and HSTS as metadata). A weak-TLS finding, when detected,
// arrives as a separate FindingRaised event that the finding path folds into a candidate.
func (g *Graph) applyTLSPosture(e events.TlsPostureDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	var supported []string
	for _, v := range e.Versions {
		if v.Supported {
			supported = append(supported, v.Version)
		}
	}
	currentness := liveVerifiedCurrentness(m.ObservationKind, e.Reachable)
	g.addObsEvidenceWithCurrentness(m, domain, "tls_posture_observed", "tls_posture_evidence", "tls_posture:"+domain,
		fmt.Sprintf("%s probed TLS posture of %s (%d version(s) supported, HSTS %t).",
			m.Source, domain, len(supported), e.HSTS.Present), ConfidenceHigh,
		currentness, map[string]any{"reachable": e.Reachable, "supported_versions": supported,
			"hsts": e.HSTS.Present, "remote_addr": e.RemoteAddr,
			"chain_state": string(e.ChainState), "chain_trusted": e.ChainTrusted,
			"chain_error": e.ChainError})
}

// addTechnology upserts a Technology asset (keyed by canonical product identity) with
// its observation and evidence, and links it with runs_technology from fromKey when
// fromKey names an asset. An empty or unknown product is skipped.
//
// The key is the canonical identity from [valueobjects.NormalizeTechnology], not the
// reported name, so the same product lands on one node however each tool spelled it -
// "IIS" from a fingerprint catalogue, "Microsoft-IIS/10.0" from a Server header, and
// "Microsoft IIS httpd" from nmap are one asset, which is the whole point of an asset
// graph. Its versions, categories, and CPEs are sorted sets that union across
// observations: a scalar version attribute would freeze the first version seen
// anywhere in the scan. The per-observation evidence keeps the single version that
// observation reported, so the merged node never hides who said what.
func (g *Graph) addTechnology(m events.EventMeta, fromKey, rawName, version string, categories, cpes []string, conf Confidence) {
	tech := valueobjects.NormalizeTechnology(rawName, version)
	if tech.Key == "" {
		return
	}
	name, version := tech.Key, tech.Version
	g.upsertAsset(Asset{Type: AssetTechnology, Key: name,
		Attributes: map[string]any{attrName: name},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	if version != "" {
		g.unionAssetSet(AssetTechnology, name, attrVersions, []string{version})
	}
	g.unionAssetSet(AssetTechnology, name, attrCategories, categories)
	g.unionAssetSet(AssetTechnology, name, attrCPEs, productCPEs(cpes))
	md := map[string]any{attrName: name, "version": version}
	if len(categories) > 0 {
		md[attrCategories] = categories
	}
	if len(cpes) > 0 {
		md[attrCPEs] = cpes
	}
	disc := "tech:" + fromKey + ":" + name
	g.addObsEvidenceWithCurrentness(m, name, "technology_observed", "technology_evidence", disc,
		fmt.Sprintf("%s identified technology %s.", m.Source, name), conf,
		liveVerifiedCurrentness(m.ObservationKind, true), md)
	if fromKey != "" {
		g.upsertRelationship(Relationship{Type: RelRunsTechnology, From: fromKey, To: name,
			EvidenceID: evID(m.EventID, disc), Confidence: conf, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
	}
}

// splitServiceCPEs separates application identity from host platform claims.
// Invalid evidence stays with product observation metadata but is not promoted
// onto either asset.
func splitServiceCPEs(cpes []string) (product, platform []string) {
	for _, raw := range cpes {
		cpe, ok := valueobjects.ParseCPE(raw)
		if !ok {
			product = append(product, raw)
			continue
		}
		if cpe.Part == "a" {
			product = append(product, raw)
		} else {
			platform = append(platform, cpe.String())
		}
	}
	return product, platform
}

// productCPEs derives product-level identities while preserving pinned CPEs on
// observation metadata. Invalid evidence remains in event stream only.
func productCPEs(cpes []string) []string {
	products := make([]string, 0, len(cpes))
	for _, raw := range cpes {
		cpe, ok := valueobjects.ParseCPE(raw)
		if ok {
			products = append(products, cpe.ProductID().String())
		}
	}
	return unionSorted(nil, products)
}
