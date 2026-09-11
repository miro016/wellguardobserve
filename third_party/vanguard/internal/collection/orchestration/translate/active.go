package translate

import (
	"bytes"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/httpprobe"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/https"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/portscan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/smtp"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/wappalyzer"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/webinfo"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// HTTPRedirects maps an ordered tool redirect trail to domain events. The first
// hop is caused by the event that introduced the starting target; each later hop
// is caused by the preceding redirect event so lineage reconstructs the chain.
func HTTPRedirects(trail []scopecheck.RedirectObservation, scanID, causationID, source, corrID string) []events.DomainEvent {
	if len(trail) == 0 {
		return nil
	}
	at := time.Now()
	out := make([]events.DomainEvent, 0, len(trail))
	for _, hop := range trail {
		disposition := events.HttpRedirectDisposition(hop.Disposition)
		evt := events.HttpRedirectObserved{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     causationID,
				Source:          source,
				Phase:           events.PhaseActive,
				Category:        events.CategoryDiscovery,
				Severity:        events.SeverityInfo,
				ObservationKind: events.ObservationKindActiveProbe,
				CapturedAt:      at,
				ToolCorrID:      corrID,
			},
			FromURL:     hop.FromURL,
			ToURL:       hop.ToURL,
			StatusCode:  hop.Status,
			Hop:         hop.Hop,
			Disposition: disposition,
			Reason:      hop.Reason,
		}
		evt.EventID = events.NewEventID(at, evt)
		out = append(out, evt)
		causationID = evt.EventID
	}
	return out
}

// TLSPosture maps an https probe result to a TlsPostureDiscovered event.
func TLSPosture(domain string, result *https.Result, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil {
		return nil
	}
	versions := make([]valueobjects.TlsVersion, 0, len(result.TLSVersions))
	for _, v := range result.TLSVersions {
		versions = append(versions, valueobjects.TlsVersion{
			Version:   v.Version,
			Supported: v.Supported,
			Cipher:    v.Cipher,
			Risk:      v.Risk,
		})
	}
	hsts := valueobjects.HstsPolicy{}
	if result.HSTS != nil {
		hsts = valueobjects.HstsPolicy{
			Present:           true,
			MaxAge:            result.HSTS.MaxAge,
			IncludeSubDomains: result.HSTS.IncludeSubDomains,
			Preload:           result.HSTS.Preload,
		}
	}
	now := time.Now()
	e := events.TlsPostureDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceHTTPS,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:     domain,
		RemoteAddr: result.RemoteAddr,
		Reachable:  result.Reachable,
		Versions:   versions,
		HSTS:       hsts,
		ChainState: events.AssessmentNotTested,
	}
	// A chain nobody could judge stays not_tested. Without that distinction a probe
	// that never completed a handshake would contribute an untrusted-looking chain
	// for every unreachable name.
	if result.ChainValidation != nil {
		e.ChainState = events.AssessmentTested
		e.ChainTrusted = result.ChainValidation.Trusted
		e.ChainError = result.ChainValidation.Error
	}
	e.EventID = events.NewEventID(now, e)
	return []events.DomainEvent{e}
}

// HTTPSCert maps the live leaf certificate from an https probe to a reused
// CertificateDiscovered event, so it feeds the certificate detectors and asset
// graph. A missing or serial-less certificate yields no event.
func HTTPSCert(domain string, result *https.Result, scanID, causationID string) []events.DomainEvent {
	if result == nil || result.TLS == nil || result.TLS.Serial == "" {
		return nil
	}
	return []events.DomainEvent{certificateEvent(&certInput{
		commonName: result.TLS.Subject,
		issuer:     result.TLS.Issuer,
		serial:     result.TLS.Serial,
		notBefore:  result.TLS.NotBefore,
		notAfter:   result.TLS.NotAfter,
		sans:       result.TLS.SANs,
		searchHint: domain,
		source:     SourceHTTPS,
	}, scanID, causationID)}
}

// MxTls maps an smtp probe result to an MxTlsDiscovered event.
func MxTls(domain string, result *smtp.Result, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil || len(result.MXHosts) == 0 {
		return nil
	}
	hosts := make([]valueobjects.MxTlsHost, 0, len(result.MXHosts))
	for i := range result.MXHosts {
		h := &result.MXHosts[i]
		// A policy-rejected MX host carries no mail posture (it was never dialed); its
		// rejection is already in the tool log as an MXTargetRejected event, so it must
		// not appear here as a mail-posture entry with an error.
		if h.PolicyRejected {
			continue
		}
		hosts = append(hosts, valueobjects.MxTlsHost{
			Host:              h.Host,
			Priority:          int(h.Priority),
			Banner:            h.Banner,
			EHLO:              append([]string(nil), h.EHLOSupport...),
			StartTLSSupported: h.STARTTLSSupported,
			TLSVersion:        h.TLSVersion,
			TLSCipher:         h.TLSCipher,
			CertSubject:       h.CertSubject,
			CertIssuer:        h.CertIssuer,
			Error:             h.Error,
		})
	}
	// Every MX host was policy-rejected: there is no mail posture to report, so emit
	// no discovery event. The rejections stay in the tool log.
	if len(hosts) == 0 {
		return nil
	}
	now := time.Now()
	e := events.MxTlsDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceSMTP,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain: domain,
		Hosts:  hosts,
	}
	e.EventID = events.NewEventID(now, e)
	return []events.DomainEvent{e}
}

// SmtpCerts maps the negotiated MX leaf certificates to reused
// CertificateDiscovered events. causationID is the MxTlsDiscovered event ID.
func SmtpCerts(result *smtp.Result, scanID, causationID string) []events.DomainEvent {
	if result == nil {
		return nil
	}
	out := make([]events.DomainEvent, 0, len(result.MXHosts))
	for i := range result.MXHosts {
		h := &result.MXHosts[i]
		if h.CertSerial == "" {
			continue
		}
		out = append(out, certificateEvent(&certInput{
			commonName: h.CertSubject,
			issuer:     h.CertIssuer,
			serial:     h.CertSerial,
			notBefore:  h.CertNotBefore,
			notAfter:   h.CertNotAfter,
			sans:       h.CertSANs,
			searchHint: h.Host,
			source:     SourceSMTP,
		}, scanID, causationID))
	}
	return out
}

// certInput carries the fields needed to build a CertificateDiscovered event from
// a live (https/smtp) certificate.
type certInput struct {
	commonName string
	issuer     string
	serial     string
	notBefore  time.Time
	notAfter   time.Time
	sans       []string
	searchHint string
	source     string
}

// certificateEvent builds a CertificateDiscovered from a live certificate.
func certificateEvent(in *certInput, scanID, causationID string) events.DomainEvent {
	now := time.Now()
	c := events.CertificateDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          in.source,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
		},
		SearchQuery: in.searchHint,
		Certificate: events.CertificateData{
			CommonName:     in.commonName,
			IssuerName:     in.issuer,
			SerialNumber:   in.serial,
			ValidFrom:      in.notBefore,
			ValidUntil:     in.notAfter,
			LiveVerifiedAt: now,
			Domains:        append([]string(nil), in.sans...),
		},
	}
	c.EventID = events.NewEventID(now, c)
	return c
}

// Webinfo maps a webinfo probe result to a reused HttpEndpointDiscovered event
// plus a TechnologyFingerprinted event per detected stack signal.
func Webinfo(result *webinfo.Result, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil || result.HTTP == nil {
		return nil
	}
	now := time.Now()
	url := normalizeEndpointURL(result.HTTP.FinalURL)
	ep := events.HttpEndpointDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceWebinfo,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		URL:        url,
		StatusCode: result.HTTP.StatusCode,
		Server:     result.HTTP.ServerSoftware,
		Headers:    webinfoSecurityHeaders(result.HTTP.Headers),
	}
	ep.AuthType, ep.AuthEvidence = detectAuthSurface(
		result.HTTP.StatusCode, webinfoHeaderValue(result.HTTP.Headers, "WWW-Authenticate"), result.LoginForm)
	ep.EventID = events.NewEventID(now, ep)
	out := []events.DomainEvent{ep}

	for _, tech := range webinfoTechnologies(result.Stack) {
		t := events.TechnologyFingerprinted{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     ep.EventID,
				Source:          SourceWebinfo,
				Phase:           events.PhaseActive,
				Category:        events.CategoryDiscovery,
				ObservationKind: events.ObservationKindActiveProbe,
				CapturedAt:      now,
				ToolCorrID:      corrID,
			},
			URL:        url,
			Technology: tech.name,
			Version:    tech.version,
			Evidence:   tech.evidence,
		}
		t.EventID = events.NewEventID(now, t)
		out = append(out, t)
	}
	return out
}

// webinfoHeaderValue returns the value of the first header matching name
// (case-insensitive) in a webinfo header list, or "" when absent.
func webinfoHeaderValue(headers []webinfo.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// webinfoSecurityHeaders returns the notable security headers present in the
// webinfo header list, matching the set the missing-headers detector checks.
func webinfoSecurityHeaders(headers []webinfo.Header) []string {
	present := make(map[string]bool, len(headers))
	for _, h := range headers {
		present[strings.ToLower(h.Name)] = true
	}
	var out []string
	for _, name := range notableSecurityHeaders {
		if present[strings.ToLower(name)] {
			out = append(out, name)
		}
	}
	return out
}

// webinfoTechnologies flattens a detected stack into fingerprint matches.
//
// webinfo's stack detector returns display strings with the version glued on
// ("Microsoft-IIS/10.0", "ARR/3.0", "WordPress 7.0.3"), so the version is split back
// out here rather than shipped inside the name. An event whose name carries its own
// version can never match the same product reported properly by another tool, and its
// Version field would claim the version is unknown when the probe plainly saw it.
func webinfoTechnologies(stack *webinfo.StackResult) []techMatch {
	if stack == nil {
		return nil
	}
	var out []techMatch
	add := func(name, evidence string) {
		tech := valueobjects.NormalizeTechnology(name, "")
		if tech.Name != "" {
			out = append(out, techMatch{name: tech.Name, version: tech.Version, evidence: evidence})
		}
	}
	add(stack.CMS, "cms")
	add(stack.Server, "Server header")
	add(stack.PoweredBy, "X-Powered-By header")
	add(stack.CDN, "cdn")
	add(stack.Hosting, "hosting")
	for _, p := range stack.Plugins {
		add(p, "plugin")
	}
	for _, lib := range stack.JSLibs {
		add(lib, "js library")
	}
	for _, lib := range stack.CSSLibs {
		add(lib, "css library")
	}
	return out
}

// Wappalyzer maps a standalone Wappalyzer probe result to an HttpEndpointDiscovered
// for the fingerprinted response plus a TechnologyFingerprinted per identified
// technology. The endpoint event causes the technology events, so the chain reads
// domain -> endpoint -> technologies.
//
// The endpoint key is the final URL: that is the response the technologies were read
// from, and it is what makes the entries merge with another tool's report of the same
// URL. The URL the probe started from stays in the tool events. The result's
// technologies are already sorted and deduped by the tool, so the event order here is
// replay-stable without further work.
func Wappalyzer(result *wappalyzer.Result, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil {
		return nil
	}
	now := time.Now()
	url := normalizeEndpointURL(result.FinalURL)
	meta := func(causation string) events.EventMeta {
		return events.EventMeta{
			ScanID:          scanID,
			CausationID:     causation,
			Source:          SourceWappalyzer,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		}
	}

	ep := events.HttpEndpointDiscovered{
		EventMeta:  meta(causationID),
		URL:        url,
		StatusCode: result.StatusCode,
		Title:      result.Title,
		Server:     result.Server,
		Headers:    presentSecurityHeaderNames(result.Headers),
	}
	ep.AuthType, ep.AuthEvidence = detectAuthSurface(result.StatusCode, result.WWWAuthenticate, result.LoginForm)
	ep.EventID = events.NewEventID(now, ep)
	out := make([]events.DomainEvent, 0, len(result.Technologies)+1)
	out = append(out, ep)

	for _, tech := range result.Technologies {
		t := events.TechnologyFingerprinted{
			EventMeta:  meta(ep.EventID),
			URL:        url,
			Technology: tech.Name,
			Version:    tech.Version,
			Evidence:   tech.Evidence,
			Categories: append([]string(nil), tech.Categories...),
			CPEs:       valueobjects.NormalizeCPEs(tech.CPEs, tech.Version, valueobjects.CPEKindProduct),
		}
		t.EventID = events.NewEventID(now, t)
		out = append(out, t)
	}
	return out
}

// presentSecurityHeaderNames filters a list of response header names down to the
// notable security headers, in the canonical order the missing-headers rule uses. It
// is the name-list counterpart of presentSecurityHeaders, for a tool that reports
// which headers existed without carrying their values.
func presentSecurityHeaderNames(names []string) []string {
	present := make(map[string]bool, len(names))
	for _, n := range names {
		present[strings.ToLower(n)] = true
	}
	var out []string
	for _, name := range notableSecurityHeaders {
		if present[strings.ToLower(name)] {
			out = append(out, name)
		}
	}
	return out
}

// Service maps an open port to a ServiceDiscovered event.
func Service(ip string, op *portscan.OpenPort, scanID, causationID, corrID string) events.ServiceDiscovered {
	now := time.Now()
	s := events.ServiceDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourcePortscan,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		IP:        ip,
		Port:      op.Port,
		Protocol:  protocolOf(op),
		Service:   serviceLabel(op),
		Product:   op.Product,
		Version:   op.Version,
		ExtraInfo: op.ExtraInfo,
		CPEs:      valueobjects.NormalizeCPEs(op.CPEs, op.Version, valueobjects.CPEKindService),
		Banner:    op.Banner,
	}
	s.EventID = events.NewEventID(now, s)
	return s
}

// protocolOf returns the open port's transport, defaulting to tcp when naabu did
// not report one.
func protocolOf(op *portscan.OpenPort) string {
	if op.Protocol == events.ServiceProtocolUDP {
		return events.ServiceProtocolUDP
	}
	return events.ServiceProtocolTCP
}

// serviceLabel prefers nmap's identified service name and falls back to the
// well-known name for the port number.
func serviceLabel(op *portscan.OpenPort) string {
	if op.Service != "" {
		return op.Service
	}
	return serviceName(op.Port)
}

// HTTP maps an HTTP probe response to an HttpEndpointDiscovered plus a
// TechnologyFingerprinted event per identified technology. causationID is the
// ServiceDiscovered EventID; the technology events are caused by the endpoint.
func HTTP(resp *httpprobe.Response, scanID, causationID, corrID string) []events.DomainEvent {
	now := time.Now()
	responseURL := resp.FinalURL
	if responseURL == "" {
		responseURL = resp.URL
	}
	url := normalizeEndpointURL(responseURL)
	ep := events.HttpEndpointDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceHTTP,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		URL:        url,
		StatusCode: resp.StatusCode,
		Title:      resp.Title,
		Server:     resp.Header.Get("Server"),
		Headers:    presentSecurityHeaders(resp.Header),
	}
	ep.AuthType, ep.AuthEvidence = detectAuthSurface(
		resp.StatusCode, resp.Header.Get("WWW-Authenticate"), webinfo.HasPasswordInput(resp.Body))
	ep.EventID = events.NewEventID(now, ep)
	out := []events.DomainEvent{ep}

	for _, tech := range fingerprint(resp) {
		t := events.TechnologyFingerprinted{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     ep.EventID,
				Source:          SourceHTTP,
				Phase:           events.PhaseActive,
				Category:        events.CategoryDiscovery,
				ObservationKind: events.ObservationKindActiveProbe,
				CapturedAt:      now,
				ToolCorrID:      corrID,
			},
			URL:        url,
			Technology: tech.name,
			Version:    tech.version,
			Evidence:   tech.evidence,
		}
		t.EventID = events.NewEventID(now, t)
		out = append(out, t)
	}
	return out
}

// notableSecurityHeaders are the response headers reported in
// HttpEndpointDiscovered.Headers and checked by the missing-security-headers rule.
var notableSecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

func presentSecurityHeaders(h http.Header) []string {
	var present []string
	for _, name := range notableSecurityHeaders {
		if h.Get(name) != "" {
			present = append(present, name)
		}
	}
	return present
}

type techMatch struct {
	name     string
	version  string
	evidence string
}

// fingerprint derives technologies from the Server and X-Powered-By headers and a
// few body markers. Detection is intentionally simple and best-effort.
func fingerprint(resp *httpprobe.Response) []techMatch {
	var matches []techMatch
	seen := map[string]bool{}
	add := func(m techMatch) {
		if m.name == "" || seen[strings.ToLower(m.name)] {
			return
		}
		seen[strings.ToLower(m.name)] = true
		matches = append(matches, m)
	}

	if server := resp.Header.Get("Server"); server != "" {
		name, version := parseServerHeader(server)
		add(techMatch{name: name, version: version, evidence: "Server: " + server})
	}
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		add(techMatch{name: poweredBy, evidence: "X-Powered-By: " + poweredBy})
	}

	body := bytes.ToLower(resp.Body)
	for _, bm := range bodyMarkers {
		if bytes.Contains(body, bm.marker) {
			add(techMatch{name: bm.tech, evidence: "body marker " + string(bm.marker)})
		}
	}
	return matches
}

var bodyMarkers = []struct {
	marker []byte
	tech   string
}{
	{[]byte("wp-content"), "WordPress"},
	{[]byte("wp-includes"), "WordPress"},
	{[]byte("/sites/all/"), "Drupal"},
	{[]byte("joomla"), "Joomla"},
}

func parseServerHeader(server string) (name, version string) {
	parts := strings.SplitN(server, "/", 2)
	name = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		if fields := strings.Fields(parts[1]); len(fields) > 0 {
			version = fields[0]
		}
	}
	return name, version
}

// normalizeEndpointURL strips the trailing slash from a root-path URL so the same
// endpoint reached as "https://host" and "https://host/" collapses to one endpoint
// node (and one finding) instead of two. It only touches the bare root: a non-root
// path like "/login/" is left untouched, since "/login" and "/login/" may be
// distinct resources, and a URL with a query or fragment is left untouched. A URL
// that does not parse is returned unchanged.
func normalizeEndpointURL(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Path == "/" && u.RawQuery == "" && u.Fragment == "" {
		u.Path = ""
		return u.String()
	}
	return raw
}

var wellKnownPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    schemeHTTP,
	110:   "pop3",
	143:   "imap",
	443:   schemeHTTPS,
	445:   "smb",
	1433:  "mssql",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	27017: "mongodb",
}

func serviceName(port int) string {
	return wellKnownPorts[port]
}
