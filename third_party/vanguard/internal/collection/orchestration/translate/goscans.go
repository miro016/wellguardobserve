package translate

import (
	"fmt"
	neturl "net/url"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// GoScansInput is the scan identity a translated goscans observation is stamped
// with. It is a value rather than a set of parameters because every translation
// needs the same four things and a per-event lookup for causation.
type GoScansInput struct {
	// ScanID correlates the observation with the run that produced it.
	ScanID string
	// Root is the scan root, used as the parent for a name this tool discovered.
	Root string
	// CorrID is the substage's per-run tool correlation id, so every derived
	// observation joins back to the tool events in the same run.
	CorrID string
	// Causation maps a target address to the EventID of the discovery that
	// introduced it, so an observation about a host threads back to how the host
	// entered the scan. A missing address simply yields no causation.
	Causation map[string]string
}

// causationFor returns the causation EventID recorded for ip, or empty.
func (in GoScansInput) causationFor(ip string) string { return in.Causation[ip] }

// GoScansEvent maps one goscans tool event to the domain observations it carries.
// It is the whole GoScans-to-domain contract in one place, and it is exhaustive by
// construction: the tool event interface is sealed, so a new tool event cannot
// reach the stream without a decision being made here.
//
// It returns nil for the events that carry no domain observation. Those are the
// tool's own lifecycle and diagnostics: run and per-target start/finish, module
// summaries, and forwarded upstream log lines. They stay in the tool-event log,
// which is where an operator looks to explain what the tool did; copying them into
// the domain stream would add rows nothing folds and no report reads.
//
// Errors are the exception: a failure that costs coverage becomes an IssueObserved,
// because "the scan did not look" and "the scan looked and found nothing" must
// never be indistinguishable in the domain stream.
func GoScansEvent(evt goscans.Event, in GoScansInput) []events.DomainEvent {
	switch e := evt.(type) {
	case goscans.HostProfileCollected:
		return goScansHostProfile(e, in)
	case goscans.ServiceDiscovered:
		return goScansService(e, in)
	case goscans.ScriptCollected:
		return goScansScript(e, in)
	case goscans.BannerCollected:
		return goScansBanner(e, in)
	case goscans.TLSAssessed:
		return goScansTLS(e, in)
	case goscans.TLSNamesUnreported:
		return goScansTLSNamesUnreported(e, in)
	case goscans.SSHAssessed:
		return goScansSSH(e, in)
	case goscans.CrawlPage:
		return goScansCrawlPage(e, in)
	case goscans.EnumItemFound:
		return goScansEnumItem(e, in)
	case goscans.CrawlCompleted:
		return goScansCrawlCompleted(e, in)
	}
	// Everything else is a diagnostic or error event, translated to a coverage issue
	// (or nothing). Kept in its own function so this dispatch stays under the
	// cyclomatic-complexity budget as new observation cases are added.
	return goScansDiagnostic(evt, in)
}

// goScansDiagnostic translates the goscans lifecycle, diagnostic, and error events.
// Result-bearing observations are handled by [GoScansEvent]; the events here either
// become a coverage IssueObserved or carry nothing (pure lifecycle and forwarded
// upstream log lines), which is what keeps a failed scan distinguishable from an
// empty one in the domain stream.
func goScansDiagnostic(evt goscans.Event, in GoScansInput) []events.DomainEvent {
	switch e := evt.(type) {
	case goscans.DiscoveryEmpty:
		return goScansDiscoveryEmpty(e, in)
	case goscans.ModuleSetupFailed:
		return goScansModuleSetupFailed(e, in)
	case goscans.ModuleTimeout:
		return goScansModuleTimeout(e, in)
	case goscans.ModuleFailed:
		return goScansModuleFailed(e, in)
	case goscans.JobSkipped:
		return goScansJobSkipped(e, in)
	case goscans.InvalidInput:
		return goScansIssue(in, "", events.SeverityHigh, goScansIssueInternal,
			fmt.Sprintf("goscans refused to run: invalid %s: %v", e.Field, e.Err))
	case goscans.FilesystemError:
		return goScansIssue(in, "", events.SeverityHigh, goScansIssueFilesystem,
			fmt.Sprintf("goscans could not %s: %v", e.Op, e.Err))
	case goscans.CleanupError:
		return goScansIssue(in, "", events.SeverityMedium, goScansIssueFilesystem,
			fmt.Sprintf("goscans left temporary state behind: %v", e.Err))
	case goscans.Cancelled:
		return goScansCancelled(e, in)
	}
	return nil
}

// The two web schemes, named once. They appear in the service-name resolution and
// in the endpoint URL check, and both must mean the same thing.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// Error classes stamped into the issue text, so a reader (and a data-quality pass)
// can tell what kind of failure cost the coverage rather than only that something
// failed. They are words in the message rather than a new field, because
// IssueObserved is the shared vocabulary and every other tool files its failures
// the same way.
const (
	goScansIssueDependency  = "dependency"
	goScansIssueTimeout     = "timeout"
	goScansIssueRemote      = "remote-rejection"
	goScansIssueParser      = "parser"
	goScansIssueFilesystem  = "filesystem"
	goScansIssueInternal    = "internal"
	goScansIssueCoverage    = "coverage"
	goScansIssueCancelled   = "cancelled"
	goScansIssueNotRelevant = "not-applicable"
)

// goScansHostProfile maps the host-level discovery evidence. It yields the profile
// itself, the reachability the scan proved by observing the host at all, an OS
// guess when there is one, the host's own names, and the further addresses that
// answered for it.
func goScansHostProfile(e goscans.HostProfileCollected, in GoScansInput) []events.DomainEvent {
	now := time.Now()
	out := make([]events.DomainEvent, 0, 4+len(e.OtherNames)+len(e.OtherIPs))

	profile := events.HostProfileObserved{
		EventMeta:       goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:              e.IP,
		DnsName:         e.DnsName,
		OtherNames:      e.OtherNames,
		OtherIPs:        e.OtherIPs,
		MacAddress:      e.MacAddress,
		OSCandidates:    e.OSGuesses,
		OSFromService:   e.OSFromSMB,
		LastBoot:        e.LastBoot.UTC(),
		Uptime:          e.Uptime,
		DetectionReason: e.DetectionReason,
		TracerouteHops:  e.Hops,
		Truncated:       e.Truncated,
	}
	if e.LastBoot.IsZero() {
		profile.LastBoot = time.Time{}
	}
	profile.EventID = events.NewEventID(now, profile)
	out = append(out, profile)

	// Discovery reported the host, which means something answered: an independent
	// reachability confirmation, separate from the port scanner's.
	reach := events.IPReachabilityObserved{
		EventMeta: goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:        e.IP,
		Reachable: true,
		State:     events.ReachabilityReachable,
	}
	reach.EventID = events.NewEventID(now, reach)
	out = append(out, reach)

	if os := goScansOSGuess(e); os != "" {
		guess := events.HostOSGuessed{
			EventMeta: goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
			IP:        e.IP,
			OS:        os,
			Method:    goScansOSMethod(e),
		}
		guess.EventID = events.NewEventID(now, guess)
		out = append(out, guess)
	}

	// The host's own names, and the addresses attributed to it. A name here is what
	// the address owner published, so it is an active-probe observation of a claim,
	// never a confirmed resolution: the IP mapping is stamped inferred for exactly
	// that reason, and a later DNS answer for the same pair upgrades it.
	names := append([]string(nil), e.OtherNames...)
	if e.DnsName != "" {
		names = append(names, e.DnsName)
	}
	sort.Strings(names)
	for _, name := range goScansDedup(names) {
		out = append(out, goScansDomainName(name, in, now))
	}
	for _, ip := range e.OtherIPs {
		if ip == e.IP {
			continue
		}
		out = append(out, goScansIPAddress(ip, e.DnsName, in, now))
	}
	return out
}

// goScansOSGuess picks the OS to report. A service that named its own OS outranks
// a stack fingerprint, and only the first fingerprint candidate is promoted: the
// rest stay on the profile, where their order still says what they are.
func goScansOSGuess(e goscans.HostProfileCollected) string {
	if e.OSFromSMB != "" {
		return e.OSFromSMB
	}
	if len(e.OSGuesses) > 0 {
		return e.OSGuesses[0]
	}
	return ""
}

// goScansOSMethod names how the promoted OS guess was obtained, so a consumer can
// weigh a service reply differently from a fingerprint.
func goScansOSMethod(e goscans.HostProfileCollected) string {
	if e.OSFromSMB != "" {
		return "goscans smb reply"
	}
	return "goscans nmap os fingerprint"
}

// goScansService maps one discovered service. The transport is the asset key's
// third component, so an unrecognised one is quarantined as an issue rather than
// defaulted: silently calling it tcp would merge two different services into one
// asset and hide the fact that the scan saw something it does not model.
func goScansService(e goscans.ServiceDiscovered, in GoScansInput) []events.DomainEvent {
	protocol := strings.ToLower(strings.TrimSpace(e.Protocol))
	if protocol != events.ServiceProtocolTCP && protocol != events.ServiceProtocolUDP {
		return goScansIssue(in, e.IP, events.SeverityLow, goScansIssueParser,
			fmt.Sprintf("goscans reported %s:%d with transport %q, which is neither tcp nor udp; the service was recorded in the tool log only, because a guessed transport would merge it with a different service",
				e.IP, e.Port, e.Protocol))
	}

	now := time.Now()
	svc := events.ServiceDiscovered{
		EventMeta: goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:        e.IP,
		Port:      e.Port,
		Protocol:  protocol,
		Service:   goScansServiceName(e),
		Product:   e.Product,
		Version:   e.Version,
		ExtraInfo: e.ExtraInfo,
		CPEs:      valueobjects.NormalizeCPEs(e.CPEs, e.Version, valueobjects.CPEKindService),
	}
	svc.EventID = events.NewEventID(now, svc)
	return []events.DomainEvent{svc}
}

// tlsImplyingServiceNames are the service names that already denote the TLS form
// of a protocol. nmap reports these with the ssl tunnel attribute set as well, so
// the attribute is a restatement rather than extra information, and appending a
// suffix would invent a spelling ("https/tls") that no other tool produces - which
// then reads as a disagreement with every tool that spells it the usual way.
var tlsImplyingServiceNames = map[string]bool{
	"https": true, "smtps": true, "imaps": true, "pop3s": true, "ldaps": true,
	"ftps": true, "nntps": true, "ircs": true, "telnets": true, "sips": true,
}

// goScansServiceName resolves the service label. nmap describes a TLS-wrapped
// service by its inner protocol with a separate tunnel attribute, so "http" with
// tunnel "ssl" is https; reporting the inner name alone would record an encrypted
// service as cleartext.
//
// The suffix is only added where it says something the name does not. A name that
// already means the TLS form is returned unchanged, and a name that does not -
// "rtsp" on a TLS socket - keeps the suffix, because there the difference from a
// cleartext service of the same name is exactly the point.
func goScansServiceName(e goscans.ServiceDiscovered) string {
	name := strings.ToLower(strings.TrimSpace(e.Name))
	if !strings.EqualFold(strings.TrimSpace(e.Tunnel), "ssl") {
		return name
	}
	if name == schemeHTTP {
		return schemeHTTPS
	}
	if name == "" {
		return "ssl"
	}
	if tlsImplyingServiceNames[name] {
		return name
	}
	return name + "/tls"
}

// goScansScript maps one NSE script result. No parser is registered yet, so every
// script arrives as bounded evidence with an explicit "none" parse status: an
// unknown script is retained, never guessed at, and never promoted to a finding.
func goScansScript(e goscans.ScriptCollected, in GoScansInput) []events.DomainEvent {
	now := time.Now()
	protocol := strings.ToLower(strings.TrimSpace(e.Protocol))
	scope := strings.ToLower(strings.TrimSpace(e.Scope))
	if scope == "" {
		scope = "host"
		if e.Port != 0 {
			scope = "port"
		}
	}
	s := events.ServiceScriptObserved{
		EventMeta:   goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:          e.IP,
		Port:        e.Port,
		Protocol:    protocol,
		Scope:       scope,
		Script:      e.Name,
		Output:      e.Output,
		RawBytes:    e.RawBytes,
		Truncated:   e.Truncated,
		ParseStatus: events.ScriptParseNone,
	}
	s.EventID = events.NewEventID(now, s)
	return []events.DomainEvent{s}
}

// goScansBanner maps one banner probe to a service observation carrying the
// bounded banner. Upstream sends several probes per service and the actor reports
// each separately; which probe answered stays in the tool event, because the
// service asset has one banner field and the domain question it answers ("what
// does this service say it is") is the same whichever probe elicited it.
func goScansBanner(e goscans.BannerCollected, in GoScansInput) []events.DomainEvent {
	if e.Excerpt == "" {
		return nil
	}
	protocol := strings.ToLower(strings.TrimSpace(e.Protocol))
	if protocol != events.ServiceProtocolTCP && protocol != events.ServiceProtocolUDP {
		return nil
	}
	now := time.Now()
	svc := events.ServiceDiscovered{
		EventMeta: goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:        e.IP,
		Port:      e.Port,
		Protocol:  protocol,
		Banner:    e.Excerpt,
	}
	svc.EventID = events.NewEventID(now, svc)
	return []events.DomainEvent{svc}
}

// goScansTLS maps one TLS assessment, plus the leaf certificate of every chain the
// endpoint presented. Only leaves become CertificateDiscovered: that event is the
// certificate-as-an-asset view, and an intermediate or root is part of a
// deployment rather than an asset of the target. The full chain, with each
// certificate's role, stays on the assessment.
func goScansTLS(e goscans.TLSAssessed, in GoScansInput) []events.DomainEvent {
	now := time.Now()
	assessed := events.TlsSecurityAssessed{
		EventMeta:                goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:                       e.IP,
		Port:                     e.Port,
		ServerName:               strings.ToLower(strings.TrimSpace(e.Vhost)),
		AssessedNames:            goScansNames(e.AssessedNames),
		Protocols:                e.Protocols,
		Ciphers:                  goScansCiphers(e.Ciphers),
		CipherCount:              e.CipherCount,
		CipherState:              events.AssessmentTested,
		Chains:                   goScansChains(e.Chains),
		ChainCount:               e.ChainCount,
		ChainState:               events.AssessmentTested,
		LowestProtocol:           e.Settings.LowestProtocol,
		MinStrength:              e.Settings.MinStrength,
		ExtendedMasterSecret:     e.Settings.ExtendedMasterSecret,
		TLSFallbackSCSV:          e.Settings.TLSFallbackSCSV,
		SecureRenegotiation:      e.Settings.SecureRenegotiation,
		SessionResumptionID:      e.Settings.SessionResumptionID,
		SessionResumptionTickets: e.Settings.SessionResumptionTickets,
		MozillaCompliant:         e.Settings.MozillaCompliant,
		SettingsState:            goScansState(e.SettingsKnown),
		Vulnerabilities:          e.Issues,
		VulnerabilityState:       goScansState(e.IssuesKnown),
		SupportedCurves:          e.SupportedCurves,
		RejectedCurves:           e.RejectedCurves,
		ECDHKeyExchange:          e.ECDHKeyExchange,
		CurveState:               goScansState(e.CurvesKnown),
		Truncated:                e.Truncated,
	}
	assessed.EventID = events.NewEventID(now, assessed)
	out := []events.DomainEvent{assessed}

	for i := range e.Chains {
		leaf, ok := goScansLeaf(e.Chains[i])
		if !ok {
			continue
		}
		out = append(out, goScansCertificate(leaf, e, in, now))
	}
	return out
}

// goScansNames normalizes a server-name list the same way ServerName is normalized,
// so a name reads identically whichever field carries it.
func goScansNames(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, name := range in {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// goScansState maps a producer's "this section was assessed" flag onto the typed
// assessment state. A section the scanner never produced is not_tested, which is
// what stops an empty vulnerability list from reading as a clean one.
func goScansState(known bool) events.AssessmentState {
	if known {
		return events.AssessmentTested
	}
	return events.AssessmentNotTested
}

// goScansCiphers maps the accepted cipher suites, preserving the producer's order
// (already sorted by protocol then name, so replay is byte-identical).
func goScansCiphers(in []goscans.TLSCipher) []events.TlsCipherSuite {
	if len(in) == 0 {
		return nil
	}
	out := make([]events.TlsCipherSuite, 0, len(in))
	for _, c := range in {
		out = append(out, events.TlsCipherSuite{
			Protocol:       c.Protocol,
			Name:           c.Name,
			KeyExchange:    c.KeyExchange,
			Authentication: c.Authentication,
			Encryption:     c.Encryption,
			Mac:            c.Mac,
			EncryptionBits: c.EncryptionBits,
			Strength:       c.Strength,
			ForwardSecrecy: c.ForwardSecrecy,
			Export:         c.Export,
			Draft:          c.Draft,
		})
	}
	return out
}

// goScansChains maps the presented certificate deployments, preserving both the
// chain order and the certificate order within each chain.
func goScansChains(in []goscans.TLSChain) []events.TlsCertificateChain {
	if len(in) == 0 {
		return nil
	}
	out := make([]events.TlsCertificateChain, 0, len(in))
	for _, chain := range in {
		certs := make([]events.TlsChainCertificate, 0, len(chain.Certificates))
		for _, c := range chain.Certificates {
			certs = append(certs, events.TlsChainCertificate{
				Role:               strings.ToLower(strings.TrimSpace(c.Role)),
				SubjectCN:          c.SubjectCN,
				IssuerCN:           c.IssuerCN,
				Serial:             valueobjects.CanonicalCertSerial(c.Serial),
				AlternativeNames:   c.AlternativeNames,
				ValidFrom:          goScansUTC(c.ValidFrom),
				ValidTo:            goScansUTC(c.ValidTo),
				PublicKeyAlgorithm: c.PublicKeyAlgorithm,
				PublicKeyBits:      c.PublicKeyBits,
				SignatureAlgorithm: c.SignatureAlgorithm,
				SignatureHash:      c.SignatureHash,
				SHA1Fingerprint:    c.SHA1Fingerprint,
				CA:                 c.CA,
				Truncated:          c.Truncated,
			})
		}
		out = append(out, events.TlsCertificateChain{
			ValidatedBy:  chain.ValidatedBy,
			ValidOrder:   chain.ValidOrder,
			Certificates: certs,
		})
	}
	return out
}

// goScansLeaf picks the chain's leaf certificate: the one upstream labelled leaf,
// falling back to the first certificate, which is where a correctly ordered chain
// puts it.
func goScansLeaf(chain goscans.TLSChain) (goscans.TLSCertificate, bool) {
	for _, c := range chain.Certificates {
		if strings.EqualFold(strings.TrimSpace(c.Role), "leaf") {
			return c, true
		}
	}
	if len(chain.Certificates) > 0 {
		return chain.Certificates[0], true
	}
	return goscans.TLSCertificate{}, false
}

// goScansCertificate maps one leaf certificate to the shared certificate event.
// LiveVerifiedAt is set because the certificate was taken off a live handshake,
// which is the distinction this field exists to draw against a certificate that was
// only ever read out of a transparency log.
func goScansCertificate(leaf goscans.TLSCertificate, e goscans.TLSAssessed, in GoScansInput, now time.Time) events.DomainEvent {
	names := append([]string(nil), leaf.AlternativeNames...)
	if leaf.SubjectCN != "" {
		names = append(names, strings.ToLower(strings.TrimSpace(leaf.SubjectCN)))
	}
	sort.Strings(names)

	query := strings.ToLower(strings.TrimSpace(e.Vhost))
	if query == "" {
		query = fmt.Sprintf("%s:%d", e.IP, e.Port)
	}
	c := events.CertificateDiscovered{
		EventMeta:   goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		SearchQuery: query,
		Certificate: events.CertificateData{
			CommonName:     leaf.SubjectCN,
			IssuerName:     leaf.IssuerCN,
			SerialNumber:   valueobjects.CanonicalCertSerial(leaf.Serial),
			ValidFrom:      goScansUTC(leaf.ValidFrom),
			ValidUntil:     goScansUTC(leaf.ValidTo),
			LiveVerifiedAt: now.UTC(),
			Domains:        goScansDedup(names),
		},
	}
	c.EventID = events.NewEventID(now, c)
	return c
}

// goScansSSH maps the SSH algorithm offer. The lists keep the server's order,
// which is its stated preference, so they are carried through unsorted.
func goScansSSH(e goscans.SSHAssessed, in GoScansInput) []events.DomainEvent {
	now := time.Now()
	p := events.SshPostureDiscovered{
		EventMeta:          goScansMeta(in, e.IP, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:                 e.IP,
		Port:               e.Port,
		ProtocolVersion:    e.ProtocolVersion,
		KeyExchange:        e.KeyExchange,
		HostKey:            e.ServerKey,
		Encryption:         e.Encryption,
		Mac:                e.Mac,
		Compression:        e.Compression,
		AuthMechanisms:     e.AuthMechanisms,
		GuessedKeyExchange: e.GuessedKeyExchange,
		Truncated:          e.Truncated,
	}
	p.EventID = events.NewEventID(now, p)
	return []events.DomainEvent{p}
}

// goScansCrawlPage maps one crawled page to an HTTP endpoint observation.
func goScansCrawlPage(e goscans.CrawlPage, in GoScansInput) []events.DomainEvent {
	return goScansEndpoint(in, e.IP, e.URL, e.ResponseCode, e.Title, e.Server, e.AuthMethod)
}

// goScansEnumItem maps one enumeration hit to an HTTP endpoint observation. A hit
// is a path that answered, which is exactly what the endpoint event records; the
// probe name that found it stays in the tool event, because the endpoint exists
// regardless of which probe list named it.
func goScansEnumItem(e goscans.EnumItemFound, in GoScansInput) []events.DomainEvent {
	return goScansEndpoint(in, e.IP, e.URL, e.ResponseCode, e.Title, e.Server, e.AuthMethod)
}

// goScansEndpoint builds the endpoint observation shared by the crawler and the
// enumerator. A URL that does not parse is dropped rather than recorded: the URL is
// the endpoint asset's key, and a malformed key would create an asset nothing can
// join to.
func goScansEndpoint(in GoScansInput, ip, url string, status int, title, server, authMethod string) []events.DomainEvent {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil
	}
	parsed, err := neturl.Parse(url)
	if err != nil || parsed.Host == "" || (parsed.Scheme != schemeHTTP && parsed.Scheme != schemeHTTPS) {
		return nil
	}

	now := time.Now()
	ep := events.HttpEndpointDiscovered{
		EventMeta:  goScansMeta(in, ip, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		URL:        parsed.String(),
		StatusCode: status,
		Title:      title,
		Server:     server,
	}
	if authMethod != "" {
		ep.AuthType = strings.ToLower(strings.TrimSpace(authMethod))
		ep.AuthEvidence = "goscans observed authentication scheme " + authMethod
	}
	ep.EventID = events.NewEventID(now, ep)
	return []events.DomainEvent{ep}
}

// goScansCrawlCompleted maps the virtual hosts a crawl discovered. They are names
// this tool found itself, so they enter the domain stream like any other
// discovered name; the caller still applies scope before publishing them.
func goScansCrawlCompleted(e goscans.CrawlCompleted, in GoScansInput) []events.DomainEvent {
	if len(e.DiscoveredVhosts) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]events.DomainEvent, 0, len(e.DiscoveredVhosts))
	for _, name := range e.DiscoveredVhosts {
		out = append(out, goScansDomainName(name, in, now))
	}
	return out
}

// goScansDiscoveryEmpty records that discovery completed and reported no host at
// all. It is a coverage issue rather than an unreachable verdict: the scan is
// configured to skip host discovery, so every target is treated as up, and an empty
// result means the scan learned nothing about the target rather than that the
// target is down.
func goScansDiscoveryEmpty(e goscans.DiscoveryEmpty, in GoScansInput) []events.DomainEvent {
	msg := fmt.Sprintf("goscans discovery returned no host for %s", e.IP)
	if e.Status != "" {
		msg += " (status: " + e.Status + ")"
	}
	msg += "; the host was not assessed, which is a coverage gap rather than a clean result"
	return goScansIssue(in, e.IP, events.SeverityLow, goScansIssueCoverage, msg)
}

// goScansModuleSetupFailed records a module that could not be built. For the TLS
// module this is where a missing or wrong-version SSLyze surfaces, so it is
// classified as a dependency failure: the fix is in deployment, not in the scan.
func goScansModuleSetupFailed(e goscans.ModuleSetupFailed, in GoScansInput) []events.DomainEvent {
	return goScansIssue(in, e.IP, events.SeverityMedium, goScansIssueDependency,
		fmt.Sprintf("goscans could not start its %s module against %s: %v; that check did not run",
			e.Module, goScansTarget(e.IP, e.Port), e.Err))
}

// goScansModuleTimeout records a module that ran out of its deadline. Whatever it
// had found is already in the stream, so this marks the result partial rather than
// discarding it.
func goScansModuleTimeout(e goscans.ModuleTimeout, in GoScansInput) []events.DomainEvent {
	return goScansIssue(in, e.IP, events.SeverityLow, goScansIssueTimeout,
		fmt.Sprintf("goscans %s module timed out after %s against %s; its result is partial",
			e.Module, e.Timeout, goScansTarget(e.IP, e.Port)))
}

// goScansModuleFailed records an upstream failure. An exception means the payload
// was unusable, which is how upstream reports a parse failure; a graceful status is
// the remote end refusing or answering unusably.
func goScansModuleFailed(e goscans.ModuleFailed, in GoScansInput) []events.DomainEvent {
	class := goScansIssueRemote
	severity := events.SeverityLow
	detail := "the module completed with an error status"
	if e.Exception {
		class = goScansIssueParser
		severity = events.SeverityMedium
		detail = "the result was discarded as unusable"
	}
	msg := fmt.Sprintf("goscans %s module failed against %s: %s", e.Module, goScansTarget(e.IP, e.Port), detail)
	if e.Status != "" {
		msg += " (status: " + e.Status + ")"
	}
	return goScansIssue(in, e.IP, severity, class, msg)
}

// goScansJobSkipped records work the planner did not schedule, but only when not
// scheduling it left a gap.
//
// A module skipped because the service is the wrong kind - a TLS check on an FTP
// port, an SSH check on a web port - is the planner working correctly, not an
// observation about the target, and there is one such skip per service per
// disabled module. Left in the domain stream they outnumber the real gaps by an
// order of magnitude and turn the report's issue list into a page of non-events,
// with the one host that genuinely went unassessed buried among them. They stay in
// the tool log, which is where the record of what the planner decided belongs, and
// they are counted in ScanCompleted.Skipped.
//
// A skip caused by a cap is the opposite: the service was eligible and was not
// assessed anyway, so it is exactly the coverage gap this stream exists to carry.
func goScansJobSkipped(e goscans.JobSkipped, in GoScansInput) []events.DomainEvent {
	if !e.Eligible {
		return nil
	}
	return goScansIssue(in, e.IP, events.SeverityLow, goScansIssueCoverage,
		fmt.Sprintf("goscans did not run its %s module against %s: %s; the service was eligible "+
			"and went unassessed, which is a coverage gap rather than a clean result",
			e.Module, goScansTarget(e.IP, e.Port), e.Reason))
}

// goScansTLSNamesUnreported records that a TLS job asked about more server names
// than it got results for. The two shapes read very differently to an operator, so
// they get their own sentence: no result at all means the service was not assessed,
// while a short count means it was assessed but nothing can be said about any one
// name. Neither is a clean result, and both are the same low-severity coverage gap.
func goScansTLSNamesUnreported(e goscans.TLSNamesUnreported, in GoScansInput) []events.DomainEvent {
	names := strings.Join(e.Requested, ", ")
	msg := fmt.Sprintf("goscans requested TLS on %s under %d server name(s) (%s) and got no result at all; "+
		"the service went unassessed, which is a coverage gap rather than a clean result",
		goScansTarget(e.IP, e.Port), len(e.Requested), names)
	if e.Reported > 0 {
		msg = fmt.Sprintf("goscans assessed TLS on %s under %d server name(s) (%s) but reported only %d result(s): "+
			"the scanner drops both a result that duplicates one it already holds and one that came back empty, "+
			"without distinguishing them, so no result can be tied to a name and the missing names may not have "+
			"been measured at all",
			goScansTarget(e.IP, e.Port), len(e.Requested), names, e.Reported)
	}
	return goScansIssue(in, e.IP, events.SeverityLow, goScansIssueCoverage, msg)
}

// goScansCancelled records work stopped by cancellation, which always costs
// coverage: whatever had not run will not run.
func goScansCancelled(e goscans.Cancelled, in GoScansInput) []events.DomainEvent {
	msg := fmt.Sprintf("goscans stopped during %s: %v", e.Phase, e.Err)
	if e.Draining {
		msg += " (waiting out a module that cannot be interrupted)"
	}
	msg += "; the remaining assessment did not run"
	return goScansIssue(in, e.IP, events.SeverityMedium, goScansIssueCancelled, msg)
}

// goScansTarget renders the target of a module error, which is a host for
// discovery and a service for everything else.
func goScansTarget(ip string, port int) string {
	if port == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// goScansDomainName builds the discovered-name observation for a name this tool
// found. It is an active-probe observation: the name came from a live reply, not
// from a passive registry.
func goScansDomainName(name string, in GoScansInput, now time.Time) events.DomainEvent {
	name = strings.ToLower(strings.TrimSpace(name))
	parent := in.Root
	depth := 1
	if name == in.Root {
		parent = ""
		depth = 0
	}
	d := events.DnsDomainNameDiscovered{
		EventMeta:       goScansMeta(in, "", now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		Domain:          name,
		ParentDomain:    parent,
		Depth:           depth,
		DiscoverySource: SourceGoScans,
	}
	d.EventID = events.NewEventID(now, d)
	return d
}

// goScansIPAddress builds the address observation for a further address the host
// answered on. Confidence is inferred, not confirmed: the scanner attributed the
// address to the host, but no DNS answer resolved the name to it, and the asset
// graph keeps the strongest confidence seen, so a later DNS answer still wins.
func goScansIPAddress(ip, domain string, in GoScansInput, now time.Time) events.DomainEvent {
	e := events.IPAddressDiscovered{
		EventMeta:  goScansMeta(in, ip, now, events.CategoryDiscovery, events.SeverityInfo, events.ObservationKindActiveProbe),
		IP:         ip,
		Domain:     strings.ToLower(strings.TrimSpace(domain)),
		Confidence: events.ConfidenceInferred,
	}
	e.EventID = events.NewEventID(now, e)
	return e
}

// goScansIssue builds the coverage/failure observation shared by every goscans
// error path. class names the kind of failure so a reader does not have to
// pattern-match the message.
func goScansIssue(in GoScansInput, target string, severity events.Severity, class, msg string) []events.DomainEvent {
	if target == "" {
		target = in.Root
	}
	now := time.Now()
	issue := events.IssueObserved{
		EventMeta: goScansMeta(in, target, now, events.CategoryIssue, severity, events.ObservationKindOperational),
		Query:     target,
		Error:     msg,
		Class:     class,
	}
	issue.EventID = events.NewEventID(now, issue)
	return []events.DomainEvent{issue}
}

// goScansMeta builds the envelope every translated goscans observation shares. The
// source is always goscans and never the tool whose result it happens to agree
// with, so two tools observing one asset stay two observations.
func goScansMeta(in GoScansInput, causationIP string, now time.Time, cat events.Category, sev events.Severity, kind events.ObservationKind) events.EventMeta {
	return events.EventMeta{
		ScanID:          in.ScanID,
		CausationID:     in.causationFor(causationIP),
		Source:          SourceGoScans,
		Phase:           events.PhaseActive,
		Category:        cat,
		Severity:        sev,
		ObservationKind: kind,
		CapturedAt:      now,
		ToolCorrID:      in.CorrID,
	}
}

// goScansUTC normalizes a timestamp to UTC, leaving a zero time zero so "not
// reported" never becomes an instant in 1970.
func goScansUTC(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}

// goScansDedup removes duplicates from an already-sorted list.
func goScansDedup(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] && v != "" {
			out = append(out, v)
		}
	}
	return out
}
