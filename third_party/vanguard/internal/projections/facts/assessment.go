package facts

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// Attribute and metadata keys for the assessment facets. They are named constants
// because a renderer, a temporal check, and a test all read the same key, and a
// typo in any one of them would silently produce an empty column.
const (
	attrServerName = "server_name"
	// attrAssessedNames lists every server name one TLS assessment covers, which
	// is more than one when the producer could not attribute its result to a
	// single name.
	attrAssessedNames = "assessed_names"
	attrScriptScope   = "scope"
	// attrTruncated marks a payload a producer had to cut, so a short list in the
	// graph is never read as the whole of what the target offered.
	attrTruncated = "truncated"
)

// applyHostProfile folds the host-level evidence onto the IPAddress asset. The
// evidence is recorded as an observation with its own confidence rather than
// promoted onto the asset: every field here is an inference, and an asset attribute
// reads as a fact about the asset.
//
// Confidence is medium, not high. The scanner really did observe these things, but
// what it observed is a guess about the host: an OS fingerprint, a name the address
// owner published, an uptime derived from timestamp drift.
func (g *Graph) applyHostProfile(e events.HostProfileObserved) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid host profile IP %q", e.IP), RawEventID: m.EventID})
		return
	}
	g.ensureIP(m, ip, version)

	md := map[string]any{}
	if e.DnsName != "" {
		md["dns_name"] = e.DnsName
	}
	if len(e.OtherNames) > 0 {
		md["other_names"] = append([]string(nil), e.OtherNames...)
	}
	if len(e.OtherIPs) > 0 {
		md["other_ips"] = append([]string(nil), e.OtherIPs...)
	}
	if e.MacAddress != "" {
		md["mac_address"] = e.MacAddress
	}
	if len(e.OSCandidates) > 0 {
		md["os_candidates"] = append([]string(nil), e.OSCandidates...)
	}
	if e.OSFromService != "" {
		md["os_from_service"] = e.OSFromService
	}
	if e.DetectionReason != "" {
		md["detection_reason"] = e.DetectionReason
	}
	if e.Uptime > 0 {
		md["uptime_seconds"] = int(e.Uptime.Seconds())
	}
	if len(e.TracerouteHops) > 0 {
		md["traceroute_hops"] = append([]string(nil), e.TracerouteHops...)
	}
	if e.Truncated {
		md[attrTruncated] = true
	}

	g.addObsEvidenceWithCurrentness(m, ip, "host_profile_observed", "host_profile_evidence",
		"host_profile:"+ip,
		fmt.Sprintf("%s profiled host %s (%d OS candidate(s), %d other name(s)).",
			m.Source, ip, len(e.OSCandidates), len(e.OtherNames)),
		ConfidenceMedium, liveVerifiedCurrentness(m.ObservationKind, true), md)
}

// applyServiceScript folds one script result as evidence on the service, or on the
// address for a host-scope script. Confidence is medium and the statement says the
// script ran rather than what it found: nobody has parsed the output, so the graph
// records that the evidence exists and where to read it, which is the honest claim.
func (g *Graph) applyServiceScript(e events.ServiceScriptObserved) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid script IP %q", e.IP), RawEventID: m.EventID})
		return
	}
	g.ensureIP(m, ip, version)

	assetKey := ip
	target := ip
	if e.Port > 0 {
		transport := normalizeActiveTransport(e.Protocol)
		assetKey = entities.NewServiceID(ip, e.Port, transport).String()
		target = assetKey
	}

	md := map[string]any{
		"script":           e.Script,
		attrScriptScope:    e.Scope,
		"parse_status":     string(e.ParseStatus),
		"raw_bytes":        e.RawBytes,
		attrTruncated:      e.Truncated,
		"output_excerpt":   e.Output,
		"output_digest":    e.Digest,
		attrExposureMode:   exposureActive,
		attrExposureSource: exposureActive,
	}
	g.addObsEvidenceWithCurrentness(m, assetKey, "service_script_observed", "service_script_evidence",
		"script:"+e.Script+":"+target,
		fmt.Sprintf("%s collected script %s against %s.", m.Source, e.Script, target),
		ConfidenceMedium, liveVerifiedCurrentness(m.ObservationKind, true), md)
}

// applyTLSSecurity folds a TLS assessment as a typed facet on the assessed service.
// It is deliberately not folded onto a domain the way an HTTPS posture is: the
// assessment is about an endpoint and a server name, and a TLS-wrapped mail or
// directory service has no domain-level HTTPS meaning to inherit.
//
// The per-section states travel with the observation. Without them a consumer
// reading an empty vulnerability list could not tell a clean endpoint from one
// SSLyze never got to, which is the single most misleading thing a TLS report can do.
func (g *Graph) applyTLSSecurity(e events.TlsSecurityAssessed) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid TLS assessment IP %q", e.IP), RawEventID: m.EventID})
		return
	}
	if e.Port < 1 || e.Port > 65535 {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid TLS assessment port %d on %s", e.Port, ip), RawEventID: m.EventID})
		return
	}
	g.ensureIP(m, ip, version)
	sid := entities.NewServiceID(ip, e.Port, entities.ProtocolTCP).String()

	names := assessedServerNames(e)
	md := map[string]any{
		attrServerName:        e.ServerName,
		attrAssessedNames:     names,
		"protocols":           append([]string(nil), e.Protocols...),
		"cipher_count":        e.CipherCount,
		"chain_count":         e.ChainCount,
		"lowest_protocol":     e.LowestProtocol,
		"min_strength":        e.MinStrength,
		"vulnerabilities":     append([]string(nil), e.Vulnerabilities...),
		"cipher_state":        string(e.CipherState),
		"chain_state":         string(e.ChainState),
		"settings_state":      string(e.SettingsState),
		"vulnerability_state": string(e.VulnerabilityState),
		"curve_state":         string(e.CurveState),
		attrTruncated:         e.Truncated,
	}
	for _, name := range names {
		g.ensureDomain(m, name)
	}

	// The discriminator separates the assessments of one socket. It is the covered
	// names rather than the reported one, because a producer that measured several
	// names and reported one result leaves the reported name empty; two such
	// results on one socket, each covering names the producer could not identify,
	// are indistinguishable here and fold together. The event log keeps both.
	disc := "tls_security:" + sid
	if len(names) > 0 {
		disc += ":" + strings.Join(names, ",")
	}
	g.addObsEvidenceWithCurrentness(m, sid, "tls_security_assessed", "tls_security_evidence", disc,
		tlsAssessmentStatement(m.Source, sid, e), ConfidenceHigh,
		liveVerifiedCurrentness(m.ObservationKind, e.CipherState == events.AssessmentTested), md)
}

// assessedServerNames returns the real server names a TLS assessment covers,
// sorted and free of addresses. A scanner reports the address itself as the server
// name for the connection it makes without SNI, and treating that as a domain would
// put an address into the graph as a name that does not exist.
func assessedServerNames(e events.TlsSecurityAssessed) []string {
	in := e.AssessedNames
	if len(in) == 0 && e.ServerName != "" {
		in = []string{e.ServerName}
	}
	out := make([]string, 0, len(in))
	for _, name := range in {
		if _, _, isIP := normalizeIP(name); name != "" && !isIP {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// tlsAssessmentStatement renders the human-readable claim. An assessment where
// nothing was tested says so instead of reporting zero findings, because "0
// vulnerabilities" and "nothing was checked" must not read the same.
func tlsAssessmentStatement(source, sid string, e events.TlsSecurityAssessed) string {
	target := sid
	if names := assessedServerNames(e); len(names) > 0 {
		target = sid + " (" + strings.Join(names, ", ") + ")"
	}
	if e.CipherState != events.AssessmentTested && e.VulnerabilityState != events.AssessmentTested {
		return fmt.Sprintf("%s could not assess TLS on %s: ciphers %s, vulnerabilities %s.",
			source, target, e.CipherState, e.VulnerabilityState)
	}
	return fmt.Sprintf("%s assessed TLS on %s: %d cipher(s), %d chain(s), %d issue(s).",
		source, target, e.CipherCount, e.ChainCount, len(e.Vulnerabilities))
}

// applySSHPosture folds the SSH algorithm offer as a typed facet on the service.
// The lists are the server's offer, so the statement says offered rather than
// negotiated: the exposure is in what the server is willing to accept.
func (g *Graph) applySSHPosture(e events.SshPostureDiscovered) {
	m := e.Meta()
	ip, version, ok := normalizeIP(e.IP)
	if !ok {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid SSH posture IP %q", e.IP), RawEventID: m.EventID})
		return
	}
	if e.Port < 1 || e.Port > 65535 {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: fmt.Sprintf("invalid SSH posture port %d on %s", e.Port, ip), RawEventID: m.EventID})
		return
	}
	g.ensureIP(m, ip, version)
	sid := entities.NewServiceID(ip, e.Port, entities.ProtocolTCP).String()

	md := map[string]any{
		"protocol_version":     e.ProtocolVersion,
		"key_exchange":         append([]string(nil), e.KeyExchange...),
		"host_key":             append([]string(nil), e.HostKey...),
		"encryption":           append([]string(nil), e.Encryption...),
		"mac":                  append([]string(nil), e.Mac...),
		"compression":          append([]string(nil), e.Compression...),
		"auth_mechanisms":      append([]string(nil), e.AuthMechanisms...),
		"guessed_key_exchange": e.GuessedKeyExchange,
		attrTruncated:          e.Truncated,
	}
	g.addObsEvidenceWithCurrentness(m, sid, "ssh_posture_observed", "ssh_posture_evidence",
		"ssh_posture:"+sid,
		fmt.Sprintf("%s read the SSH offer of %s: %d key exchange, %d cipher(s), %d auth mechanism(s).",
			m.Source, sid, len(e.KeyExchange), len(e.Encryption), len(e.AuthMechanisms)),
		ConfidenceHigh, liveVerifiedCurrentness(m.ObservationKind, true), md)
}
