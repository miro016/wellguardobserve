package projections

import (
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// weakCipherStrength is the symmetric strength below which an accepted suite is
// listed as weak. It is the same 128-bit floor the upstream scanners apply for
// their own low-strength flag, restated here because the projection must reach the
// same verdict whichever tool reported the suite.
const weakCipherStrength = 128

// weakCipherAlgorithms are the symmetric algorithms whose presence makes a suite
// unacceptable regardless of key size: a broken stream cipher and a 64-bit block
// cipher whose birthday bound is reachable in a single long-lived connection.
var weakCipherAlgorithms = map[string]bool{
	"RC4": true, "3DES": true, "DES": true, "IDEA": true, "NULL": true, "RC2": true,
}

// anonymousAuthentication marks a suite that authenticates nobody, so the
// handshake it protects can be trivially intercepted.
const anonymousAuthentication = "anon"

// applyHostProfile folds the host-level evidence onto the address it is about. The
// profile is replaced rather than merged field by field: it is one scanner's
// coherent picture of a host at one moment, and interleaving two scanners' guesses
// would produce a profile neither of them reported. The contributing sources
// accumulate, so the attribution is not lost.
func (inv *Inventory) applyHostProfile(e events.HostProfileObserved) {
	ipNode := inv.ensureIPNode(e.IP)
	inv.addProvenance(&ipNode.Provenance, e.Meta())

	sources := []string{e.Meta().Source}
	if ipNode.Profile != nil {
		sources = unionSortedStrings(ipNode.Profile.Sources, sources)
	}
	ipNode.Profile = &entities.HostProfile{
		DnsName:         e.DnsName,
		OtherNames:      append([]string(nil), e.OtherNames...),
		OtherIPs:        append([]string(nil), e.OtherIPs...),
		MacAddress:      e.MacAddress,
		OSCandidates:    append([]string(nil), e.OSCandidates...),
		OSFromService:   e.OSFromService,
		LastBoot:        e.LastBoot,
		Uptime:          e.Uptime,
		DetectionReason: e.DetectionReason,
		TracerouteHops:  append([]string(nil), e.TracerouteHops...),
		Truncated:       e.Truncated,
		Sources:         sources,
	}
}

// applyServiceScript folds one script result onto the service it ran against. A
// host-scope script (port 0) has no service to attach to, so it lands on the
// address instead of being dropped: a host script that names the OS or the SMB
// dialect is evidence about the host.
func (inv *Inventory) applyServiceScript(e events.ServiceScriptObserved) {
	script := entities.ServiceScript{
		Script:      e.Script,
		Scope:       e.Scope,
		Output:      e.Output,
		RawBytes:    e.RawBytes,
		Digest:      e.Digest,
		Truncated:   e.Truncated,
		ParseStatus: string(e.ParseStatus),
		Source:      e.Meta().Source,
	}

	if e.Port == 0 {
		ipNode := inv.ensureIPNode(e.IP)
		inv.addProvenance(&ipNode.Provenance, e.Meta())
		ipNode.Scripts = upsertScript(ipNode.Scripts, script)
		return
	}

	svcNode, ok := inv.serviceNodeFor(e.IP, e.Port, e.Protocol)
	if !ok {
		return
	}
	inv.addProvenance(&svcNode.Provenance, e.Meta())
	svcNode.Scripts = upsertScript(svcNode.Scripts, script)
}

// applyTLSSecurity folds a TLS assessment onto the service that was assessed. The
// assessment list is keyed by server name, because one endpoint can present a
// different certificate and cipher selection per name and collapsing them would
// hide exactly the misconfiguration worth finding.
func (inv *Inventory) applyTLSSecurity(e events.TlsSecurityAssessed) {
	svcNode, ok := inv.serviceNodeFor(e.IP, e.Port, entities.ProtocolTCP)
	if !ok {
		return
	}
	inv.addProvenance(&svcNode.Provenance, e.Meta())

	assessment := tlsAssessmentFrom(e)
	for i := range svcNode.TLS {
		if svcNode.TLS[i].ServerName != assessment.ServerName {
			continue
		}
		assessment.Sources = unionSortedStrings(svcNode.TLS[i].Sources, assessment.Sources)
		svcNode.TLS[i] = assessment
		return
	}
	svcNode.TLS = append(svcNode.TLS, assessment)
	sort.SliceStable(svcNode.TLS, func(i, j int) bool { return svcNode.TLS[i].ServerName < svcNode.TLS[j].ServerName })
}

// tlsAssessmentFrom reduces the event to the folded summary. The full cipher table
// and certificate chains stay in the event stream, which is the audit record; what
// a report and a detector need is which versions are accepted, which suites should
// not be offered, whether the chain is trusted, and which sections ran at all.
func tlsAssessmentFrom(e events.TlsSecurityAssessed) entities.TlsAssessment {
	out := entities.TlsAssessment{
		ServerName:               e.ServerName,
		Protocols:                append([]string(nil), e.Protocols...),
		LowestProtocol:           e.LowestProtocol,
		MinStrength:              e.MinStrength,
		CipherCount:              e.CipherCount,
		WeakCiphers:              weakCipherNames(e.Ciphers),
		ForwardSecrecy:           allForwardSecret(e.Ciphers),
		ChainCount:               e.ChainCount,
		ChainTrusted:             chainsTrusted(e.Chains),
		ChainOrderValid:          chainsOrdered(e.Chains),
		Vulnerabilities:          append([]string(nil), e.Vulnerabilities...),
		ExtendedMasterSecret:     e.ExtendedMasterSecret,
		TLSFallbackSCSV:          e.TLSFallbackSCSV,
		SecureRenegotiation:      e.SecureRenegotiation,
		SessionResumptionID:      e.SessionResumptionID,
		SessionResumptionTickets: e.SessionResumptionTickets,
		MozillaCompliant:         e.MozillaCompliant,
		CipherState:              entities.AssessmentState(e.CipherState),
		ChainState:               entities.AssessmentState(e.ChainState),
		SettingsState:            entities.AssessmentState(e.SettingsState),
		VulnerabilityState:       entities.AssessmentState(e.VulnerabilityState),
		CurveState:               entities.AssessmentState(e.CurveState),
		Truncated:                e.Truncated,
		Sources:                  []string{e.Meta().Source},
	}
	if leaf, ok := leafCertificate(e.Chains); ok {
		out.LeafSubject = leaf.SubjectCN
		out.LeafIssuer = leaf.IssuerCN
		out.LeafSerial = leaf.Serial
		out.LeafValidUntil = leaf.ValidTo
	}
	return out
}

// weakCipherNames lists the accepted suites that should not be offered at all,
// sorted. A suite qualifies on any of four independent grounds, so the list is a
// union rather than a first-match classification.
func weakCipherNames(ciphers []events.TlsCipherSuite) []string {
	var weak []string
	for _, c := range ciphers {
		if isWeakCipher(c) {
			weak = append(weak, c.Name)
		}
	}
	sort.Strings(weak)
	return dedupSortedStrings(weak)
}

// isWeakCipher reports whether one accepted suite should not be offered.
func isWeakCipher(c events.TlsCipherSuite) bool {
	if c.Export || c.Draft {
		return true
	}
	if weakCipherAlgorithms[strings.ToUpper(strings.TrimSpace(c.Encryption))] {
		return true
	}
	if strings.Contains(strings.ToLower(c.Authentication), anonymousAuthentication) {
		return true
	}
	// A strength of zero means the producer rated nothing, which is not the same as
	// rating it weak, so only a positive rating below the floor counts.
	return c.Strength > 0 && c.Strength < weakCipherStrength
}

// allForwardSecret reports whether every accepted suite provides forward secrecy.
// With no accepted suites it reports false: nothing was proven, and claiming
// forward secrecy for an endpoint that negotiated nothing would be the same
// mistake as reading an untested check as a passed one.
func allForwardSecret(ciphers []events.TlsCipherSuite) bool {
	if len(ciphers) == 0 {
		return false
	}
	for _, c := range ciphers {
		if !c.ForwardSecrecy {
			return false
		}
	}
	return true
}

// chainsTrusted reports whether every presented chain was accepted by at least one
// trust store. An endpoint presenting no chain reports false, for the same reason
// allForwardSecret does.
func chainsTrusted(chains []events.TlsCertificateChain) bool {
	if len(chains) == 0 {
		return false
	}
	for _, c := range chains {
		if len(c.ValidatedBy) == 0 {
			return false
		}
	}
	return true
}

// chainsOrdered reports whether every presented chain was sent in a valid order.
func chainsOrdered(chains []events.TlsCertificateChain) bool {
	if len(chains) == 0 {
		return false
	}
	for _, c := range chains {
		if !c.ValidOrder {
			return false
		}
	}
	return true
}

// leafCertificate returns the leaf of the first presented chain, falling back to
// the first certificate when no role is labelled, which is where a correctly
// ordered chain puts it.
func leafCertificate(chains []events.TlsCertificateChain) (events.TlsChainCertificate, bool) {
	for _, chain := range chains {
		for _, c := range chain.Certificates {
			if strings.EqualFold(c.Role, "leaf") {
				return c, true
			}
		}
		if len(chain.Certificates) > 0 {
			return chain.Certificates[0], true
		}
	}
	return events.TlsChainCertificate{}, false
}

// applySSHPosture folds the SSH algorithm offer onto the service. A later
// observation replaces the earlier one for the same reason a host profile does: it
// is one handshake's coherent offer, and merging two would describe a server that
// offered neither list.
func (inv *Inventory) applySSHPosture(e events.SshPostureDiscovered) {
	svcNode, ok := inv.serviceNodeFor(e.IP, e.Port, entities.ProtocolTCP)
	if !ok {
		return
	}
	inv.addProvenance(&svcNode.Provenance, e.Meta())

	sources := []string{e.Meta().Source}
	if svcNode.SSH != nil {
		sources = unionSortedStrings(svcNode.SSH.Sources, sources)
	}
	svcNode.SSH = &entities.SshPosture{
		ProtocolVersion:    e.ProtocolVersion,
		Banner:             e.Banner,
		KeyExchange:        append([]string(nil), e.KeyExchange...),
		HostKey:            append([]string(nil), e.HostKey...),
		Encryption:         append([]string(nil), e.Encryption...),
		Mac:                append([]string(nil), e.Mac...),
		Compression:        append([]string(nil), e.Compression...),
		AuthMechanisms:     append([]string(nil), e.AuthMechanisms...),
		GuessedKeyExchange: e.GuessedKeyExchange,
		Truncated:          e.Truncated,
		Sources:            sources,
	}
}

// serviceNodeFor resolves the service an assessment belongs to, creating it when a
// module reported on a port no discovery event covered. That happens when the
// assessing tool is enabled and the discovering one is not, and dropping the
// assessment because the port was never separately announced would lose the whole
// observation.
func (inv *Inventory) serviceNodeFor(ip string, port int, protocol string) (*ServiceNode, bool) {
	if protocol == "" {
		protocol = entities.ProtocolTCP
	}
	key := serviceKey(ip, port, protocol)
	if node, ok := inv.Services[key]; ok {
		return node, true
	}
	svc, err := entities.NewService(ip, port, protocol)
	if err != nil {
		return nil, false
	}
	node := &ServiceNode{Service: svc}
	inv.Services[key] = node
	inv.ensureIPNode(ip).Services = appendUnique(inv.ensureIPNode(ip).Services, key)
	return node, true
}

// upsertScript adds or replaces a script result, keeping the list ordered by script
// name so the projection is byte-identical whatever order the events arrived in.
// A repeat of the same script from the same source replaces the earlier result: it
// is the same observation, not a second one.
func upsertScript(scripts []entities.ServiceScript, script entities.ServiceScript) []entities.ServiceScript {
	for i := range scripts {
		if scripts[i].Script == script.Script && scripts[i].Source == script.Source {
			scripts[i] = script
			return scripts
		}
	}
	scripts = append(scripts, script)
	sort.SliceStable(scripts, func(i, j int) bool {
		if scripts[i].Script != scripts[j].Script {
			return scripts[i].Script < scripts[j].Script
		}
		return scripts[i].Source < scripts[j].Source
	})
	return scripts
}

// mergeServiceIdentity folds a second observation of a service into the node. An
// empty field is enriched from the later evidence; a field that already holds a
// different non-empty value keeps it and records the disagreement, so neither
// observation is lost and neither tool silently overwrites the other.
func mergeServiceIdentity(svc *entities.Service, e events.ServiceDiscovered) {
	m := e.Meta()
	mergeServiceName(svc, e.Service, m)
	for _, f := range []struct {
		name  string
		field *string
		value string
	}{
		{"product", &svc.Product, e.Product},
		{"version", &svc.Version, e.Version},
		{"extra_info", &svc.ExtraInfo, e.ExtraInfo},
	} {
		if f.value == "" || f.value == *f.field {
			continue
		}
		if *f.field == "" {
			*f.field = f.value
			continue
		}
		svc.Conflicts = appendConflict(svc.Conflicts, entities.FieldObservation{
			Field: f.name, Value: f.value, Source: m.Source, ObservedAt: m.CapturedAt,
		})
	}
	// A banner is a sample, not a claim about the service's identity: it is what
	// this probe read from this socket at this moment. Two tools reading
	// "HTTP/1.1 404" and "HTTP/1.1 302 Found" are both right and are not
	// disagreeing, so every banner is kept as its own observation rather than the
	// second one being filed as a conflict with the first.
	svc.Banners = appendBanner(svc.Banners, entities.FieldObservation{
		Field: "banner", Value: e.Banner, Source: m.Source, ObservedAt: m.CapturedAt,
	})
	if svc.Banner == "" {
		svc.Banner = e.Banner
	}
	// Platform identifiers are a set, not a single claim: two tools reporting
	// different CPEs for one service are both right about what they matched.
	svc.CPEs = unionSortedStrings(svc.CPEs, e.CPEs)
}

// mergeServiceName folds a newly observed service name into the node. It is kept
// out of the generic field merge because two service names can differ without
// disagreeing, and treating every difference as a conflict filled the report with
// disagreements no operator could act on.
//
// Two names contradict each other only when they name different application
// protocols. "http" and "https", or "rtsp" and "rtsp/tls", are one socket described
// at two layers: one producer names the protocol, another names it and says it is
// wrapped in TLS. Both are right, so the qualified reading simply wins as the more
// specific of the two rather than being recorded as the loser of a conflict.
//
// A name that identifies nothing is not a claim at all. nmap writes "tcpwrapped"
// when the handshake completed but the peer closed without answering, and "unknown"
// when nothing it recognises came back; neither displaces a real name, and neither
// contests one.
func mergeServiceName(svc *entities.Service, name string, m events.EventMeta) {
	if name == "" || name == svc.Name || !serviceNameIsAnswer(name) {
		return
	}
	if svc.Name == "" || !serviceNameIsAnswer(svc.Name) {
		svc.Name = name
		return
	}
	if serviceNameProtocol(svc.Name) == serviceNameProtocol(name) {
		if serviceNameSaysTLS(name) {
			svc.Name = name
		}
		return
	}
	svc.Conflicts = appendConflict(svc.Conflicts, entities.FieldObservation{
		Field: "name", Value: name, Source: m.Source, ObservedAt: m.CapturedAt,
	})
}

// serviceNameProtocol reduces a service name to the application protocol it names,
// dropping any transport qualification. Producers here write that qualification two
// ways - a "/tls" suffix, and "https" for HTTP over TLS - so both reduce to the bare
// protocol and names that differ only in it compare equal.
func serviceNameProtocol(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "https" {
		return "http"
	}
	return strings.TrimSuffix(n, "/tls")
}

// serviceNameSaysTLS reports whether a service name carries the transport
// qualification, which makes it the more specific of two names for one protocol.
func serviceNameSaysTLS(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n != serviceNameProtocol(n)
}

// serviceNameIsAnswer reports whether a service name identifies anything at all.
func serviceNameIsAnswer(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "tcpwrapped", "unknown":
		return false
	}
	return true
}

// appendBanner records one banner reading once, keeping the list ordered by source
// then value so the projection is byte-identical whatever order the events arrived
// in. The same source reading the same bytes twice is one observation, so a replay
// does not grow the list.
func appendBanner(banners []entities.FieldObservation, b entities.FieldObservation) []entities.FieldObservation {
	if b.Value == "" {
		return banners
	}
	for _, existing := range banners {
		if existing.Value == b.Value && existing.Source == b.Source {
			return banners
		}
	}
	banners = append(banners, b)
	sort.SliceStable(banners, func(i, j int) bool {
		if banners[i].Source != banners[j].Source {
			return banners[i].Source < banners[j].Source
		}
		return banners[i].Value < banners[j].Value
	})
	return banners
}

// appendConflict records a disagreement once. The same source reporting the same
// value for the same field twice is one observation, so a replay does not grow the
// list.
func appendConflict(conflicts []entities.FieldObservation, c entities.FieldObservation) []entities.FieldObservation {
	for _, existing := range conflicts {
		if existing.Field == c.Field && existing.Value == c.Value && existing.Source == c.Source {
			return conflicts
		}
	}
	conflicts = append(conflicts, c)
	sort.SliceStable(conflicts, func(i, j int) bool {
		if conflicts[i].Field != conflicts[j].Field {
			return conflicts[i].Field < conflicts[j].Field
		}
		if conflicts[i].Source != conflicts[j].Source {
			return conflicts[i].Source < conflicts[j].Source
		}
		return conflicts[i].Value < conflicts[j].Value
	})
	return conflicts
}

// dedupSortedStrings removes adjacent duplicates from a sorted list.
func dedupSortedStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
