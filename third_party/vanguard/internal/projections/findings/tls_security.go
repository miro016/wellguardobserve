package findings

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// Catalogue references shared by the cryptographic rules. CWE-327 is "use of a
// broken or risky cryptographic algorithm", which is the same weakness whether the
// algorithm is a TLS suite or an SSH cipher, so both rule families cite it.
const (
	cweBrokenCrypto = "CWE-327"
	cweWeakStrength = "CWE-326"
)

// deprecatedTLSProtocols maps a protocol version a server should no longer accept
// to the severity of still accepting it. SSLv2 and SSLv3 are broken outright; TLS
// 1.0 and 1.1 are deprecated and fail every current compliance baseline.
var deprecatedTLSProtocols = map[string]events.Severity{
	"SSLv2":   events.SeverityHigh,
	"SSLv3":   events.SeverityHigh,
	"TLSv1.0": events.SeverityHigh,
	"TLSv1.1": events.SeverityMedium,
}

// tlsVulnerabilitySeverity maps the named checks a TLS scanner reports to the
// severity of a positive result. A check absent from this table is still reported,
// at medium, rather than dropped: a scanner that gained a new check must not go
// quiet, and under-rating a real positive is safer than hiding it.
//
// Lucky13 sits at low rather than medium because the check behind it proves less
// than its name suggests. A scanner reports it from the accepted suite list alone -
// any CBC suite on a protocol older than TLS 1.3 - which measures what the endpoint
// offers, not whether its padding check leaks timing. The distinction matters here
// because the weaker reading is the common one: the flag fires on most endpoints
// that still offer CBC at all, and rating that medium would drown the checks that
// were actually measured.
var tlsVulnerabilitySeverity = map[string]events.Severity{
	"Heartbleed":             events.SeverityCritical,
	"CcsInjection":           events.SeverityCritical,
	"Drown":                  events.SeverityCritical,
	"Freak":                  events.SeverityHigh,
	"Logjam":                 events.SeverityHigh,
	"Robot":                  events.SeverityHigh,
	"Poodle":                 events.SeverityHigh,
	"Crime":                  events.SeverityHigh,
	"Beast":                  events.SeverityMedium,
	"Sweet32":                events.SeverityMedium,
	"ClientRenegotiationDos": events.SeverityMedium,
	"Lucky13":                events.SeverityLow,
	"EarlyDataSupported":     events.SeverityLow,
}

// tlsVulnerabilityRefuted holds the checks whose scanner-side test is weaker than
// the vulnerability it names, paired with the evidence that positively refutes a
// reported positive.
//
// A check listed here is dropped only when the assessment proves the vulnerability
// cannot apply. An assessment that could not answer leaves the claim standing,
// because "nothing refuted this" and "this was checked and is fine" are different
// statements and only the second may silence a finding.
var tlsVulnerabilityRefuted = map[string]func(events.TlsSecurityAssessed) bool{
	"Freak": freakRefuted,
}

// freakRefuted reports whether an assessment proves FREAK cannot apply to the
// endpoint.
//
// FREAK is a downgrade onto 512-bit export-grade RSA, so it needs the endpoint to
// offer an RSA_EXPORT suite. A scanner may not test that: the common test is an RSA
// key exchange whose key size is at most 512 bits, and the key size is left at zero
// for every suite that is neither ephemeral nor export. Zero is at most 512, so
// every endpoint offering an ordinary RSA suite is reported vulnerable, which is a
// high-severity finding on a configuration that cannot be downgraded at all.
//
// Refuting it needs the whole suite list rather than a sample. A capped list that
// happens to contain no export suite says nothing about the suites it dropped, and
// a list that was never enumerated says nothing at all, so both leave the finding
// in place for a human to judge.
func freakRefuted(e events.TlsSecurityAssessed) bool {
	if e.CipherState != events.AssessmentTested || len(e.Ciphers) != e.CipherCount {
		return false
	}
	for _, c := range e.Ciphers {
		if c.Export {
			return false
		}
	}
	return true
}

// tlsProtocolIssues are the upstream issue flags that restate protocol support the
// Protocols list already carries. They are excluded from the vulnerability rule so
// one weakness does not raise two findings; weak-tls-version owns them.
var tlsProtocolIssues = map[string]bool{
	"Sslv2Enabled": true, "Sslv3Enabled": true, "Tlsv1_0Enabled": true, "Tlsv1_1Enabled": true,
}

// tlsCipherIssues are the upstream issue flags that restate a cipher weakness the
// weak-cipher rule derives from the suite list itself. Excluded for the same reason.
var tlsCipherIssues = map[string]bool{
	"Rc4Enabled": true, "ExportSuite": true, "DraftSuite": true,
	"LowEncryptionStrength": true, "NoPerfectForwardSecrecy": true,
	"Md2Enabled": true, "Md5Enabled": true, "Sha1Enabled": true,
}

// tlsChainIssues are the upstream issue flags the chain rule owns.
var tlsChainIssues = map[string]bool{
	"AnyChainInvalid": true, "AnyChainInvalidOrder": true,
}

// WeakTLSSecurityVersion raises a finding when an assessed TLS endpoint still
// accepts a deprecated protocol version. It shares the weak-tls-version rule ID
// with the HTTPS-posture rule on purpose: it is the same weakness, so when both an
// HTTPS probe and a service-level assessment prove it for one asset the projection
// folds them into one finding with both tools' provenance rather than two
// tool-prefixed duplicates.
func WeakTLSSecurityVersion(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsSecurityAssessed)
	if !ok || e.CipherState != events.AssessmentTested {
		return nil
	}
	var weak []string
	severity := events.SeverityInfo
	for _, p := range e.Protocols {
		sev, deprecated := deprecatedTLSProtocols[p]
		if !deprecated {
			continue
		}
		weak = append(weak, p)
		if sev > severity {
			severity = sev
		}
	}
	if len(weak) == 0 {
		return nil
	}
	sort.Strings(weak)

	kind, id := tlsAsset(e)
	f := events.FindingRaised{
		Rule:            "weak-tls-version",
		Title:           "Deprecated TLS protocol version supported",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       kind,
		AssetID:         id,
		Evidence:        fmt.Sprintf("%s still negotiates %s", tlsTarget(e), strings.Join(weak, ", ")),
		Recommendation:  "Disable SSLv2/SSLv3/TLS 1.0/1.1 and require TLS 1.2 or higher.",
		References:      []string{cweWeakStrength},
	}
	f.Severity = severity
	return []events.FindingRaised{f}
}

// WeakTLSCipher raises a finding when an assessed endpoint accepts a cipher suite
// that should not be offered: an export or draft suite, a broken or 64-bit cipher,
// an anonymous key exchange, or one rated below the strength floor.
func WeakTLSCipher(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsSecurityAssessed)
	if !ok || e.CipherState != events.AssessmentTested || len(e.Ciphers) == 0 {
		return nil
	}
	weak := weakSuiteNames(e.Ciphers)
	if len(weak) == 0 {
		return nil
	}
	kind, id := tlsAsset(e)
	f := events.FindingRaised{
		Rule:            "weak-tls-cipher",
		Title:           "Weak TLS cipher suite accepted",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       kind,
		AssetID:         id,
		Evidence: fmt.Sprintf("%s accepts %d weak cipher suite(s): %s",
			tlsTarget(e), len(weak), strings.Join(capList(weak), ", ")),
		Recommendation: "Remove export, draft, RC4, 3DES, anonymous, and sub-128-bit suites from the accepted set.",
		References:     []string{cweBrokenCrypto},
	}
	f.Severity = events.SeverityMedium
	return []events.FindingRaised{f}
}

// TLSNoForwardSecrecy raises a finding when an assessed endpoint accepts at least
// one suite without forward secrecy: recorded traffic stays decryptable to anyone
// who later obtains the server key.
func TLSNoForwardSecrecy(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsSecurityAssessed)
	if !ok || e.CipherState != events.AssessmentTested || len(e.Ciphers) == 0 {
		return nil
	}
	var without []string
	for _, c := range e.Ciphers {
		if !c.ForwardSecrecy {
			without = append(without, c.Name)
		}
	}
	if len(without) == 0 {
		return nil
	}
	sort.Strings(without)

	kind, id := tlsAsset(e)
	f := events.FindingRaised{
		Rule:            "tls-no-forward-secrecy",
		Title:           "TLS suites without forward secrecy accepted",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       kind,
		AssetID:         id,
		Evidence: fmt.Sprintf("%s accepts %d suite(s) without forward secrecy: %s",
			tlsTarget(e), len(without), strings.Join(capList(without), ", ")),
		Recommendation: "Offer only ECDHE or DHE key exchange so recorded sessions stay unreadable after a key compromise.",
		References:     []string{"CWE-310"},
	}
	f.Severity = events.SeverityLow
	return []events.FindingRaised{f}
}

// TLSChainUntrusted raises a finding when a presented certificate chain is not
// accepted by any trust store, or is sent in the wrong order. It fires only when
// chain validation actually ran: an unassessed chain is a coverage gap, and
// reporting it as untrusted would be a fabricated finding.
//
// Trust is only judged for an assessment that covers at least one real server
// name. A scanner also connects without SNI and reports the address as the server
// name, and a certificate issued for a domain never validates against an address -
// so that chain comes back untrusted on every correctly configured server in the
// world. Reporting it would make the rule fire on healthy hosts and say nothing
// about the unhealthy ones. Chain order is independent of the name, so it is still
// judged.
func TLSChainUntrusted(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsSecurityAssessed)
	if !ok || e.ChainState != events.AssessmentTested || len(e.Chains) == 0 {
		return nil
	}
	byName := len(tlsServerNames(e)) > 0
	untrusted, misordered := 0, 0
	for _, c := range e.Chains {
		if byName && len(c.ValidatedBy) == 0 {
			untrusted++
		}
		if !c.ValidOrder {
			misordered++
		}
	}
	if untrusted == 0 && misordered == 0 {
		return nil
	}

	kind, id := tlsAsset(e)
	title, evidence, severity := "Certificate chain sent in invalid order",
		fmt.Sprintf("%s presents %d of %d chain(s) in the wrong order", tlsTarget(e), misordered, len(e.Chains)),
		events.SeverityLow
	if untrusted > 0 {
		title = "Certificate chain not trusted"
		evidence = fmt.Sprintf("%s presents %d of %d chain(s) that no trust store accepted",
			tlsTarget(e), untrusted, len(e.Chains))
		severity = events.SeverityHigh
	}
	f := events.FindingRaised{
		Rule:            "tls-certificate-chain-invalid",
		Title:           title,
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       kind,
		AssetID:         id,
		Evidence:        evidence,
		Recommendation:  "Serve the full chain in leaf-to-root order from a certificate a public trust store accepts.",
		References:      []string{"CWE-295"},
	}
	f.Severity = severity
	return []events.FindingRaised{f}
}

// TLSPostureChainUntrusted raises the same tls-certificate-chain-invalid finding
// from the HTTPS probe's own chain validation. It shares the rule ID and the domain
// asset with TLSChainUntrusted on purpose: a chain the service-level assessment
// also rejected is one weakness proven twice, and the projection folds the two into
// one finding carrying both tools' provenance rather than reporting two problems.
//
// Its value is the hosts the other rule never reaches. The HTTPS probe runs against
// every in-scope name; the service-level assessment runs only where its scanner ran,
// so without this rule a host it did not reach has no chain finding at all.
//
// It fires only when validation ran. A probe that never completed a handshake has
// judged nothing, and a false ChainTrusted there would be a fabricated finding.
func TLSPostureChainUntrusted(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsPostureDiscovered)
	if !ok || e.ChainState != events.AssessmentTested || e.ChainTrusted || e.Domain == "" {
		return nil
	}
	reason := e.ChainError
	if reason == "" {
		reason = "no path to a trusted root could be built from the certificates it served"
	}
	f := events.FindingRaised{
		Rule:            "tls-certificate-chain-invalid",
		Title:           "Certificate chain not trusted",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetDomain,
		AssetID:         e.Domain,
		Evidence:        fmt.Sprintf("%s presents a chain that did not validate: %s", e.Domain, reason),
		Recommendation:  "Serve the full chain in leaf-to-root order from a certificate a public trust store accepts.",
		References:      []string{"CWE-295"},
	}
	f.Severity = events.SeverityHigh
	return []events.FindingRaised{f}
}

// TLSKnownVulnerability raises one finding per named check that came back positive,
// so each weakness is separately triaged, dated, and closed. Flags that restate a
// protocol, cipher, or chain weakness another rule owns are excluded, so one
// underlying problem produces one finding. A check the assessment positively
// refutes is dropped rather than reported.
func TLSKnownVulnerability(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsSecurityAssessed)
	if !ok || e.VulnerabilityState != events.AssessmentTested {
		return nil
	}
	kind, id := tlsAsset(e)
	var out []events.FindingRaised
	for _, name := range e.Vulnerabilities {
		if tlsProtocolIssues[name] || tlsCipherIssues[name] || tlsChainIssues[name] {
			continue
		}
		if refuted, weak := tlsVulnerabilityRefuted[name]; weak && refuted(e) {
			continue
		}
		rule := tlsVulnerabilityRule(name)
		if rule == "" {
			continue
		}
		severity, known := tlsVulnerabilitySeverity[name]
		if !known {
			severity = events.SeverityMedium
		}
		f := events.FindingRaised{
			Rule:            rule,
			Title:           "TLS endpoint affected by " + name,
			FindingCategory: string(entities.FindingVulnerability),
			AssetKind:       kind,
			AssetID:         id,
			Evidence:        fmt.Sprintf("%s tested positive for %s", tlsTarget(e), name),
			Recommendation:  "Patch or reconfigure the TLS stack so the named check no longer applies.",
			References:      []string{cweBrokenCrypto},
		}
		f.Severity = severity
		out = append(out, f)
	}
	return out
}

// tlsVulnerabilityRule returns the stable rule ID for one named check, or "" when
// the name carries no usable identifier and so cannot be triaged.
//
// The vulnerability's own identity is part of the rule ID because findings fold by
// rule and asset. One shared ID keeps a single check per endpoint and drops the
// rest, and those are different vulnerabilities rather than duplicates of each
// other: an endpoint reported vulnerable to two things would lose the less severe
// one entirely, which is silent loss of a real weakness rather than deduplication.
//
// Names arrive as the scanner's own check identifiers in Go field-name form, so a
// word ends where a lowercase letter or digit is followed by an uppercase one, and
// anything that is not a letter or digit separates words. Digits stay attached to
// the word they follow, which keeps Sweet32 and Lucky13 whole.
func tlsVulnerabilityRule(name string) string {
	var words []string
	var word []rune
	flush := func() {
		if len(word) > 0 {
			words = append(words, string(word))
			word = word[:0]
		}
	}
	prevLower := false
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			if prevLower {
				flush()
			}
			word = append(word, r-'A'+'a')
			prevLower = false
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			word = append(word, r)
			prevLower = true
		default:
			flush()
			prevLower = false
		}
	}
	flush()
	if len(words) == 0 {
		return ""
	}
	return "tls-vuln-" + strings.Join(words, "-")
}

// TLSMissingHardening raises a finding when an assessed endpoint lacks the
// downgrade and renegotiation protections a current TLS stack should have. It fires
// only when the settings section was tested, because every field it reads is a
// boolean whose false value would otherwise be indistinguishable from "not asked".
func TLSMissingHardening(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.TlsSecurityAssessed)
	if !ok || e.SettingsState != events.AssessmentTested {
		return nil
	}
	var missing []string
	severity := events.SeverityLow
	if !e.SecureRenegotiation {
		missing = append(missing, "secure renegotiation")
		severity = events.SeverityMedium
	}
	if !e.TLSFallbackSCSV {
		missing = append(missing, "TLS_FALLBACK_SCSV")
	}
	if !e.ExtendedMasterSecret {
		missing = append(missing, "extended master secret")
	}
	if len(missing) == 0 {
		return nil
	}

	kind, id := tlsAsset(e)
	f := events.FindingRaised{
		Rule:            "tls-missing-hardening",
		Title:           "TLS downgrade and renegotiation protections missing",
		FindingCategory: string(entities.FindingMisconfig),
		AssetKind:       kind,
		AssetID:         id,
		Evidence:        fmt.Sprintf("%s does not support %s", tlsTarget(e), strings.Join(missing, ", ")),
		Recommendation:  "Enable secure renegotiation, TLS_FALLBACK_SCSV, and the extended master secret extension.",
		References:      []string{"CWE-757"},
	}
	f.Severity = severity
	return []events.FindingRaised{f}
}

// tlsAsset resolves which asset a TLS finding is about. An assessment that covers
// exactly one server name is about that name, which is the same asset the
// HTTPS-posture rules key on, so the two tools' findings for one rule fold
// together. Anything else keys on the service: an assessment of the bare endpoint
// is about the socket, and one covering several names at once belongs to no single
// name, so picking one would make the finding's identity depend on which name the
// producer happened to keep.
func tlsAsset(e events.TlsSecurityAssessed) (kind, id string) {
	if names := tlsServerNames(e); len(names) == 1 {
		return assetDomain, names[0]
	}
	return assetService, entities.NewServiceID(e.IP, e.Port, entities.ProtocolTCP).String()
}

// tlsServerNames returns the real server names an assessment covers, dropping the
// address a scanner reports for the connection it makes without SNI. AssessedNames
// is the producer's own statement of coverage; ServerName is read only when the
// producer supplied no list, which is how an assessment recorded before coverage
// was reported still resolves to its name.
func tlsServerNames(e events.TlsSecurityAssessed) []string {
	names := e.AssessedNames
	if len(names) == 0 && e.ServerName != "" {
		names = []string{e.ServerName}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" && !isIPLiteral(n) {
			out = append(out, n)
		}
	}
	return out
}

// isIPLiteral reports whether a server name is an address rather than a hostname.
//
// A TLS scanner reports the address itself as the server name for the connection
// it makes without SNI, so "188.123.96.172" arrives in the same field a real
// virtual host would. Keying a finding on it would file the finding against a
// domain asset that is not a domain, inventing a name that does not exist and
// splitting the service's findings across two assets.
func isIPLiteral(name string) bool {
	_, err := netip.ParseAddr(strings.Trim(name, "[]"))
	return err == nil
}

// tlsTarget renders the assessed endpoint for evidence text, naming both the server
// name and the address so a reader can tell which of several names on one address
// the finding is about. An assessment covering several names names them all, so the
// reader is not left thinking one arbitrary name was singled out.
func tlsTarget(e events.TlsSecurityAssessed) string {
	endpoint := fmt.Sprintf("%s:%d", e.IP, e.Port)
	switch names := tlsServerNames(e); {
	case len(names) == 1:
		return fmt.Sprintf("%s on %s", names[0], endpoint)
	case len(names) > 1:
		return fmt.Sprintf("%s under %s", endpoint, strings.Join(capList(names), ", "))
	}
	return endpoint
}

// weakSuiteNames lists the accepted suites that should not be offered, sorted.
func weakSuiteNames(ciphers []events.TlsCipherSuite) []string {
	var weak []string
	for _, c := range ciphers {
		if weakSuite(c) {
			weak = append(weak, c.Name)
		}
	}
	sort.Strings(weak)
	return weak
}

// weakSuite reports whether one accepted suite should not be offered. The grounds
// are independent, so any one of them is enough.
func weakSuite(c events.TlsCipherSuite) bool {
	if c.Export || c.Draft {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(c.Encryption)) {
	case "RC4", "3DES", "DES", "IDEA", "RC2", "NULL":
		return true
	}
	if strings.Contains(strings.ToLower(c.Authentication), "anon") {
		return true
	}
	// Strength zero means the producer rated nothing, which is not the same as
	// rating the suite weak, so only a positive rating below the floor counts.
	return c.Strength > 0 && c.Strength < 128
}

// evidenceListCap is how many items an evidence sentence names before summarizing
// the rest. Long enough to characterize what was found, short enough to stay one
// readable line.
const evidenceListCap = 8

// capList shortens a list for evidence text, saying how many were left out so the
// reader knows the list is not the whole set.
func capList(in []string) []string {
	if len(in) <= evidenceListCap {
		return in
	}
	out := append([]string(nil), in[:evidenceListCap]...)
	return append(out, fmt.Sprintf("and %d more", len(in)-evidenceListCap))
}
