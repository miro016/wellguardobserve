package goscans

import (
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/upstream"
)

// tlsAssessment reduces one upstream virtual-host assessment to the bounded event
// payload. Everything upstream reports is either carried, derived into a carried
// field, or left behind deliberately; the reasons are on the event's own fields.
//
// It never invents a value for a section SSLyze did not produce: the three Known
// flags say which sections exist, so an absent section can never be read as a
// clean one.
func (a *Actor) tlsAssessment(ip string, port int, data *upstream.SSLData) TLSAssessed {
	out := TLSAssessed{IP: ip, Port: port, Vhost: data.Vhost}

	ciphers, protocols, cipherCount, cipherTrunc := a.tlsCiphers(data)
	out.Ciphers, out.Protocols, out.CipherCount = ciphers, protocols, cipherCount

	chains, chainCount, chainTrunc := a.tlsChains(data)
	out.Chains, out.ChainCount = chains, chainCount

	settingsTrunc := false
	if data.Settings != nil {
		out.SettingsKnown = true
		out.Settings = TLSSettings{
			LowestProtocol:           data.Settings.LowestProtocol.String(),
			MinStrength:              data.Settings.MinStrength,
			ExtendedMasterSecret:     data.Settings.Ems,
			TLSFallbackSCSV:          data.Settings.TlsFallbackScsv,
			SecureRenegotiation:      data.Settings.SecureRenegotiation,
			SessionResumptionID:      data.Settings.SessionResumptionWithId,
			SessionResumptionTickets: data.Settings.SessionResumptionWithTickets,
			MozillaCompliant:         data.Settings.IsCompliantToMozillaConfig,
		}
	}
	if data.Issues != nil {
		out.IssuesKnown = true
		out.Issues = issueNames(data.Issues)
	}
	if data.Curves != nil {
		out.CurvesKnown = true
		out.ECDHKeyExchange = data.Curves.SupportEcdhKeyExchange
		var supTrunc, rejTrunc bool
		out.SupportedCurves, supTrunc = a.curveNames(data.Curves.SupportedCurves)
		out.RejectedCurves, rejTrunc = a.curveNames(data.Curves.RejectedCurves)
		settingsTrunc = supTrunc || rejTrunc
	}

	out.Truncated = cipherTrunc || chainTrunc || settingsTrunc
	return out
}

// tlsCiphers reduces the accepted-suite map to a sorted, capped list and derives
// the distinct protocol versions from it. Upstream keys the map by
// "protocol|cipher_id", so map order is not stable and the sort is what makes two
// scans of the same server produce the same event.
//
// Upstream models every algorithm slot as a small integer enum with a generated
// String method, so each one is rendered through String rather than converted:
// converting the integer directly would yield a control character, not a name.
func (a *Actor) tlsCiphers(data *upstream.SSLData) (out []TLSCipher, protocols []string, count int, truncated bool) {
	seenProtocol := make(map[string]struct{}, 4)

	all := make([]TLSCipher, 0, len(data.Ciphers))
	for _, c := range data.Ciphers {
		if c == nil {
			continue
		}
		name := c.IanaName
		if name == "" {
			name = c.OpensslName
		}
		protocol := c.Protocol.String()
		if protocol != "" {
			seenProtocol[protocol] = struct{}{}
		}
		suite := TLSCipher{
			Protocol:       protocol,
			Name:           name,
			KeyExchange:    c.KeyExchange.String(),
			Authentication: c.Authentication.String(),
			Encryption:     c.Encryption.String(),
			Mac:            c.Mac.String(),
			EncryptionBits: c.EncryptionBits,
			Strength:       c.EncryptionStrength,
			ForwardSecrecy: c.ForwardSecrecy,
			Export:         c.Export,
			Draft:          c.Draft,
		}
		if kex, secret, ok := keyExchangeOf(c.IanaName, protocol); ok {
			suite.KeyExchange, suite.ForwardSecrecy = kex, secret
		}
		all = append(all, suite)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Protocol != all[j].Protocol {
			return all[i].Protocol < all[j].Protocol
		}
		return all[i].Name < all[j].Name
	})
	all = dedupSuites(all)
	count = len(all)

	protocols = make([]string, 0, len(seenProtocol))
	for p := range seenProtocol {
		protocols = append(protocols, p)
	}
	sort.Strings(protocols)

	if limit := a.cfg.Limits.MaxCiphers; len(all) > limit {
		return all[:limit], protocols, count, true
	}
	return all, protocols, count, false
}

// dedupSuites collapses repeats of one suite in an already-sorted list.
//
// Upstream keys its suite table by OpenSSL name and appends every entry sharing
// one, so a single negotiated suite can come back several times. Left alone the
// repeats reach the reader twice over: as an inflated suite count, and as evidence
// naming the same weak suite once per copy, which reads as several weaknesses.
//
// A protocol and a name together identify a suite. The same name under two protocol
// versions is two real acceptances and both are kept.
func dedupSuites(sorted []TLSCipher) []TLSCipher {
	out := sorted[:0]
	for i, c := range sorted {
		if i > 0 && c.Protocol == sorted[i-1].Protocol && c.Name == sorted[i-1].Name {
			continue
		}
		out = append(out, c)
	}
	return out
}

// tlsProtocol13 is the scanner's name for TLS 1.3, and keyExchangeTLS13 the key
// exchange reported for its suites: the version negotiates the key exchange outside
// the suite, so the suite name cannot state it and the set of possibilities is
// named instead.
const (
	tlsProtocol13    = "TLSv1.3"
	keyExchangeTLS13 = "(EC)DHE / PSK / PSK + (EC)DHE"
)

// forwardSecretKeyExchanges are the key exchanges that give a session forward
// secrecy: the ephemeral Diffie-Hellman variants, and MQV, which is ephemeral by
// construction.
var forwardSecretKeyExchanges = map[string]bool{"DHE": true, "ECDHE": true, "ECMQV": true}

// keyExchangeOf derives a suite's key exchange from its IANA name, and reports
// whether that key exchange provides forward secrecy. The third result is false
// when the name carries no key exchange the caller can act on.
//
// The name is the authority here rather than the scanner's own classification,
// because a scanner resolves the key exchange through a static suite table and such
// a table can be wrong: one shipped table types most ECDHE suites as static ECDH,
// which turns every suite that does provide forward secrecy into one that appears
// not to. The IANA name states the key exchange directly and cannot disagree with
// itself, so it is read instead.
//
// A TLS 1.3 suite names only its AEAD and hash, because the key exchange is
// negotiated separately and is always ephemeral, so the protocol answers for it.
// Anything else unrecognised is left to the caller's existing value: a name this
// cannot classify is not evidence that the scanner was wrong about it.
func keyExchangeOf(ianaName, protocol string) (kex string, forwardSecret, ok bool) {
	if protocol == tlsProtocol13 {
		return keyExchangeTLS13, true, true
	}
	const prefix, sep = "TLS_", "_WITH_"
	if !strings.HasPrefix(ianaName, prefix) {
		return "", false, false
	}
	cut := strings.Index(ianaName, sep)
	if cut < len(prefix) {
		return "", false, false
	}
	// The segment between the prefix and _WITH_ names the key exchange and then the
	// authentication; the key exchange is the first token of it.
	first, _, _ := strings.Cut(ianaName[len(prefix):cut], "_")
	if first == "" {
		return "", false, false
	}
	return first, forwardSecretKeyExchanges[first], true
}

// tlsChains reduces the presented certificate deployments, capping the number of
// chains and the certificates within each one against the same certificate limit:
// a server that sends fifty chains and a server that sends one fifty-deep chain
// are the same volume problem.
func (a *Actor) tlsChains(data *upstream.SSLData) (out []TLSChain, count int, truncated bool) {
	count = len(data.Chains)
	limit := a.cfg.Limits.MaxCertificates

	for i, chain := range data.Chains {
		if chain == nil {
			continue
		}
		if i >= limit {
			truncated = true
			break
		}
		validated := append([]string(nil), chain.ValidatedBy...)
		sort.Strings(validated)

		certs := make([]TLSCertificate, 0, len(chain.Certificates))
		for j, cert := range chain.Certificates {
			if cert == nil {
				continue
			}
			if j >= limit {
				truncated = true
				break
			}
			c, nameTrunc := a.tlsCertificate(cert)
			truncated = truncated || nameTrunc
			certs = append(certs, c)
		}
		out = append(out, TLSChain{
			ValidatedBy:  validated,
			ValidOrder:   chain.HasValidOrder,
			Certificates: certs,
		})
	}
	return out, count, truncated
}

// tlsCertificate reduces one certificate. The serial arrives as a big integer and
// is rendered as hexadecimal so it keys identically to the serial the certificate
// transparency sources report.
func (a *Actor) tlsCertificate(cert *upstream.SSLCertificate) (TLSCertificate, bool) {
	serial := cert.Serial
	names := append([]string(nil), cert.AlternativeNames...)
	for i := range names {
		names[i] = strings.ToLower(strings.TrimSpace(names[i]))
	}
	sort.Strings(names)
	names = dedupSorted(names)
	names, truncated := capStrings(names, a.cfg.Limits.MaxVhosts)

	return TLSCertificate{
		Role:               cert.Type,
		SubjectCN:          cert.SubjectCN,
		IssuerCN:           cert.IssuerCN,
		Serial:             serial.Text(16),
		AlternativeNames:   names,
		ValidFrom:          cert.ValidFrom,
		ValidTo:            cert.ValidTo,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      cert.PublicKeyBits,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SignatureHash:      cert.SignatureHashAlgorithm.String(),
		SHA1Fingerprint:    cert.Sha1Fingerprint,
		CA:                 cert.Ca,
		Truncated:          truncated,
	}, truncated
}

// curveNames reduces an elliptic-curve list to sorted, capped names. The OpenSSL
// NID upstream also carries is dropped: it identifies the same curve the name
// already does, in a form only OpenSSL uses.
func (a *Actor) curveNames(curves []upstream.SSLEllipticCurve) ([]string, bool) {
	names := make([]string, 0, len(curves))
	for _, c := range curves {
		if c.Name != "" {
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	return capStrings(dedupSorted(names), a.cfg.Limits.MaxSSHAlgorithms)
}

// isWildcardSample reports whether name is a label upstream discovery generated
// rather than a name any host answered to.
//
// A wildcard certificate name is expanded into two entries: the base name, which the
// certificate really covers and which is worth keeping, and a "wildcard." sample of
// the same base, which exists only to drive upstream's own wildcard detection. That
// sample names no host. Forwarding it would put a host that does not exist into the
// inventory, and because discovery is an active probe it would arrive as live
// evidence rather than as a guess.
//
// The sample is recognised by the pair upstream always emits together: a "wildcard."
// prefix whose remainder is itself one of the names this host reported. Matching the
// prefix alone would discard a real host that happens to carry that label, so the
// base name has to be present for the pair to be the generated one. A host genuinely
// answering to both a name and that name prefixed with "wildcard." would lose the
// prefixed one, which is the safer direction to be wrong in: the base name survives
// either way, and no invented host reaches the inventory.
func isWildcardSample(name string, reported map[string]bool) bool {
	base, ok := strings.CutPrefix(name, "wildcard.")
	return ok && reported[base]
}

// dedupSorted removes adjacent duplicates from an already-sorted list.
func dedupSorted(in []string) []string {
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
