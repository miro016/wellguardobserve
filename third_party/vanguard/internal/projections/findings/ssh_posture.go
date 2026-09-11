package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// weakSSHKeyExchange are key exchange algorithms a server should no longer offer:
// SHA-1 based exchanges, 1024-bit groups, and the RSA transport exchange that has
// no forward secrecy at all.
var weakSSHKeyExchange = map[string]bool{
	"diffie-hellman-group1-sha1":         true,
	"diffie-hellman-group14-sha1":        true,
	"diffie-hellman-group-exchange-sha1": true,
	"rsa1024-sha1":                       true,
	"gss-group1-sha1-":                   true,
}

// weakSSHHostKey are host key algorithms a server should no longer offer: DSA is
// limited to 1024 bits by the standard, and the SHA-1 RSA signature algorithm has
// been superseded by rsa-sha2-256 and rsa-sha2-512.
var weakSSHHostKey = map[string]bool{
	"ssh-dss": true, "ssh-rsa": true, "ssh-dss-cert-v01@openssh.com": true,
	"ssh-rsa-cert-v01@openssh.com": true,
}

// weakSSHCipher are encryption algorithms a server should no longer offer: the
// broken RC4 family, single DES, 64-bit block ciphers reachable by a birthday
// attack, and the CBC modes vulnerable to the SSH plaintext recovery attack.
var weakSSHCipher = map[string]bool{
	"arcfour": true, "arcfour128": true, "arcfour256": true,
	"3des-cbc": true, "des-cbc": true, "blowfish-cbc": true, "cast128-cbc": true,
	"aes128-cbc": true, "aes192-cbc": true, "aes256-cbc": true,
	"rijndael-cbc@lysator.liu.se": true, "none": true,
}

// weakSSHMac are message authentication algorithms a server should no longer
// offer: MD5, truncated digests, SHA-1, and the encrypt-and-MAC variants.
var weakSSHMac = map[string]bool{
	"hmac-md5": true, "hmac-md5-96": true, "hmac-md5-etm@openssh.com": true,
	"hmac-sha1": true, "hmac-sha1-96": true, "hmac-sha1-etm@openssh.com": true,
	"hmac-sha2-256-96": true, "hmac-sha2-512-96": true, "umac-64@openssh.com": true,
	"none": true,
}

// WeakSSHAlgorithm raises a finding when an SSH endpoint offers deprecated key
// exchange, host key, cipher, or MAC algorithms. It reads the server's offer, not a
// negotiated session: a server willing to accept a broken algorithm is exposed by
// the offer whatever a well-configured client would choose.
//
// An empty list is never a finding. An algorithm slot the scanner did not read is
// indistinguishable from one the server did not offer, and inventing a weakness
// from missing data is worse than missing one.
func WeakSSHAlgorithm(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.SshPostureDiscovered)
	if !ok {
		return nil
	}
	var weak []string
	for _, group := range []struct {
		label    string
		offered  []string
		rejected map[string]bool
	}{
		{"key exchange", e.KeyExchange, weakSSHKeyExchange},
		{"host key", e.HostKey, weakSSHHostKey},
		{"cipher", e.Encryption, weakSSHCipher},
		{"MAC", e.Mac, weakSSHMac},
	} {
		for _, alg := range group.offered {
			if group.rejected[strings.ToLower(strings.TrimSpace(alg))] {
				weak = append(weak, group.label+" "+alg)
			}
		}
	}
	if len(weak) == 0 {
		return nil
	}
	sort.Strings(weak)

	sid := entities.NewServiceID(e.IP, e.Port, entities.ProtocolTCP)
	f := events.FindingRaised{
		Rule:            "weak-ssh-algorithm",
		Title:           "SSH server offers deprecated algorithms",
		FindingCategory: string(entities.FindingMisconfig),
		AssetKind:       assetService,
		AssetID:         sid.String(),
		Evidence: fmt.Sprintf("%s:%d offers %d deprecated algorithm(s): %s",
			e.IP, e.Port, len(weak), strings.Join(capList(weak), ", ")),
		Recommendation: "Restrict the offered algorithms to current key exchanges, rsa-sha2/ed25519 host keys, AEAD ciphers, and encrypt-then-MAC digests.",
		References:     []string{cweBrokenCrypto},
	}
	f.Severity = events.SeverityMedium
	return []events.FindingRaised{f}
}

// SSHInsecureAuthentication raises a finding when an SSH endpoint offers an
// authentication mechanism that grants access without proving anything. "none" is
// the whole finding: it means the server will accept an unauthenticated session.
//
// Password authentication is deliberately not a finding. It is a deployment choice
// with legitimate uses, and flagging every password-accepting SSH server would bury
// the case that actually matters.
func SSHInsecureAuthentication(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.SshPostureDiscovered)
	if !ok {
		return nil
	}
	for _, mech := range e.AuthMechanisms {
		if !strings.EqualFold(strings.TrimSpace(mech), "none") {
			continue
		}
		sid := entities.NewServiceID(e.IP, e.Port, entities.ProtocolTCP)
		f := events.FindingRaised{
			Rule:            "ssh-none-authentication",
			Title:           "SSH server offers unauthenticated access",
			FindingCategory: string(entities.FindingExposure),
			AssetKind:       assetService,
			AssetID:         sid.String(),
			Evidence:        fmt.Sprintf("%s:%d offers the \"none\" authentication mechanism", e.IP, e.Port),
			Recommendation:  "Remove the none authentication method so every session must present a credential.",
			References:      []string{"CWE-287"},
		}
		f.Severity = events.SeverityHigh
		return []events.FindingRaised{f}
	}
	return nil
}

// DeprecatedSSHProtocol raises a finding when an SSH endpoint still speaks
// protocol version 1, which has known integrity and key recovery weaknesses and has
// been removed from every current implementation.
func DeprecatedSSHProtocol(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.SshPostureDiscovered)
	if !ok {
		return nil
	}
	version := strings.TrimSpace(e.ProtocolVersion)
	if version == "" || !strings.HasPrefix(version, "1.") {
		return nil
	}
	sid := entities.NewServiceID(e.IP, e.Port, entities.ProtocolTCP)
	f := events.FindingRaised{
		Rule:            "deprecated-ssh-protocol",
		Title:           "Deprecated SSH protocol version",
		FindingCategory: string(entities.FindingMisconfig),
		AssetKind:       assetService,
		AssetID:         sid.String(),
		Evidence:        fmt.Sprintf("%s:%d speaks SSH protocol %s", e.IP, e.Port, version),
		Recommendation:  "Disable SSH protocol 1 and serve protocol 2 only.",
		References:      []string{cweBrokenCrypto},
	}
	f.Severity = events.SeverityHigh
	return []events.FindingRaised{f}
}
