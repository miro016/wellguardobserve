package smtp

import (
	"net"
	"time"
)

// Result holds SMTP STARTTLS probe results for all discovered MX hosts.
type Result struct {
	Domain  string
	MXHosts []MXProbeResult
	Error   string
}

// EgressLikelyBlocked reports whether every MX host's TCP/25 connect timed out -
// the signature of blocked outbound port 25 (a firewall silently dropping the
// SYN) rather than a target-side fault. A connection that was refused, or that
// failed at a later stage (banner, EHLO, STARTTLS, TLS handshake), proves port
// 25 was reachable and so does not count. With no MX hosts it returns false: the
// domain handles no mail, which is a definite negative, not an egress gap.
func (r *Result) EgressLikelyBlocked() bool {
	if len(r.MXHosts) == 0 {
		return false
	}
	participating := 0
	for i := range r.MXHosts {
		// A hard-exclusion rejection is a policy decision, not a runner egress
		// failure, so it neither counts as a timeout nor forces the signal off: it
		// simply does not participate.
		if r.MXHosts[i].PolicyRejected {
			continue
		}
		participating++
		if !r.MXHosts[i].DialTimedOut {
			return false
		}
	}
	return participating > 0
}

// PolicyLimited reports whether every MX host was refused by a hard exclusion, so the
// result carries no mail posture because policy withheld it - distinct from a domain
// that handles no mail (no MX) or one whose MX hosts failed on the network. The
// caller surfaces this as a scope decision, never as a clean or blocked mail posture.
func (r *Result) PolicyLimited() bool {
	if len(r.MXHosts) == 0 {
		return false
	}
	for i := range r.MXHosts {
		if !r.MXHosts[i].PolicyRejected {
			return false
		}
	}
	return true
}

// MXProbeResult holds probe results for one MX host.
type MXProbeResult struct {
	Host              string
	Priority          uint16
	Banner            string
	EHLOSupport       []string
	STARTTLSSupported bool
	TLSVersion        string
	TLSCipher         string
	CertSubject       string
	CertIssuer        string
	CertSerial        string
	CertNotBefore     time.Time
	CertNotAfter      time.Time
	CertSANs          []string
	Error             string
	// DialTimedOut records that the TCP connect to port 25 timed out (the SYN got
	// no answer), as opposed to being refused or failing at a later stage. It is
	// the per-host signal EgressLikelyBlocked aggregates to spot a blocked
	// outbound-25 egress.
	DialTimedOut bool
	// PolicyRejected records that a hard exclusion denied this MX host before any
	// SMTP traffic: the MX hostname matched a domain exclusion, or every resolved MX
	// address matched an IP exclusion. Error carries the policy reason. A rejected
	// host sends no banner, EHLO, STARTTLS, or QUIT, contributes to neither the mail
	// posture nor the egress signal, and is not a target-side failure.
	PolicyRejected bool
	// rejectedIP is the excluded resolved address when the dial was refused after
	// resolution; empty when the hostname itself matched a domain exclusion.
	rejectedIP string
}

// MXResolver resolves MX records for a domain. Matches net.LookupMX signature.
type MXResolver func(domain string) ([]*net.MX, error)
