package report

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ServiceAssessment is one service's TLS or SSH assessment, reduced to what a
// reader needs to decide whether to look further. The full evidence stays in the
// event stream and the entity snapshots; this is the index into it.
type ServiceAssessment struct {
	// Service is the canonical service key ("host/port/proto"), and ServerName the
	// SNI a TLS assessment used (empty for SSH and for a bare-endpoint assessment).
	Service    string
	ServerName string
	// Kind is "tls" or "ssh".
	Kind string
	// Summary is the concise posture line.
	Summary string
	// Completeness states what the scanner actually established: "assessed" when at
	// least one section ran, otherwise the reason it could not. It is a separate
	// column because a thin summary and an unrun assessment look identical
	// otherwise, and only one of them is good news.
	Completeness string
	// Sources are the tools that contributed, comma-joined.
	Sources string
}

// buildServiceAssessments collects the TLS and SSH assessments folded onto
// services, in service order. Services with neither are skipped: the section is an
// assessment index, not a second service listing.
func buildServiceAssessments(inv *projections.Inventory) []ServiceAssessment {
	var out []ServiceAssessment
	for _, svc := range inv.SortedServices() {
		key := serviceKeyOf(svc)
		for _, tls := range svc.TLS {
			out = append(out, ServiceAssessment{
				Service:      key,
				ServerName:   tls.ServerName,
				Kind:         "tls",
				Summary:      TLSSummary(tls),
				Completeness: tlsCompleteness(tls),
				Sources:      strings.Join(tls.Sources, ", "),
			})
		}
		if svc.SSH != nil {
			out = append(out, ServiceAssessment{
				Service:      key,
				Kind:         "ssh",
				Summary:      SSHSummary(*svc.SSH),
				Completeness: sshCompleteness(*svc.SSH),
				Sources:      strings.Join(svc.SSH.Sources, ", "),
			})
		}
	}
	return out
}

// serviceKeyOf renders the canonical service key for a node, through the same
// identity helper the Services index uses, so the two sections name one socket the
// same way.
func serviceKeyOf(svc *projections.ServiceNode) string {
	return serviceID(svc.IP, svc.Port, svc.Protocol)
}

// TLSSummary renders the concise TLS posture: which versions are accepted, how
// many suites, how many of them should not be offered, whether the chain is
// trusted, and how many named checks came back positive. It is exported so the
// report and the operator views word a posture identically; two surfaces phrasing
// the same assessment differently is how a reader ends up trusting the wrong one.
func TLSSummary(t entities.TlsAssessment) string {
	if !t.Assessed() {
		return "not assessed"
	}
	parts := []string{}
	if len(t.Protocols) > 0 {
		parts = append(parts, strings.Join(t.Protocols, "/"))
	}
	if t.CipherState == entities.AssessmentTested {
		suite := fmt.Sprintf("%d suite(s)", t.CipherCount)
		if len(t.WeakCiphers) > 0 {
			suite += fmt.Sprintf(", %d weak", len(t.WeakCiphers))
		}
		// The flag says every accepted suite provides forward secrecy, so its
		// negation is "at least one does not" rather than "none do". Wording it as an
		// absence would overstate the finding on the common endpoint that offers both
		// ephemeral and static key exchanges.
		if !t.ForwardSecrecy {
			suite += ", some suites lack PFS"
		}
		parts = append(parts, suite)
	}
	if t.ChainState == entities.AssessmentTested {
		chain := "chain trusted"
		if !t.ChainTrusted {
			chain = "chain untrusted"
		}
		if t.LeafIssuer != "" {
			chain += " (" + t.LeafIssuer + ")"
		}
		parts = append(parts, chain)
	}
	if t.VulnerabilityState == entities.AssessmentTested {
		parts = append(parts, fmt.Sprintf("%d issue(s)", len(t.Vulnerabilities)))
	}
	if len(parts) == 0 {
		return "assessed, nothing reported"
	}
	return strings.Join(parts, "; ")
}

// tlsCompleteness names which sections ran. An assessment with untested sections
// says so, because an empty issue list from an untested endpoint is not a clean
// result and must never read as one.
func tlsCompleteness(t entities.TlsAssessment) string {
	var missing []string
	for _, section := range []struct {
		name  string
		state entities.AssessmentState
	}{
		{"ciphers", t.CipherState},
		{"chain", t.ChainState},
		{"settings", t.SettingsState},
		{"vulnerabilities", t.VulnerabilityState},
	} {
		if section.state != entities.AssessmentTested {
			missing = append(missing, section.name)
		}
	}
	switch {
	case len(missing) == 0 && t.Truncated:
		return "assessed (capped)"
	case len(missing) == 0:
		return "assessed"
	case len(missing) == 4:
		return "not assessed"
	default:
		return "partial: no " + strings.Join(missing, ", ")
	}
}

// SSHSummary renders the concise SSH posture: the protocol version and how many
// algorithms the server offers in each slot, which is what makes a thin offer
// visible next to a complete one. Exported for the same reason as TLSSummary.
func SSHSummary(s entities.SshPosture) string {
	parts := []string{}
	if s.ProtocolVersion != "" {
		parts = append(parts, "SSH "+s.ProtocolVersion)
	}
	parts = append(parts, fmt.Sprintf("%d kex, %d host key, %d cipher, %d MAC",
		len(s.KeyExchange), len(s.HostKey), len(s.Encryption), len(s.Mac)))
	if len(s.AuthMechanisms) > 0 {
		parts = append(parts, "auth: "+strings.Join(s.AuthMechanisms, ", "))
	}
	return strings.Join(parts, "; ")
}

// sshCompleteness states whether the algorithm offer was fully read. An empty slot
// is a slot the scanner did not read, which is not the same as a server that
// offers nothing there.
func sshCompleteness(s entities.SshPosture) string {
	if s.Truncated {
		return "read (capped)"
	}
	if len(s.KeyExchange) == 0 && len(s.Encryption) == 0 && len(s.Mac) == 0 {
		return "not read"
	}
	return "read"
}

// writeServiceAssessments renders the TLS and SSH assessment index.
func (r Report) writeServiceAssessments(sb *strings.Builder) {
	fmt.Fprintf(sb, "## Service Assessments (%d)\n\n", len(r.ServiceAssessments))
	if len(r.ServiceAssessments) == 0 {
		sb.WriteString("No service-level TLS or SSH assessment ran.\n\n")
		return
	}
	sb.WriteString("Per-service TLS and SSH posture. Completeness is separate from the summary on purpose: ")
	sb.WriteString("an endpoint whose checks did not run reports nothing wrong, which is not the same as nothing being wrong.\n\n")
	sb.WriteString("| Service | Server name | Kind | Summary | Completeness | Sources |\n")
	sb.WriteString("|---------|-------------|------|---------|--------------|---------|\n")
	for _, a := range r.ServiceAssessments {
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s | %s |\n",
			a.Service, orDash(a.ServerName), a.Kind, a.Summary, a.Completeness, orDash(a.Sources))
	}
	sb.WriteString("\n")
}

// orDash renders an empty value as a dash so a table cell is never blank.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
