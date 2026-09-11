package detectors

import (
	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/findings"
)

// Rule derives findings from a single domain event. Rules are pure: they read
// the event and return zero or more findings with their content, severity, and
// category set, but without scan-correlation metadata. A rule that does not
// apply to the given event returns nil. The rule functions live in the findings
// package (internal/projections/findings); this registry only composes
// them and runs them over the event stream.
type Rule func(events.DomainEvent) []events.FindingRaised

// Registry holds the active set of detection rules.
type Registry struct {
	rules []Rule
}

// NewRegistry builds a Registry from the given rules. Callers can compose a
// custom rule set, for example to enable only the rules whose source tools are
// active for a scan.
func NewRegistry(rules ...Rule) *Registry {
	return &Registry{rules: rules}
}

// DefaultRegistry returns the built-in detection rules: the passive rules plus
// the active rules. Active rules only match active-phase events, so they stay
// dormant unless the active phase is enabled and emits those events.
func DefaultRegistry() *Registry {
	return NewRegistry(
		// passive
		findings.ExpiredCert,
		findings.ExpiringCert,
		findings.LongLivedCert,
		findings.WildcardCert,
		findings.ZoneTransferOpen,
		findings.MissingDNSSEC,
		findings.MailSecurity,
		findings.BreachExposure,
		findings.MaliciousReputation,
		findings.DorkExposure,
		findings.ShodanVulnerabilities,
		findings.NetlasVulnerabilities,
		findings.CensysVulnerabilities,
		findings.CensysReputation,
		findings.RiskyProviderPortShodan,
		findings.RiskyProviderPortNetlas,
		findings.RiskyProviderPortCensys,
		// active
		findings.PlaintextHTTP,
		findings.MissingSecurityHeaders,
		findings.RiskyOpenPort,
		// active: the UDP pass. Each rule reads a udp ServiceDiscovered, which the
		// scanner raises only for a port that answered, and each stays inside what a
		// discovery reply proves. A profile with tools.portscan.udp disabled emits no
		// such event, so these stay dormant.
		findings.UDPManagementPlaneExposure,
		findings.UDPReflectorSurface,
		findings.UDPRemoteAccessSurface,
		findings.WeakTLSVersion,
		findings.TLSPostureChainUntrusted,
		findings.MxNoStartTLS,
		findings.VersionDisclosure,
		findings.DefaultCredentials,
		// active: service-level TLS and SSH assessment. WeakTLSSecurityVersion shares
		// the weak-tls-version rule ID with the HTTPS-posture rule above, so one
		// weakness proven by two tools folds into one finding with both provenances.
		findings.WeakTLSSecurityVersion,
		findings.WeakTLSCipher,
		findings.TLSNoForwardSecrecy,
		findings.TLSChainUntrusted,
		findings.TLSKnownVulnerability,
		findings.TLSMissingHardening,
		findings.WeakSSHAlgorithm,
		findings.SSHInsecureAuthentication,
		findings.DeprecatedSSHProtocol,
	)
}

// Apply runs every rule against evt and returns all findings produced. The
// findings carry content and severity but still need their envelope stamped by
// the publisher.
func (r *Registry) Apply(evt events.DomainEvent) []events.FindingRaised {
	if r == nil {
		return nil
	}
	var out []events.FindingRaised
	for _, rule := range r.rules {
		out = append(out, rule(evt)...)
	}
	return out
}
