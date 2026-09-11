package scandiff

import (
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Identity is the spine of the comparison: a stable, semantic key that names the
// asset or fact an event describes, so two events from different scans that mean
// "the same thing" share one identity even though their volatile envelope fields
// (EventID, ScanID, CausationID, CapturedAt, ToolCorrID) differ by construction.
//
// An identity is the concrete type name plus the normalized natural-key fields of
// the payload:
//
//	identity = TypeName + "|" + normalizedKeyFields
//
// The type name is always present, so events of different types never collide even
// when their natural keys would. The per-type key extractors live in a registry
// inside this package (option B from the plan): the event types are left untouched
// and all identity knowledge sits in one reviewable place. The cost is that the
// extractors must track the event structs; identityRegistryComplete (test) guards
// that every event type has an entry.

// idKeyFunc returns the normalized natural-key portion of an event's identity (the
// part after "TypeName|"). It receives the event already reduced to its value form
// by Identity, so it can type-assert to the value struct directly.
type idKeyFunc func(events.DomainEvent) string

// identityRegistry maps an event TypeName to its natural-key extractor. It is
// exhaustive: every registered DomainEvent type has an entry. Per-provider
// snapshot events fold Source into the key so each provider's snapshot is its own
// fact (a name "found by censys" and the same name "found by shodan" are distinct
// snapshot identities, while a plain DnsDomainNameDiscovered collapses across the
// tools that reported it).
var identityRegistry = map[string]idKeyFunc{
	// Lifecycle.
	"ScanStarted":   func(e events.DomainEvent) string { return normalizeDomain(e.(events.ScanStarted).RootTarget) },
	"ScanCompleted": func(e events.DomainEvent) string { return normalizeDomain(e.(events.ScanCompleted).RootTarget) },

	// Passive discovery keyed by domain.
	"DnsDomainNameDiscovered": func(e events.DomainEvent) string {
		return normalizeDomain(e.(events.DnsDomainNameDiscovered).Domain)
	},
	"DnsRecordsDiscovered": func(e events.DomainEvent) string {
		return normalizeDomain(e.(events.DnsRecordsDiscovered).Domain)
	},
	"DomainRegistrationDiscovered": func(e events.DomainEvent) string {
		return normalizeDomain(e.(events.DomainRegistrationDiscovered).Domain)
	},
	"MailSecurityDiscovered": func(e events.DomainEvent) string {
		return normalizeDomain(e.(events.MailSecurityDiscovered).Domain)
	},
	"MxTlsDiscovered":      func(e events.DomainEvent) string { return normalizeDomain(e.(events.MxTlsDiscovered).Domain) },
	"TlsPostureDiscovered": func(e events.DomainEvent) string { return normalizeDomain(e.(events.TlsPostureDiscovered).Domain) },
	"BreachDataDiscovered": func(e events.DomainEvent) string { return normalizeDomain(e.(events.BreachDataDiscovered).Domain) },
	"ZoneTransferDiscovered": func(e events.DomainEvent) string {
		v := e.(events.ZoneTransferDiscovered)
		return keyJoin(normalizeDomain(v.Domain), normalizeDomain(v.Nameserver))
	},

	// Per-provider snapshots: Source is part of the identity.
	"CensysHostsDiscovered": func(e events.DomainEvent) string {
		v := e.(events.CensysHostsDiscovered)
		return keyJoin(normalizeDomain(v.Domain), normalizeSource(v.Meta().Source))
	},
	"ShodanHostsDiscovered": func(e events.DomainEvent) string {
		v := e.(events.ShodanHostsDiscovered)
		return keyJoin(normalizeDomain(v.Domain), normalizeSource(v.Meta().Source))
	},
	"NetlasHostsDiscovered": func(e events.DomainEvent) string {
		v := e.(events.NetlasHostsDiscovered)
		return keyJoin(normalizeDomain(v.Domain), normalizeSource(v.Meta().Source))
	},
	"DomainReputationDiscovered": func(e events.DomainEvent) string {
		v := e.(events.DomainReputationDiscovered)
		return keyJoin(normalizeDomain(v.Domain), normalizeSource(v.Meta().Source))
	},
	"WebAssetsDiscovered": func(e events.DomainEvent) string {
		v := e.(events.WebAssetsDiscovered)
		return keyJoin(normalizeDomain(v.Domain), normalizeSource(v.Meta().Source))
	},

	// Network / host.
	"IPAddressDiscovered": func(e events.DomainEvent) string {
		v := e.(events.IPAddressDiscovered)
		return keyJoin(normalizeIP(v.IP), normalizeDomain(v.Domain), strings.ToUpper(strings.TrimSpace(v.RecordType)))
	},
	"NetblockDiscovered":     func(e events.DomainEvent) string { return strings.TrimSpace(e.(events.NetblockDiscovered).Prefix) },
	"IPReachabilityObserved": func(e events.DomainEvent) string { return normalizeIP(e.(events.IPReachabilityObserved).IP) },
	"HostOSGuessed":          func(e events.DomainEvent) string { return normalizeIP(e.(events.HostOSGuessed).IP) },
	"ServiceDiscovered": func(e events.DomainEvent) string {
		v := e.(events.ServiceDiscovered)
		return keyJoin(normalizeIP(v.IP), normalizeService(v.Port, v.Protocol))
	},

	// Web.
	"HttpEndpointDiscovered": func(e events.DomainEvent) string {
		return normalizeURL(e.(events.HttpEndpointDiscovered).URL)
	},
	"HttpRedirectObserved": func(e events.DomainEvent) string {
		v := e.(events.HttpRedirectObserved)
		return keyJoin(normalizeSource(v.Meta().Source), normalizeURL(v.FromURL), normalizeInt(v.Hop))
	},
	"TechnologyFingerprinted": func(e events.DomainEvent) string {
		v := e.(events.TechnologyFingerprinted)
		return keyJoin(normalizeURL(v.URL), normalizeText(v.Technology))
	},

	// Certificates.
	"CertificateDiscovered": func(e events.DomainEvent) string {
		v := e.(events.CertificateDiscovered)
		return certificateKey(v)
	},

	// Findings and issues.
	typeFindingRaised: func(e events.DomainEvent) string {
		return findingKey(e.(events.FindingRaised))
	},
	"IssueObserved": func(e events.DomainEvent) string {
		v := e.(events.IssueObserved)
		return keyJoin(normalizeSource(v.Meta().Source), normalizeText(v.Query), normalizeText(v.Error))
	},
}

// Identity returns the semantic identity of an event: its type name plus the
// normalized natural key. It reduces pointer events to their value form first so
// a live value and a replayed pointer of the same event share one identity. A type
// without a registry entry falls back to type name plus its full normalized payload
// (genericIdentity), which is safe but coarse - any payload difference reads as a
// new identity (a missing+unexpected pair) rather than a single changed entry.
func Identity(evt events.DomainEvent) string {
	evt = events.AsValue(evt)
	name := events.TypeName(evt)
	if fn, ok := identityRegistry[name]; ok {
		return name + "|" + fn(evt)
	}
	return name + "|" + genericIdentity(evt)
}

// normalizeSource lowercases and trims the producing-tool name so identity and the
// per-source presence set agree on a provider's spelling.
func normalizeSource(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// certificateKey matches the canonical inventory identity. Serial formatting and
// issuer naming vary between CT and live TLS producers, but the physical
// certificate serial is source-independent.
func certificateKey(e events.CertificateDiscovered) string {
	return valueobjects.CanonicalCertSerial(e.Certificate.SerialNumber)
}

// keyJoin concatenates the parts of a multi-field natural key with a separator that
// does not occur in normalized domains, IPs, or URLs.
func keyJoin(parts ...string) string { return strings.Join(parts, "|") }
