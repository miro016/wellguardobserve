package scandiff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// Field is one comparable field of an event payload. Scalars use a single-element
// Values; set-valued fields (A/AAAA, NS, SANs, CPEs, headers) use the sorted,
// normalized set. A field whose value normalizes to empty is dropped entirely, so a
// field going blank between scans reads as a real change rather than an empty token.
type Field struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// payloadFields returns the normalized semantic payload of an event as an ordered
// set of fields. It is the single representation behind both the matched/changed
// verdict (this step) and the field-level delta (step 3): two payloads are equal
// exactly when their field lists are equal after normalization and per-field
// sorting.
//
// Registered high-value types use a per-type extractor that applies semantic
// normalization (so a trailing dot, case, or mapped-IP difference is not a spurious
// change). Every other type falls back to a generic canonical projection of its
// JSON, which is correct for the verdict but coarse: it has no semantic
// normalization, so its deltas are presence/whole-value only.
func payloadFields(evt events.DomainEvent) []Field {
	evt = events.AsValue(evt)
	name := events.TypeName(evt)
	var fs []Field
	if fn, ok := payloadRegistry[name]; ok {
		fs = fn(evt)
	} else {
		fs = genericFields(evt)
	}
	return cleanFields(fs)
}

// payloadRegistry maps an event TypeName to its per-type field extractor. It covers
// the high-value discovery and finding types where semantic normalization matters;
// the long tail (lifecycle, issues, the nested per-provider host
// snapshots) uses genericFields.
var payloadRegistry = map[string]func(events.DomainEvent) []Field{
	"DnsDomainNameDiscovered":      fieldsDNSDomainName,
	"DnsRecordsDiscovered":         fieldsDNSRecords,
	"IPAddressDiscovered":          fieldsIPAddress,
	"NetblockDiscovered":           fieldsNetblock,
	"ServiceDiscovered":            fieldsService,
	"HttpEndpointDiscovered":       fieldsHTTPEndpoint,
	"HttpRedirectObserved":         fieldsHTTPRedirect,
	"TechnologyFingerprinted":      fieldsTechnology,
	"CertificateDiscovered":        fieldsCertificate,
	typeFindingRaised:              fieldsFinding,
	"DomainRegistrationDiscovered": fieldsRegistration,
	"MailSecurityDiscovered":       fieldsMailSecurity,
}

func fieldsDNSDomainName(e events.DomainEvent) []Field {
	v := e.(events.DnsDomainNameDiscovered)
	return append(metaFields(v.Meta()),
		scalar("parentDomain", normalizeDomain(v.ParentDomain)),
		scalar("depth", normalizeInt(v.Depth)),
		scalar("discoverySource", normalizeText(v.DiscoverySource)),
	)
}

func fieldsDNSRecords(e events.DomainEvent) []Field {
	v := e.(events.DnsRecordsDiscovered)
	mx := make([]string, 0, len(v.MX))
	for _, m := range v.MX {
		mx = append(mx, fmt.Sprintf("%s:%d", normalizeDomain(m.Host), m.Priority))
	}
	return append(metaFields(v.Meta()),
		set("a", normalizeEach(v.A, normalizeIP)),
		set("aaaa", normalizeEach(v.AAAA, normalizeIP)),
		set("cname", normalizeEach(v.CNAME, normalizeDomain)),
		set("ns", normalizeEach(v.NS, normalizeDomain)),
		set("mx", mx),
		set("txt", normalizeEach(v.TXT, strings.TrimSpace)),
		scalar("dnssec", normalizeBool(v.DNSSEC)),
	)
}

func fieldsIPAddress(e events.DomainEvent) []Field {
	v := e.(events.IPAddressDiscovered)
	return append(metaFields(v.Meta()),
		scalar("confidence", normalizeText(v.Confidence)),
	)
}

func fieldsNetblock(e events.DomainEvent) []Field {
	v := e.(events.NetblockDiscovered)
	return append(metaFields(v.Meta()),
		scalar("asn", normalizeInt(v.ASN)),
		scalar("name", normalizeText(v.Name)),
		scalar("country", normalizeText(v.Country)),
		scalar("registry", normalizeText(v.Registry)),
	)
}

func fieldsService(e events.DomainEvent) []Field {
	v := e.(events.ServiceDiscovered)
	return append(metaFields(v.Meta()),
		scalar("service", normalizeText(v.Service)),
		scalar("product", normalizeText(v.Product)),
		scalar("version", normalizeText(v.Version)),
		scalar("extraInfo", normalizeText(v.ExtraInfo)),
		set("cpes", normalizeEach(v.CPEs, normalizeText)),
		scalar("banner", normalizeServiceBanner(v.Banner)),
	)
}

func fieldsHTTPEndpoint(e events.DomainEvent) []Field {
	v := e.(events.HttpEndpointDiscovered)
	return append(metaFields(v.Meta()),
		scalar("statusCode", normalizeInt(v.StatusCode)),
		scalar("title", normalizeText(v.Title)),
		scalar("server", normalizeText(v.Server)),
		set("headers", normalizeEach(v.Headers, normalizeText)),
		scalar("authType", normalizeText(v.AuthType)),
		scalar("authEvidence", normalizeText(v.AuthEvidence)),
	)
}

func fieldsHTTPRedirect(e events.DomainEvent) []Field {
	v := e.(events.HttpRedirectObserved)
	return append(metaFields(v.Meta()),
		scalar("toURL", normalizeURL(v.ToURL)),
		scalar("statusCode", normalizeInt(v.StatusCode)),
		scalar("disposition", normalizeText(string(v.Disposition))),
		scalar("reason", normalizeText(v.Reason)),
	)
}

func fieldsTechnology(e events.DomainEvent) []Field {
	v := e.(events.TechnologyFingerprinted)
	return append(metaFields(v.Meta()),
		scalar("version", normalizeText(v.Version)),
		scalar("evidence", normalizeText(v.Evidence)),
		set("categories", normalizeEach(v.Categories, normalizeText)),
		set("cpes", normalizeEach(v.CPEs, normalizeText)),
	)
}

func fieldsCertificate(e events.DomainEvent) []Field {
	v := e.(events.CertificateDiscovered)
	return append(metaFields(v.Meta()),
		scalar("commonName", normalizeText(v.Certificate.CommonName)),
		scalar("notBefore", timeKey(v.Certificate.ValidFrom)),
		scalar("notAfter", timeKey(v.Certificate.ValidUntil)),
		scalar("entryTimestamp", timeKey(v.Certificate.LoggedAt)),
		set("domains", normalizeEach(v.Certificate.Domains, normalizeDomain)),
	)
}

func fieldsFinding(e events.DomainEvent) []Field {
	v := e.(events.FindingRaised)
	return append(metaFields(v.Meta()),
		scalar("title", normalizeText(v.Title)),
		scalar("findingCategory", normalizeText(v.FindingCategory)),
		scalar("evidence", normalizeText(v.Evidence)),
		scalar("recommendation", normalizeText(v.Recommendation)),
		set("references", normalizeEach(v.References, normalizeText)),
		scalar("knownExploited", normalizeBool(v.KnownExploited)),
		scalar("confidence", normalizeText(v.Confidence)),
		set("locations", normalizeEach(v.Locations, normalizeURL)),
	)
}

func fieldsRegistration(e events.DomainEvent) []Field {
	v := e.(events.DomainRegistrationDiscovered)
	return append(metaFields(v.Meta()),
		scalar("dataSource", normalizeText(v.DataSource)),
		scalar("registrar", normalizeText(v.Registrar)),
		scalar("whoisServer", normalizeDomain(v.WhoisServer)),
		set("status", normalizeEach(v.Status, normalizeText)),
		scalar("created", timeKey(v.CreatedDate)),
		scalar("updated", timeKey(v.UpdatedDate)),
		scalar("expiry", timeKey(v.ExpiryDate)),
		set("nameservers", normalizeEach(v.Nameservers, normalizeDomain)),
		scalar("dnssec", normalizeBool(v.DNSSEC)),
	)
}

func fieldsMailSecurity(e events.DomainEvent) []Field {
	v := e.(events.MailSecurityDiscovered)
	dkim := make([]string, 0, len(v.DKIM))
	for _, d := range v.DKIM {
		dkim = append(dkim, normalizeText(d.Selector)+":"+normalizeText(d.Value))
	}
	return append(metaFields(v.Meta()),
		scalar("spf", normalizeText(v.SPF)),
		scalar("dmarc", normalizeText(v.DMARC)),
		scalar("dmarcSeverity", normalizeText(v.DMARCSeverity)),
		set("dkim", dkim),
		scalar("mxCount", normalizeInt(v.MXCount)),
	)
}

// metaFields carries the retained semantic envelope fields (Severity, Phase,
// Category) into every per-type payload. They are kept, not stripped: per the
// volatile-vs-semantic split only EventID, ScanID, CausationID, CapturedAt, and
// ToolCorrID are run-time noise, while a severity change is a real change. Source
// is deliberately absent here - it is tracked separately as the per-side source set
// (see classify.go) so a provenance shift never reads as a content change.
func metaFields(m events.EventMeta) []Field {
	return []Field{
		scalar("severity", m.Severity.String()),
		scalar("phase", string(m.Phase)),
		scalar("category", string(m.Category)),
	}
}

// scalar builds a single-valued field, or an empty field (dropped by cleanFields)
// when the value normalizes to "".
func scalar(name, value string) Field {
	if value == "" {
		return Field{Name: name}
	}
	return Field{Name: name, Values: []string{value}}
}

// set builds a set-valued field from already-normalized values, sorting and
// deduplicating and dropping blanks so the representation is canonical.
func set(name string, values []string) Field {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return Field{Name: name}
	}
	return Field{Name: name, Values: out}
}

// cleanFields drops empty-valued fields and returns the remainder sorted by name,
// so equality and the step-3 delta both read a canonical, order-stable list.
func cleanFields(fs []Field) []Field {
	out := make([]Field, 0, len(fs))
	for _, f := range fs {
		if len(f.Values) == 0 {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// normalizeEach maps a normalizer over a slice, returning a new slice.
func normalizeEach(in []string, fn func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, fn(s))
	}
	return out
}

// timeKey renders an intrinsic certificate/registration timestamp as a stable UTC
// token, empty for the zero time. Unlike the envelope CapturedAt these times are
// semantic and must be compared.
func timeKey(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// volatileJSONKeys are the envelope keys the generic fallback strips before
// comparing. It is built from events.VolatileMetaFields() - the single source of
// truth for the five run-to-run volatile envelope fields - plus Source, which is
// excluded from the content payload and tracked separately as the per-side source
// set. Everything else (the retained Severity/Phase/Category and the typed payload)
// participates in the comparison.
var volatileJSONKeys = buildVolatileJSONKeys()

// buildVolatileJSONKeys folds the events-package volatile set plus the
// separately-tracked Source into the strip set.
func buildVolatileJSONKeys() map[string]bool {
	keys := map[string]bool{"Source": true}
	for _, name := range events.VolatileMetaFields() {
		keys[name] = true
	}
	return keys
}

// strippedPayloadMap marshals an event to its JSON object (EventMeta is embedded,
// so its fields are promoted to the top level) and removes the volatile keys.
func strippedPayloadMap(evt events.DomainEvent) map[string]json.RawMessage {
	data, err := json.Marshal(evt)
	if err != nil {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	for k := range volatileJSONKeys {
		delete(m, k)
	}
	return m
}

// genericFields is the per-field canonical projection used for types without a
// per-type extractor: one field per remaining JSON key, valued by that key's raw
// canonical JSON. It is correct for the matched/changed verdict but has no semantic
// normalization, so its deltas are coarse.
func genericFields(evt events.DomainEvent) []Field {
	m := strippedPayloadMap(evt)
	fs := make([]Field, 0, len(m))
	for k, raw := range m {
		fs = append(fs, Field{Name: lowerFirst(k), Values: []string{string(raw)}})
	}
	return fs
}

// genericIdentity is the fallback natural key for an unregistered type: its full
// normalized payload as canonical JSON (map marshaling sorts keys). Safe but
// coarse - any payload difference yields a new identity, so the event shows up as a
// missing+unexpected pair rather than a single changed entry. Registering the type
// upgrades it to precise change detection.
func genericIdentity(evt events.DomainEvent) string {
	m := strippedPayloadMap(evt)
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// lowerFirst lowercases the first rune of a JSON key so the generic field names
// read like the per-type camelCase ones ("Domain" -> "domain").
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
