package findings

import (
	"slices"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// Asset kinds used in FindingRaised.AssetKind, matching entities.AssetRef.Kind. Each
// carries the canonical id documented there: a service is the socket a scan observed
// (host is an address), an endpoint is a normalized URL, and a certificate is the
// entities.CertificateID key rather than a raw serial.
const (
	assetCertificate = entities.AssetKindCertificate
	assetDomain      = entities.AssetKindDomain
	assetService     = entities.AssetKindService
	assetIP          = entities.AssetKindIP
	assetEndpoint    = entities.AssetKindEndpoint
)

// serviceFacet builds the structured service identity a service-kind finding carries.
// It derives Port/Proto from the probe URL when the detector only had a URL (httpx),
// and takes product/version/CPEs from whatever the detector fingerprinted.
func serviceFacet(url, product, version string, cpes []string) events.ServiceFacet {
	sf := events.ServiceFacet{Product: product, Version: version, CPEs: cpes}
	if sid, ok := entities.ServiceIDFromURL(url); ok {
		sf.Port = sid.Port
		sf.Proto = sid.Proto
	}
	return sf
}

// toServiceFacet mirrors the event's plain service facet into the entity facet.
func toServiceFacet(s events.ServiceFacet) entities.ServiceFacet {
	return entities.ServiceFacet{
		Port:    s.Port,
		Proto:   s.Proto,
		Product: s.Product,
		Version: s.Version,
		CPEs:    append([]string(nil), s.CPEs...),
	}
}

// mergeServiceFacet fills empty fields of a from b and unions the CPEs. The same
// rule+asset always describes one service, so preferring a's non-empty fields is
// deterministic across replay.
func mergeServiceFacet(a, b entities.ServiceFacet) entities.ServiceFacet {
	if a.Port == 0 {
		a.Port = b.Port
	}
	if a.Proto == "" {
		a.Proto = b.Proto
	}
	if a.Product == "" {
		a.Product = b.Product
	}
	if a.Version == "" {
		a.Version = b.Version
	}
	a.CPEs = unionSorted(a.CPEs, b.CPEs)
	return a
}

// endpointAssetID returns the canonical Endpoint asset id for a probe URL: the exact
// normalized URL the facts projection materializes as an Endpoint node, so a URL-scoped
// finding names an asset that exists.
//
// It fails closed. The previous behavior - deriving a "host/port/tcp" service id from the
// URL, and falling back to the raw URL when parsing failed - produced hostname-shaped
// service keys for an asset kind that is only ever keyed by an observed address, so the
// finding pointed at nothing. A URL that cannot be normalized is quarantined by the same
// normalizer that would have created the Endpoint, so the rule raises no finding instead
// of inventing an unowned key.
func endpointAssetID(url string) (string, bool) {
	id, err := entities.EndpointID(url)
	if err != nil {
		return "", false
	}
	return id, true
}

// certificateAssetID returns the canonical Certificate asset id for an observed
// certificate: the key entities.CertificateID produces from its serial and common name,
// which is exactly the key the facts projection materializes for the same
// CertificateDiscovered event.
//
// A raw serial is not usable as the id. Producers spell the serial differently (case,
// ":" separators, a leading DER sign-padding byte), and the asset key pairs the canonical
// serial with the common name so a CT record and a live handshake for one leaf converge
// without colliding across issuers.
func certificateAssetID(c events.CertificateData) string {
	return entities.CertificateID(c.IssuerName, c.SerialNumber, c.CommonName)
}

// Findings is the read model over raised findings for one scan. It deduplicates
// findings by ID (hash of rule + asset) and rolls them up by severity, category,
// and affected asset. It is distinct from Projection.Issues, which holds scan
// errors (IssueObserved), not target weaknesses.
type Findings struct {
	// All holds every unique finding keyed by finding ID.
	All map[string]*entities.Finding
	// BySeverity counts findings per severity level.
	BySeverity map[int]int
	// ByCategory counts findings per category.
	ByCategory map[entities.FindingCategory]int
	// ByAsset maps an asset key ("kind:id") to the finding IDs against it.
	ByAsset map[string][]string
}

// NewFindings returns a Findings read model with initialised maps.
func NewFindings() Findings {
	var f Findings
	f.ensureInit()
	return f
}

func (f *Findings) ensureInit() {
	if f.All == nil {
		f.All = make(map[string]*entities.Finding)
	}
	if f.BySeverity == nil {
		f.BySeverity = make(map[int]int)
	}
	if f.ByCategory == nil {
		f.ByCategory = make(map[entities.FindingCategory]int)
	}
	if f.ByAsset == nil {
		f.ByAsset = make(map[string][]string)
	}
}

// Apply folds a FindingRaised event into the model, deduplicating by finding ID.
// On a repeat it appends provenance and keeps the earliest FirstSeen, without
// double-counting the rollups.
func (f *Findings) Apply(e events.FindingRaised) {
	f.ensureInit()
	finding, err := entities.NewFinding(
		e.Rule,
		e.Title,
		entities.FindingCategory(e.FindingCategory),
		int(e.Meta().Severity),
		entities.AssetRef{Kind: e.AssetKind, ID: e.AssetID},
		e.Evidence,
		e.Recommendation,
		toReferences(e.References),
		e.At(),
	)
	if err != nil {
		return
	}
	prov := provenanceFromMeta(e.Meta())
	conf := confidenceOrConfirmed(e.Confidence)

	if existing, ok := f.All[finding.ID]; ok {
		existing.Provenance = appendProvenance(existing.Provenance, prov)
		if finding.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = finding.FirstSeen
		}
		// The dedup ID ignores Locations, so a second event for the same host+rule
		// (for example a later web-search pass) contributes more URLs; union them so
		// no location is lost and the order stays replay-stable.
		existing.Locations = unionSorted(existing.Locations, e.Locations)
		// Verification upgrade path: a later event reporting this finding confirmed
		// (a later source corroborating an inferred one) upgrades it. Taking
		// the stronger confidence keeps the fold order-independent on replay.
		existing.Confidence = existing.Confidence.Stronger(conf)
		// Known-exploited is monotonic: once any contributing event flags it, it stays.
		existing.KnownExploited = existing.KnownExploited || e.KnownExploited
		// A later event for the same rule+asset may carry the service identity the
		// first lacked; merge field-wise (same rule+asset describes one service, so
		// this is stable) and union the CPEs.
		existing.Service = mergeServiceFacet(existing.Service, toServiceFacet(e.Service))
		// Corroboration is additive: a second event widens the evidence window and
		// adds its acquisition kind without displacing the first event's evidence.
		// Classify then derives the temporal status from the merged whole.
		accumulateTemporal(existing, e)
		return
	}

	finding.Confidence = conf
	finding.KnownExploited = e.KnownExploited
	finding.Locations = unionSorted(nil, e.Locations)
	finding.Service = toServiceFacet(e.Service)
	finding.Provenance = []entities.Provenance{prov}
	accumulateTemporal(&finding, e)
	f.All[finding.ID] = &finding
	f.BySeverity[finding.Severity]++
	f.ByCategory[finding.Category]++
	key := assetKey(finding.Asset.Kind, finding.Asset.ID)
	f.ByAsset[key] = appendUnique(f.ByAsset[key], finding.ID)
}

// Highest returns the worst severity present, or 0 (info) when there are none.
func (f *Findings) Highest() int {
	highest := 0
	for sev := range f.BySeverity {
		if sev > highest {
			highest = sev
		}
	}
	return highest
}

// CountAtLeast returns the number of findings at or above the given severity.
func (f *Findings) CountAtLeast(sev int) int {
	count := 0
	for s, n := range f.BySeverity {
		if s >= sev {
			count += n
		}
	}
	return count
}

// Sorted returns all findings ordered by severity descending, then category,
// then ID for a stable order.
func (f *Findings) Sorted() []*entities.Finding {
	out := make([]*entities.Finding, 0, len(f.All))
	for _, finding := range f.All {
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ForAsset returns the findings raised against a specific asset.
func (f *Findings) ForAsset(kind, id string) []*entities.Finding {
	ids := f.ByAsset[assetKey(kind, id)]
	out := make([]*entities.Finding, 0, len(ids))
	for _, fid := range ids {
		if finding, ok := f.All[fid]; ok {
			out = append(out, finding)
		}
	}
	return out
}

func assetKey(kind, id string) string {
	return kind + ":" + id
}

func appendProvenance(provs []entities.Provenance, p entities.Provenance) []entities.Provenance {
	for _, existing := range provs {
		if existing.EventID == p.EventID {
			return provs
		}
	}
	return append(provs, p)
}

// appendUnique appends v to s only if it is not already present.
func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// confidenceOrConfirmed maps an event's plain-string confidence to the typed
// entities.Confidence, defaulting an empty value to confirmed (most findings are
// directly observed; only the inferred ones set the field explicitly).
func confidenceOrConfirmed(s string) entities.Confidence {
	if s == "" {
		return entities.ConfidenceConfirmed
	}
	return entities.Confidence(s)
}

// unionSorted returns the sorted set union of base and extra, dropping empties
// and duplicates. It keeps a finding's Locations deterministic across the events
// that merge into it.
func unionSorted(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	var out []string
	for _, v := range base {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	for _, v := range extra {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// provenanceFromMeta projects an event envelope into entity provenance. It
// mirrors projections.ProvenanceFromMeta; the copy keeps this package free of an
// import cycle with the parent projections package, which imports Findings.
func provenanceFromMeta(m events.EventMeta) entities.Provenance {
	return entities.Provenance{
		EventID:         m.EventID,
		Source:          m.Source,
		Phase:           string(m.Phase),
		ObservationKind: string(m.ObservationKind),
		CapturedAt:      m.CapturedAt,
	}
}

// toReferences classifies formatted reference strings into typed References.
func toReferences(refs []string) []entities.Reference {
	out := make([]entities.Reference, 0, len(refs))
	for _, r := range refs {
		kind := "URL"
		switch {
		case strings.HasPrefix(r, "CWE-"):
			kind = "CWE"
		case strings.HasPrefix(r, "CVE-"):
			kind = "CVE"
		}
		out = append(out, entities.Reference{Kind: kind, Value: r})
	}
	return out
}
