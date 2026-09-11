package facts

import (
	"fmt"
	"sort"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/analysis"
)

// Graph is the folded facts read model. Assets and relationships deduplicate by
// canonical key; observations, evidence, and issues accumulate. It is built by
// [Build] or by repeated [Graph.Apply] calls and rendered deterministically by
// [Graph.JSON] / [Graph.Markdown].
type Graph struct {
	scanID      string
	rootTarget  string
	generatedAt time.Time // latest event time in the stream, not wall clock (keeps output deterministic)
	// asOf is the fixed cutoff every currentness classification in this graph is
	// evaluated against. It is supplied once at construction rather than read from
	// each event, so two certificates observed minutes apart in the same scan are
	// judged against one reference time and a rebuild is byte-stable.
	asOf events.AnalysisAsOf
	// policy is the declared freshness policy every recent_passive verdict in this
	// graph is measured against. It is held on the graph so the rendered artifact and
	// any consumer that asks for the classified surface cannot use different windows.
	policy analysis.FreshnessPolicy

	assetIdx map[string]*Asset        // key: string(Type) + "\x00" + Key
	relIdx   map[string]*Relationship // key: string(Type) + "\x00" + From + "\x00" + To

	observations []Observation
	evidence     []Evidence
	issues       []Issue
	environments []events.ScanEnvironmentRecorded

	findIdx     map[string]*FindingCandidate // candidate id -> candidate
	currentMeta events.EventMeta             // event currently being folded; enriches observations

	total    int
	mapped   int
	unmapped map[string]int // event type name -> count with no normalizer yet
}

// New returns an empty graph ready to fold events, evaluating currentness against
// the given cutoff. Derive the cutoff from the whole stream (events.DeriveAnalysisAsOf)
// before folding; [Build] does that for a caller that already holds the slice.
func New(asOf events.AnalysisAsOf) *Graph {
	return &Graph{
		asOf:     asOf,
		policy:   analysis.DefaultFreshnessPolicy(),
		assetIdx: map[string]*Asset{},
		relIdx:   map[string]*Relationship{},
		findIdx:  map[string]*FindingCandidate{},
		unmapped: map[string]int{},
	}
}

// Build folds a whole event stream into a graph.
//
// It walks the stream twice: once to derive the analysis cutoff (which is only known
// after the last ScanCompleted has been seen) and once to fold. Classifying during a
// single pass would judge early events against an incomplete cutoff.
//
// It fails rather than folding a stream with no capture times. Every event the
// orchestrator emits stamps CapturedAt, so a stream with none is truncated or written
// by an incompatible vocabulary, and every currentness label derived from it would be
// silently wrong.
func Build(evts []events.DomainEvent) (*Graph, error) {
	asOf, err := events.DeriveAnalysisAsOf(evts)
	if err != nil {
		return nil, fmt.Errorf("facts graph: %w", err)
	}
	g := New(asOf)
	for _, e := range evts {
		g.Apply(e)
	}
	return g, nil
}

// AnalysisAsOf returns the cutoff this graph classified against, so a renderer can
// state it next to every temporal claim.
func (g *Graph) AnalysisAsOf() events.AnalysisAsOf { return g.asOf }

// FreshnessPolicy returns the declared windows this graph classified against, so a
// consumer building its own view judges "recent" exactly the way the artifact did.
func (g *Graph) FreshnessPolicy() analysis.FreshnessPolicy { return g.policy }

// Apply folds one event. It normalizes the event to its value form first so a live
// value and a replayed pointer of the same event fold identically (see events.AsValue),
// then dispatches to the per-type normalizer. An event type with no normalizer is
// counted under coverage rather than dropped.
func (g *Graph) Apply(evt events.DomainEvent) {
	evt = events.AsValue(evt)
	m := evt.Meta()
	g.currentMeta = m
	g.total++
	if g.scanID == "" {
		g.scanID = m.ScanID
	}
	if m.CapturedAt.After(g.generatedAt) {
		g.generatedAt = m.CapturedAt
	}
	switch e := evt.(type) {
	case events.ScanStarted:
		g.rootTarget = normalizeFQDN(e.RootTarget)
		g.mapped++
	case events.ScanCompleted:
		g.mapped++
	case events.ActiveTargetApproved:
		// Approval is control-plane state rather than an observed target fact. Its
		// deliberate no-op is still a complete projection decision, so do not report
		// it as an event type without a normalizer.
		g.mapped++
	case events.ScanEnvironmentRecorded:
		g.environments = append(g.environments, e)
		g.mapped++
	case events.IssueObserved:
		g.applyIssue(e)
		g.mapped++
	default:
		if g.applyDiscovery(evt) {
			g.mapped++
		} else {
			g.unmapped[events.TypeName(evt)]++
		}
	}
}

// applyDiscovery dispatches a discovery/facet event to its normalizer, returning false
// when no normalizer handles the type (so the caller records it under coverage). The
// dispatch is split across two helpers to keep each switch's cyclomatic complexity
// bounded, mirroring how Inventory.Apply delegates to applyInfra.
func (g *Graph) applyDiscovery(evt events.DomainEvent) bool {
	return g.applyNameOrHostEvent(evt) || g.applyActiveOrFacetEvent(evt) || g.applyFindingEvent(evt)
}

// applyNameOrHostEvent handles the name-, IP-, host-intel-, certificate-, and
// zone-transfer discovery events.
func (g *Graph) applyNameOrHostEvent(evt events.DomainEvent) bool {
	switch e := evt.(type) {
	case events.DnsDomainNameDiscovered:
		g.applyDNSDomainName(e)
	case events.DnsRecordsDiscovered:
		g.applyDNSRecords(e)
	case events.CensysHostsDiscovered:
		g.applyCensysHosts(e)
	case events.ShodanHostsDiscovered:
		g.applyShodanHosts(e)
	case events.NetlasHostsDiscovered:
		g.applyNetlasHosts(e)
	case events.IPAddressDiscovered:
		g.applyIPAddress(e)
	case events.NetblockDiscovered:
		g.applyNetblock(e)
	case events.IPReachabilityObserved:
		g.applyReachability(e)
	case events.HostOSGuessed:
		g.applyHostOS(e)
	case events.CertificateDiscovered:
		g.applyCertificate(e)
	case events.ZoneTransferDiscovered:
		g.applyZoneTransfer(e)
	default:
		return false
	}
	return true
}

// applyActiveOrFacetEvent handles the active-probe events and the passive domain-facet
// events (registration, mail security, reputation, breach, MX TLS, web assets).
func (g *Graph) applyActiveOrFacetEvent(evt events.DomainEvent) bool {
	switch e := evt.(type) {
	case events.ServiceDiscovered:
		g.applyService(e)
	case events.HttpEndpointDiscovered:
		g.applyHTTPEndpoint(e)
	case events.HttpRedirectObserved:
		g.applyHTTPRedirect(e)
	case events.TechnologyFingerprinted:
		g.applyTechnology(e)
	case events.TlsPostureDiscovered:
		g.applyTLSPosture(e)
	case events.MxTlsDiscovered:
		g.applyMxTLS(e)
	case events.DomainRegistrationDiscovered:
		g.applyRegistration(e)
	case events.MailSecurityDiscovered:
		g.applyMailSecurity(e)
	case events.DomainReputationDiscovered:
		g.applyReputation(e)
	case events.BreachDataDiscovered:
		g.applyBreach(e)
	case events.WebAssetsDiscovered:
		g.applyWebAssets(e)
	case events.HostProfileObserved:
		g.applyHostProfile(e)
	case events.ServiceScriptObserved:
		g.applyServiceScript(e)
	case events.TlsSecurityAssessed:
		g.applyTLSSecurity(e)
	case events.SshPostureDiscovered:
		g.applySSHPosture(e)
	default:
		return false
	}
	return true
}

// applyIssue passes an upstream scan/tool issue through as a graph Issue.
func (g *Graph) applyIssue(e events.IssueObserved) {
	m := e.Meta()
	g.addIssue(Issue{
		Type:       issueRecon,
		Source:     m.Source,
		Severity:   m.Severity,
		Message:    e.Error,
		RawEventID: m.EventID,
	})
}

// upsertAsset inserts or merges an asset whose source supplied no real-world time. The
// asset's window falls back to the scan time and the recorded assertion says so, so
// nothing downstream can read the fallback as evidence the asset existed then.
func (g *Graph) upsertAsset(a Asset) {
	g.upsertAssetClaim(a, claim{})
}

// upsertAssetClaim inserts a new asset or merges into the existing one with the same key:
// widening first/last seen, unioning sources, filling attributes it does not yet have,
// and appending the temporal assertion this event makes about it.
//
// The merge only ever widens the compact window and only ever appends to the assertion
// list. A second source's weaker or older claim is never dropped, because the difference
// between two sources' claims is itself the evidence a consumer needs.
func (g *Graph) upsertAssetClaim(a Asset, cl claim) {
	a.Assertions = appendAssertion(a.Assertions, assert(g.currentMeta, cl))
	k := string(a.Type) + "\x00" + a.Key
	ex, ok := g.assetIdx[k]
	if !ok {
		cp := a
		g.assetIdx[k] = &cp
		return
	}
	if !a.FirstSeen.IsZero() && (ex.FirstSeen.IsZero() || a.FirstSeen.Before(ex.FirstSeen)) {
		ex.FirstSeen = a.FirstSeen
	}
	if a.LastSeen.After(ex.LastSeen) {
		ex.LastSeen = a.LastSeen
	}
	ex.Sources = unionSorted(ex.Sources, a.Sources)
	for _, as := range a.Assertions {
		ex.Assertions = appendAssertion(ex.Assertions, as)
	}
	for kk, vv := range a.Attributes {
		if ex.Attributes == nil {
			ex.Attributes = map[string]any{}
		}
		if _, present := ex.Attributes[kk]; !present {
			ex.Attributes[kk] = vv
		}
	}
}

// unionAssetSet merges values into a sorted []string attribute of an already
// upserted asset. upsertAsset fills scalar attributes only when absent, which makes
// the first observation win; set attributes must instead accumulate across every
// observation, so a later tool's metadata is never dropped. Unknown assets are
// ignored: the caller upserts first.
func (g *Graph) unionAssetSet(t AssetType, key, attr string, values []string) {
	if len(values) == 0 {
		return
	}
	ex, ok := g.assetIdx[string(t)+"\x00"+key]
	if !ok {
		return
	}
	if ex.Attributes == nil {
		ex.Attributes = map[string]any{}
	}
	cur, _ := ex.Attributes[attr].([]string)
	if merged := unionSorted(cur, values); len(merged) > 0 {
		ex.Attributes[attr] = merged
	}
}

// upsertRelationship inserts or merges an edge whose source supplied no real-world time.
func (g *Graph) upsertRelationship(r Relationship) {
	g.upsertRelationshipClaim(r, claim{})
}

// upsertRelationshipClaim inserts a new relationship or widens the seen window of the
// existing one with the same (type, from, to), appending this event's assertion.
func (g *Graph) upsertRelationshipClaim(r Relationship, cl claim) {
	if cl.EvidenceID == "" {
		cl.EvidenceID = r.EvidenceID
	}
	if cl.Confidence == "" {
		cl.Confidence = r.Confidence
	}
	r.Assertions = appendAssertion(r.Assertions, assert(g.currentMeta, cl))
	k := string(r.Type) + "\x00" + r.From + "\x00" + r.To
	ex, ok := g.relIdx[k]
	if !ok {
		cp := r
		g.relIdx[k] = &cp
		return
	}
	if !r.FirstSeen.IsZero() && (ex.FirstSeen.IsZero() || r.FirstSeen.Before(ex.FirstSeen)) {
		ex.FirstSeen = r.FirstSeen
	}
	if r.LastSeen.After(ex.LastSeen) {
		ex.LastSeen = r.LastSeen
	}
	// Every assertion is kept, including the weaker one, so a historical cert_covers_name
	// claim stays reconstructable after a current DNS claim upgrades the same edge.
	for _, as := range r.Assertions {
		ex.Assertions = appendAssertion(ex.Assertions, as)
	}
	// A stronger later assertion (an active probe upgrading a passive edge) wins the
	// summary confidence, mode, and backing evidence; a weaker one leaves them.
	if confidenceRank(r.Confidence) > confidenceRank(ex.Confidence) {
		ex.Confidence = r.Confidence
		ex.Mode = r.Mode
		ex.EvidenceID = r.EvidenceID
	}
}

// confidenceRank orders confidence so a merge can keep the strongest.
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func (g *Graph) addObservation(o Observation) {
	if o.ObservationKind == "" {
		o.ObservationKind = g.currentMeta.ObservationKind
	}
	if o.CapturedAt.IsZero() {
		o.CapturedAt = g.currentMeta.CapturedAt
	}
	// A missing SourceObservedAt stays zero. Filling it from the host currently being
	// folded would attribute one service's provider timestamp to a sibling that carried
	// none, which is exactly the gap the temporal coverage block has to count.
	if o.Currentness == "" {
		o.Currentness = currentnessForKind(o.ObservationKind)
	}
	g.observations = append(g.observations, o)
}
func (g *Graph) addEvidence(e Evidence) { g.evidence = append(g.evidence, e) }
func (g *Graph) addIssue(i Issue)       { g.issues = append(g.issues, i) }

// ensureIP materializes the IPAddress asset for an address another event merely
// mentioned. A mention is not an observation: it leaves the seen window alone and records
// an undated assertion, so a bare reference can never read as "this address existed at
// scan time". The normalizer that actually observed the address supplies the window.
func (g *Graph) ensureIP(m events.EventMeta, ip string, version int) {
	g.upsertAssetClaim(Asset{Type: AssetIPAddress, Key: ip,
		Attributes: map[string]any{"ip": ip, attrIPVersion: version},
		Sources:    srcs(m.Source)}, claim{NoSubjectTime: true})
}

// ensureDomain materializes the Domain/Subdomain asset for a name another event merely
// mentioned, under the same mention-is-not-observation rule as [Graph.ensureIP].
func (g *Graph) ensureDomain(m events.EventMeta, name string) {
	g.upsertAssetClaim(Asset{Type: assetTypeFor(name, g.rootTarget), Key: name,
		Attributes: map[string]any{attrFQDN: name},
		Sources:    srcs(m.Source)}, claim{NoSubjectTime: true})
}

// addObsEvidence records an observation on an asset and the evidence derived from it,
// sharing one discriminator so their ids pair up. It is the common shape most facet
// normalizers use.
func (g *Graph) addObsEvidence(m events.EventMeta, assetKey, obsType, evType, disc, statement string, conf Confidence, md map[string]any) {
	g.addObsEvidenceWithCurrentness(m, assetKey, obsType, evType, disc, statement, conf, "", md)
}

// addObsEvidenceWithCurrentness records an observation whose payload establishes a
// more specific current-state meaning than its acquisition method alone can provide.
func (g *Graph) addObsEvidenceWithCurrentness(m events.EventMeta, assetKey, obsType, evType, disc, statement string, conf Confidence, currentness Currentness, md map[string]any) {
	oid := obsID(m.EventID, disc)
	g.addObservation(Observation{ID: oid, Type: obsType, AssetKey: assetKey,
		Source: m.Source, Mode: m.Phase, Confidence: conf, Currentness: currentness,
		RawEventID: m.EventID, CausedByEventID: m.CausationID, ToolCorrID: m.ToolCorrID,
		CapturedAt: m.CapturedAt, Metadata: md})
	g.addEvidence(Evidence{ID: evID(m.EventID, disc), Type: evType, ObservationID: oid,
		Statement: statement, Source: m.Source, Mode: m.Phase, Confidence: conf, RawEventID: m.EventID})
}

// currentnessForKind returns the current-state meaning inherent in an acquisition
// method. Payload-specific validity is handled by the relevant normalizer.
func currentnessForKind(kind events.ObservationKind) Currentness {
	switch kind {
	case events.ObservationKindDNSAnswer:
		return CurrentnessCurrentlyResolved
	case events.ObservationKindHistoricalLog:
		return CurrentnessHistoricalOnly
	default:
		return CurrentnessUnknown
	}
}

// liveVerifiedCurrentness returns live_verified only when a positive payload came
// from an active probe. Attempted probes and non-active acquisitions stay unknown.
func liveVerifiedCurrentness(kind events.ObservationKind, verified bool) Currentness {
	if verified && kind == events.ObservationKindActiveProbe {
		return CurrentnessLiveVerified
	}
	return CurrentnessUnknown
}

// obsID and evID build the stable, per-event unique ids for an observation and its
// derived evidence. EventID is unique per event, so a discriminator that is unique
// within the event makes the id unique across the graph.
func obsID(eventID, discriminator string) string { return "obs:" + eventID + ":" + discriminator }
func evID(eventID, discriminator string) string  { return "ev:" + eventID + ":" + discriminator }

// srcs returns the single-element source slice for a producing tool, or nil when empty.
func srcs(source string) []string {
	if source == "" {
		return nil
	}
	return []string{source}
}

// unionSorted returns the sorted, de-duplicated union of two string slices.
func unionSorted(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
