package facts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/analysis"
)

// Evidence badge labels. A badge is the detail the exclusive class deliberately drops:
// one asset can be historically covered by CT, currently resolving, and live-probed at
// the same time, and an analyst needs to see all three even though the rollup has to pick
// one class to count it under.
const (
	badgeLiveProbe          = "live probe"
	badgeCurrentDNS         = "current DNS"
	badgeNotResolving       = "not resolving at scan time"
	badgeHistoricalCT       = "historical CT"
	badgeValidCertCoverage  = "valid certificate coverage"
	badgeExpiredCertCover   = "expired certificate coverage"
	badgeValidNow           = "validity covers as-of"
	badgeExpired            = "validity ended before as-of"
	badgeNotYetValid        = "validity starts after as-of"
	badgeScanTimeFallback   = "scan-time fallback only"
	badgeRecentPassivePfx   = "recent passive: "
	badgeStalePassivePrefix = "stale passive: "
)

// ClassifiedAsset is one asset placed in exactly one primary currentness class, with the
// full evidence detail kept alongside. Nothing is removed from the graph to produce it:
// every asset in the graph appears here exactly once.
type ClassifiedAsset struct {
	Type AssetType `json:"type"`
	Key  string    `json:"key"`
	// Primary is the single class this asset counts under in the exclusive rollup.
	Primary Currentness `json:"primary"`
	// Reason names the rule that chose Primary, so a surprising verdict is traceable
	// without re-deriving the classification.
	Reason string `json:"reason"`
	// Badges are every other piece of temporal evidence about the asset.
	Badges []string `json:"badges,omitempty"`
	// ObservationIDs are the observations behind the classification, so any subset can
	// be walked back to the raw evidence.
	ObservationIDs []string `json:"observation_ids,omitempty"`
	// Sources are the tools that contributed evidence, sorted.
	Sources []string `json:"sources,omitempty"`
	// LatestSourceObservedAt and LastLiveVerifiedAt are lifted from the asset's
	// temporal summary so a consumer can show the age behind the class.
	LatestSourceObservedAt time.Time `json:"latest_source_observed_at,omitzero"`
	LastLiveVerifiedAt     time.Time `json:"last_live_verified_at,omitzero"`
}

// ClassifiedRelationship is the same classification applied to a graph edge, so the
// timeline can style a historical cert_covers_name edge differently from a current
// resolves_to edge between the same two nodes.
type ClassifiedRelationship struct {
	Type    RelationshipType `json:"type"`
	From    string           `json:"from"`
	To      string           `json:"to"`
	Primary Currentness      `json:"primary"`
	Reason  string           `json:"reason"`
	Badges  []string         `json:"badges,omitempty"`
}

// ClassCount is one class and how many subjects fall in it, rendered as a list rather
// than a map so the output keeps precedence order instead of alphabetical order.
type ClassCount struct {
	Class Currentness `json:"class"`
	Count int         `json:"count"`
}

// TypeBreakdown is the exclusive class breakdown for one asset type, with the complete
// total it must sum to.
type TypeBreakdown struct {
	Type    AssetType    `json:"type"`
	Total   int          `json:"total"`
	ByClass []ClassCount `json:"by_class"`
}

// ClassifiedSurface answers "what appears current?" with mutually exclusive counts while
// the complete inventory stays intact beside it.
//
// It is strictly additive over the facts graph: it classifies, it never filters. Total is
// always the complete asset count, and the per-class counts always sum to it, so a reader
// can see immediately how much of the estate the current-looking subset actually is.
type ClassifiedSurface struct {
	AnalysisAsOf    time.Time `json:"analysis_as_of"`
	AnalysisPartial bool      `json:"analysis_partial,omitempty"`
	DataView        string    `json:"data_view"`
	// FreshnessWindows is the declared policy that produced every recent_passive
	// verdict below, printed so a threshold can never hide the evidence.
	FreshnessWindows string `json:"freshness_windows"`
	// Total is the complete number of assets in the graph, never a filtered subset.
	Total int `json:"total"`
	// ByClass partitions Total exactly, in precedence order.
	ByClass []ClassCount `json:"by_class"`
	// ByType gives the same partition per asset type.
	ByType []TypeBreakdown `json:"by_type"`
	// Assets and Relationships carry the per-subject detail.
	Assets        []ClassifiedAsset        `json:"assets"`
	Relationships []ClassifiedRelationship `json:"relationships"`
}

// ClassifiedSurface classifies every asset and relationship in the graph against the
// graph's own analysis cutoff and the given freshness policy.
//
// The classification rules it encodes, each of which exists because the opposite reading
// is tempting and wrong:
//
//   - CT coverage proves historical certificate issuance and namespace use. It proves
//     nothing about current DNS, ownership, or service.
//   - An unexpired certificate is valid_unverified, never live_verified. Validity is a
//     statement by the issuer, not evidence that anything serves the certificate.
//   - valid_unverified needs a genuine validity interval, so it applies to a certificate
//     and to certificate coverage. A hostname covered by an unexpired certificate earns a
//     badge for that coverage, and its own class stays historical_only or
//     currentness_unknown until something actually observes the name.
//   - A successful active response is current only as of that observation.
//   - A failed or skipped probe is a coverage gap, never proof of absence.
//   - An empty successful DNS answer means the name did not resolve at scan time; the
//     name stays in the complete history either way.
func (g *Graph) ClassifiedSurface() ClassifiedSurface {
	return classifiedSurface(g.snap(), g.asOf, g.policy)
}

// classifiedSurface does the work over an already-built snapshot, so [Graph.snap] can
// embed the result without re-entering [Graph.ClassifiedSurface] and recursing.
func classifiedSurface(s snapshot, cutoff events.AnalysisAsOf, policy analysis.FreshnessPolicy) ClassifiedSurface {
	asOf := cutoff.At
	obsByAsset := make(map[string][]Observation, len(s.Observations))
	for _, o := range s.Observations {
		obsByAsset[o.AssetKey] = append(obsByAsset[o.AssetKey], o)
	}
	certCoverage := certificateCoverage(s, asOf)

	out := ClassifiedSurface{
		AnalysisAsOf:     asOf,
		AnalysisPartial:  cutoff.Partial,
		DataView:         events.DataViewCompleteHistory,
		FreshnessWindows: policy.String(),
		Total:            len(s.Assets),
	}
	byClass := map[Currentness]int{}
	byType := map[AssetType]map[Currentness]int{}
	for _, a := range s.Assets {
		ca := classifyAsset(a, obsByAsset[a.Key], certCoverage[a.Key], asOf, policy)
		out.Assets = append(out.Assets, ca)
		byClass[ca.Primary]++
		if byType[a.Type] == nil {
			byType[a.Type] = map[Currentness]int{}
		}
		byType[a.Type][ca.Primary]++
	}
	for _, r := range s.Relationships {
		out.Relationships = append(out.Relationships, classifyRelationship(r, asOf, policy))
	}
	out.ByClass = orderedCounts(byClass)
	types := make([]AssetType, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	for _, t := range types {
		total := 0
		for _, n := range byType[t] {
			total += n
		}
		out.ByType = append(out.ByType, TypeBreakdown{Type: t, Total: total, ByClass: orderedCounts(byType[t])})
	}
	return out
}

// orderedCounts renders a class tally in precedence order, dropping empty classes.
func orderedCounts(counts map[Currentness]int) []ClassCount {
	out := make([]ClassCount, 0, len(counts))
	for _, c := range currentnessPrecedence {
		if n := counts[c]; n > 0 {
			out = append(out, ClassCount{Class: c, Count: n})
		}
	}
	return out
}

// nameCoverage records what the certificates covering one name say at the cutoff.
type nameCoverage struct {
	validNow bool
	expired  bool
}

// certificateCoverage folds the cert_covers_name edges into, per covered name, whether
// any covering certificate is still valid at the cutoff and whether any has expired. A
// name can legitimately have both.
func certificateCoverage(s snapshot, asOf time.Time) map[string]nameCoverage {
	certValid := make(map[string]bool, len(s.Assets))
	certKnown := make(map[string]bool, len(s.Assets))
	for _, a := range s.Assets {
		if a.Type != AssetCertificate {
			continue
		}
		certKnown[a.Key] = true
		certValid[a.Key] = intervalsCover(a.ValidIntervals, asOf)
	}
	out := make(map[string]nameCoverage)
	for _, r := range s.Relationships {
		if r.Type != RelCertCoversName || !certKnown[r.From] {
			continue
		}
		cov := out[r.To]
		if certValid[r.From] {
			cov.validNow = true
		} else {
			cov.expired = true
		}
		out[r.To] = cov
	}
	return out
}

// intervalsCover reports whether any interval contains the cutoff. Both bounds are
// inclusive, and a zero end means the interval is open and still running.
func intervalsCover(intervals []Interval, at time.Time) bool {
	if at.IsZero() {
		return false
	}
	for _, iv := range intervals {
		if !iv.From.IsZero() && iv.From.After(at) {
			continue
		}
		if iv.Until.IsZero() || !iv.Until.Before(at) {
			return true
		}
	}
	return false
}

// classifyAsset places one asset in exactly one class and collects every badge its
// evidence earns.
func classifyAsset(a Asset, obs []Observation, cov nameCoverage, asOf time.Time, policy analysis.FreshnessPolicy) ClassifiedAsset {
	ca := ClassifiedAsset{
		Type: a.Type, Key: a.Key, Sources: a.Sources,
		LatestSourceObservedAt: a.LatestSourceObservedAt,
		LastLiveVerifiedAt:     a.LastLiveVerifiedAt,
	}
	var live, resolved, negativeDNS bool
	ca.ObservationIDs, live, resolved, negativeDNS = assetObservationSignals(obs)

	// Not every asset carries its own observation: a DNS record node is created by the
	// lookup that resolved it, while the observation hangs off the owner name. Reading
	// the asset's own assertions catches those, and requiring a dated assertion keeps a
	// name that did not resolve from counting as resolved - the empty answer records the
	// same acquisition kind, but with no subject time.
	live = live || hasDatedKind(a.Assertions, events.ObservationKindActiveProbe)
	resolved = resolved || hasDatedKind(a.Assertions, events.ObservationKindDNSAnswer)

	historicalLog := hasKind(a.Assertions, events.ObservationKindHistoricalLog)
	freshSource, staleSource := passiveFreshness(a.Assertions, asOf, policy)
	validNow := intervalsCover(a.ValidIntervals, asOf)
	bounded, allEnded := boundedAndEnded(a.ValidIntervals, asOf)

	ca.Badges = assetBadges(assetEvidence{
		live: live, resolved: resolved, negativeDNS: negativeDNS,
		historicalLog: historicalLog, validNow: validNow, bounded: bounded, allEnded: allEnded,
		freshSource: freshSource, staleSource: staleSource, coverage: cov,
		fallbackOnly: a.SourceTimeMissing && !a.SourceDated,
	})

	switch {
	case live:
		ca.Primary, ca.Reason = CurrentnessLiveVerified, "an active probe got a positive response during this scan"
	case resolved:
		ca.Primary, ca.Reason = CurrentnessCurrentlyResolved, "a DNS collection returned a positive record during this scan"
	case validNow && a.Type == AssetCertificate:
		ca.Primary, ca.Reason = CurrentnessValidUnverified, "its validity interval covers the as-of time, with no live observation"
	case freshSource != "":
		ca.Primary, ca.Reason = CurrentnessRecentPassive, "observed by "+freshSource+" inside its declared freshness window"
	case bounded && allEnded:
		ca.Primary, ca.Reason = CurrentnessHistoricalOnly, "every bounded assertion ended before the as-of time"
	case staleSource != "":
		ca.Primary, ca.Reason = CurrentnessHistoricalOnly, "the newest observation, by "+staleSource+", is older than its declared freshness window"
	case historicalLog:
		ca.Primary, ca.Reason = CurrentnessHistoricalOnly, "its only evidence is a historical log entry"
	case a.SourceTimeMissing && !a.SourceDated:
		ca.Primary, ca.Reason = CurrentnessUnknown, "no source supplied an observation time; only the scan-time fallback dates it"
	default:
		ca.Primary, ca.Reason = CurrentnessUnknown, "its evidence supports no defensible reading of current state"
	}
	return ca
}

// assetObservationSignals extracts the observation-level evidence used by the asset
// classifier. Validity and passive freshness remain assertion-level decisions because a
// collapsed observation label no longer carries their bounds or source time.
func assetObservationSignals(obs []Observation) (ids []string, live, resolved, negativeDNS bool) {
	ids = make([]string, 0, len(obs))
	for _, o := range obs {
		ids = append(ids, o.ID)
		switch o.Currentness {
		case CurrentnessLiveVerified:
			live = true
		case CurrentnessCurrentlyResolved:
			resolved = true
		case CurrentnessUnknown:
			negativeDNS = negativeDNS || o.Type == "dns_lookup_observed"
		case CurrentnessValidUnverified, CurrentnessRecentPassive, CurrentnessHistoricalOnly:
		}
	}
	sort.Strings(ids)
	return ids, live, resolved, negativeDNS
}

// assetEvidence is the decided evidence about one asset, gathered so the badge list is
// built in one place instead of being appended to along the classification path.
type assetEvidence struct {
	live, resolved, negativeDNS bool
	historicalLog               bool
	validNow, bounded, allEnded bool
	freshSource, staleSource    string
	coverage                    nameCoverage
	fallbackOnly                bool
}

// assetBadges renders every piece of evidence as a label, including the evidence the
// exclusive class did not win on.
func assetBadges(e assetEvidence) []string {
	var badges []string
	add := func(b string) { badges = append(badges, b) }
	if e.live {
		add(badgeLiveProbe)
	}
	if e.resolved {
		add(badgeCurrentDNS)
	}
	if e.negativeDNS && !e.resolved {
		add(badgeNotResolving)
	}
	if e.historicalLog {
		add(badgeHistoricalCT)
	}
	switch {
	case e.validNow:
		add(badgeValidNow)
	case e.bounded && e.allEnded:
		add(badgeExpired)
	case e.bounded:
		add(badgeNotYetValid)
	}
	if e.coverage.validNow {
		add(badgeValidCertCoverage)
	}
	if e.coverage.expired {
		add(badgeExpiredCertCover)
	}
	if e.freshSource != "" {
		add(badgeRecentPassivePfx + e.freshSource)
	}
	if e.staleSource != "" {
		add(badgeStalePassivePrefix + e.staleSource)
	}
	if e.fallbackOnly {
		add(badgeScanTimeFallback)
	}
	return badges
}

// passiveFreshness returns the source of the newest dated point observation that is
// still inside its declared window, and the source of the newest one that is not. Both
// are empty when no assertion carries a source-supplied observation time.
func passiveFreshness(assertions []TemporalAssertion, asOf time.Time, policy analysis.FreshnessPolicy) (fresh, stale string) {
	var freshAt, staleAt time.Time
	for _, a := range assertions {
		if a.SourceObservedAt.IsZero() {
			continue
		}
		if policy.IsFresh(a.Source, a.SourceObservedAt, asOf) {
			if a.SourceObservedAt.After(freshAt) {
				freshAt, fresh = a.SourceObservedAt, a.Source
			}
			continue
		}
		if a.SourceObservedAt.After(staleAt) {
			staleAt, stale = a.SourceObservedAt, a.Source
		}
	}
	return fresh, stale
}

// boundedAndEnded reports whether the subject has any genuine validity interval, and
// whether every one of them ended before the cutoff.
func boundedAndEnded(intervals []Interval, asOf time.Time) (bounded, allEnded bool) {
	if len(intervals) == 0 || asOf.IsZero() {
		return false, false
	}
	allEnded = true
	for _, iv := range intervals {
		if iv.Until.IsZero() || !iv.Until.Before(asOf) {
			allEnded = false
		}
	}
	return true, allEnded
}

// hasKind reports whether any assertion was acquired the given way.
func hasKind(assertions []TemporalAssertion, kind events.ObservationKind) bool {
	for _, a := range assertions {
		if a.ObservationKind == kind {
			return true
		}
	}
	return false
}

// hasDatedKind reports whether any assertion acquired the given way actually placed the
// subject in time. An undated assertion of the same kind is a mention or a negative
// result, and neither is evidence that the subject was there.
func hasDatedKind(assertions []TemporalAssertion, kind events.ObservationKind) bool {
	for _, a := range assertions {
		if a.ObservationKind == kind && !a.SourceTimeMissing {
			return true
		}
	}
	return false
}

// classifyRelationship applies the same vocabulary to an edge, using only the edge's own
// assertions: an edge has no observations of its own, and borrowing its endpoints' would
// let a live host make a historical certificate-coverage edge look current.
func classifyRelationship(r Relationship, asOf time.Time, policy analysis.FreshnessPolicy) ClassifiedRelationship {
	cr := ClassifiedRelationship{Type: r.Type, From: r.From, To: r.To}
	validNow := intervalsCover(r.ValidIntervals, asOf)
	bounded, allEnded := boundedAndEnded(r.ValidIntervals, asOf)
	fresh, stale := passiveFreshness(r.Assertions, asOf, policy)
	liveEdge := !r.LastLiveVerifiedAt.IsZero() || hasKind(r.Assertions, events.ObservationKindActiveProbe)
	resolvedEdge := hasKind(r.Assertions, events.ObservationKindDNSAnswer)

	switch {
	case liveEdge:
		cr.Primary, cr.Reason = CurrentnessLiveVerified, "an active probe established this edge during this scan"
	case resolvedEdge:
		cr.Primary, cr.Reason = CurrentnessCurrentlyResolved, "a DNS answer established this edge during this scan"
	case validNow:
		cr.Primary, cr.Reason = CurrentnessValidUnverified, "its validity interval covers the as-of time, with no live observation"
	case fresh != "":
		cr.Primary, cr.Reason = CurrentnessRecentPassive, "asserted by "+fresh+" inside its declared freshness window"
	case bounded && allEnded:
		cr.Primary, cr.Reason = CurrentnessHistoricalOnly, "every bounded assertion ended before the as-of time"
	case stale != "":
		cr.Primary, cr.Reason = CurrentnessHistoricalOnly, "the newest assertion, by "+stale+", is older than its declared freshness window"
	case hasKind(r.Assertions, events.ObservationKindHistoricalLog):
		cr.Primary, cr.Reason = CurrentnessHistoricalOnly, "its only evidence is a historical log entry"
	default:
		cr.Primary, cr.Reason = CurrentnessUnknown, "its evidence supports no defensible reading of current state"
	}
	cr.Badges = assetBadges(assetEvidence{
		live: liveEdge, resolved: resolvedEdge,
		historicalLog: hasKind(r.Assertions, events.ObservationKindHistoricalLog),
		validNow:      validNow, bounded: bounded, allEnded: allEnded,
		freshSource: fresh, staleSource: stale,
	})
	return cr
}

// Markdown renders the exclusive breakdown with the complete total always in view.
func (s ClassifiedSurface) Markdown() string {
	var sb strings.Builder
	sb.WriteString("## Classified surface\n\n")
	fmt.Fprintf(&sb, "Every one of the %d assets in the complete graph appears in exactly one class below; "+
		"nothing is filtered out. Freshness windows: %s.\n\n", s.Total, s.FreshnessWindows)
	sb.WriteString("| Currentness | Assets |\n|---|---|\n")
	for _, c := range s.ByClass {
		fmt.Fprintf(&sb, "| %s | %d |\n", c.Class, c.Count)
	}
	fmt.Fprintf(&sb, "| **complete total** | **%d** |\n\n", s.Total)

	sb.WriteString("### By asset type\n\n")
	sb.WriteString("| Asset type | Total | Breakdown |\n|---|---|---|\n")
	for _, t := range s.ByType {
		parts := make([]string, 0, len(t.ByClass))
		for _, c := range t.ByClass {
			parts = append(parts, fmt.Sprintf("%s %d", c.Class, c.Count))
		}
		fmt.Fprintf(&sb, "| %s | %d | %s |\n", t.Type, t.Total, strings.Join(parts, ", "))
	}
	sb.WriteString("\n")
	return sb.String()
}
