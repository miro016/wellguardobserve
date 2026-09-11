package facts

import (
	"slices"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// Finding asset kinds, matching entities.AssetRef.Kind and the findings projection.
const (
	assetKindDomain   = entities.AssetKindDomain
	assetKindIP       = entities.AssetKindIP
	assetKindService  = entities.AssetKindService
	assetKindEndpoint = entities.AssetKindEndpoint
)

// applyFindingEvent handles the finding events: a raised finding becomes a
// FindingCandidate. It returns false for a type it does not handle so the caller
// records it under coverage.
func (g *Graph) applyFindingEvent(evt events.DomainEvent) bool {
	switch e := evt.(type) {
	case events.FindingRaised:
		g.applyFindingRaised(e)
	default:
		return false
	}
	return true
}

// applyFindingRaised folds a FindingRaised into a candidate plus its affects/evidence edges.
func (g *Graph) applyFindingRaised(e events.FindingRaised) {
	g.raiseFindingCandidate(e.Meta(), e.Rule, e.AssetKind, e.AssetID, e.FindingCategory,
		e.Title, e.Evidence, e.Recommendation, e.References, mapEventConfidence(e.Confidence))
}

// raiseFindingCandidate upserts the candidate for a rule/asset pair and records its
// finding_affects_asset edge, an observation+evidence on the affected asset, and the
// finding_supported_by_evidence edge. rawAssetID is the finding's natural asset key (a
// domain name, IP, service id, or certificate serial); the graph asset key is derived
// from it, but the candidate id keeps the raw key so it matches entities.FindingID.
func (g *Graph) raiseFindingCandidate(m events.EventMeta, rule, assetKind, rawAssetID,
	category, title, evidence, recommendation string, refs []string, conf Confidence) {
	assetKey := factsAssetKey(assetKind, rawAssetID)
	id := entities.FindingID(rule, entities.AssetRef{Kind: assetKind, ID: rawAssetID})
	c := g.upsertFindingCandidate(id, rule, category, title, assetKey, conf, m.Severity,
		refs, recommendation, m.EventID, m.CapturedAt)
	g.upsertRelationship(Relationship{Type: RelFindingAffectsAsset, From: id, To: assetKey,
		Confidence: conf, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})

	disc := "finding:" + id
	stmt := strings.TrimSpace(evidence)
	if stmt == "" {
		stmt = title
	}
	g.addObsEvidence(m, assetKey, "finding_observed", "finding_evidence", disc, stmt, conf, nil)
	eid := evID(m.EventID, disc)
	c.EvidenceIDs = appendUnique(c.EvidenceIDs, eid)
	g.upsertRelationship(Relationship{Type: RelFindingSupportedByEvidence, From: id, To: eid,
		EvidenceID: eid, Confidence: conf, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
}

// upsertFindingCandidate inserts a new candidate or merges into the existing one with the
// same id: widening the seen window, keeping the strongest confidence and severity,
// unioning references, and filling an empty title/recommendation.
func (g *Graph) upsertFindingCandidate(id, rule, category, title, assetKey string,
	conf Confidence, sev events.Severity, refs []string, recommendation, srcEventID string, at time.Time) *FindingCandidate {
	ex, ok := g.findIdx[id]
	if !ok {
		c := &FindingCandidate{
			ID: id, Rule: rule, Category: category, Title: title, AssetKey: assetKey,
			Confidence: conf,
			Severity:   sev, References: unionSorted(nil, refs), Recommendation: recommendation,
			SourceEventID: srcEventID, FirstSeen: at, LastSeen: at,
		}
		g.findIdx[id] = c
		return c
	}
	if !at.IsZero() && at.Before(ex.FirstSeen) {
		ex.FirstSeen = at
	}
	if at.After(ex.LastSeen) {
		ex.LastSeen = at
	}
	if confidenceRank(conf) > confidenceRank(ex.Confidence) {
		ex.Confidence = conf
	}
	if sev > ex.Severity {
		ex.Severity = sev
	}
	ex.References = unionSorted(ex.References, refs)
	if ex.Title == "" {
		ex.Title = title
	}
	if ex.Recommendation == "" {
		ex.Recommendation = recommendation
	}
	return ex
}

// factsAssetKey derives the graph asset key from a finding's asset kind and canonical id.
// A domain is normalized and an IP canonicalized because a producer may still hand over a
// differently spelled name or address; an endpoint is re-normalized through the same
// identity function that materialized the Endpoint asset; a service and a certificate id
// are already the graph key ("host/port/proto" and the entities.CertificateID key).
//
// This is a normalization, never a repair. A key that does not resolve to an asset stays
// unresolved and is reported by [Graph.Integrity] as a dangling finding edge, because
// silently rewriting it here would make facts disagree with the findings model and the
// threat scenarios about the same persisted event.
func factsAssetKey(kind, id string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case assetKindDomain:
		return normalizeFQDN(id)
	case assetKindIP:
		if c, _, ok := normalizeIP(id); ok {
			return c
		}
		return strings.TrimSpace(id)
	case assetKindEndpoint:
		if key, err := entities.EndpointID(id); err == nil {
			return key
		}
		return strings.TrimSpace(id)
	default:
		return strings.TrimSpace(id)
	}
}

// appendUnique appends v to s only if it is not already present, preserving order.
func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}
