package facts

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// applyHTTPRedirect folds one response-backed redirect without claiming the
// destination answered. The responding URL is a live Endpoint joined to the host in its
// own URL authority by serves_endpoint; the destination is only a
// Domain/Subdomain/ExternalDomain/IP reference with unknown currentness.
func (g *Graph) applyHTTPRedirect(e events.HttpRedirectObserved) {
	m := e.Meta()
	fromURL, err := entities.EndpointID(e.FromURL)
	if err != nil {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: "invalid redirect source URL: " + err.Error(), RawEventID: m.EventID})
		return
	}
	toURL, err := entities.EndpointID(e.ToURL)
	if err != nil {
		g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
			Message: "invalid redirect destination URL: " + err.Error(), RawEventID: m.EventID})
		return
	}
	fromHost, fromType, fromVersion, ok := httpURLHost(fromURL, g.rootTarget)
	if !ok {
		return
	}
	toHost, toType, toVersion, ok := httpURLHost(toURL, g.rootTarget)
	if !ok {
		return
	}

	// FromURL returned the 3xx response, so both its endpoint and host carry a
	// dated active assertion. The destination gets a no-subject-time reference.
	g.upsertAsset(Asset{Type: AssetEndpoint, Key: fromURL,
		Attributes: map[string]any{attrURL: fromURL, attrStatusCode: e.StatusCode},
		FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	g.upsertAsset(Asset{Type: fromType, Key: fromHost, Attributes: hostAssetAttributes(fromHost, fromVersion),
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
	g.upsertAssetClaim(Asset{Type: toType, Key: toHost,
		Attributes: hostAssetAttributes(toHost, toVersion), Sources: srcs(m.Source)}, claim{NoSubjectTime: true})

	metadata := map[string]any{
		"from_url": fromURL, "to_url": toURL, "from_host": fromHost, "to_host": toHost,
		attrStatusCode: e.StatusCode, "hop": e.Hop, "disposition": string(e.Disposition),
	}
	if e.Reason != "" {
		metadata["reason"] = e.Reason
	}
	disc := "redirect:" + strconv.Itoa(e.Hop)
	statement := fmt.Sprintf("%s observed HTTP %d redirect from %s to %s (%s).",
		m.Source, e.StatusCode, fromURL, toURL, e.Disposition)
	if e.Reason != "" {
		statement = fmt.Sprintf("%s observed HTTP %d redirect from %s to %s (%s: %s).",
			m.Source, e.StatusCode, fromURL, toURL, e.Disposition, e.Reason)
	}
	g.addObsEvidenceWithCurrentness(m, fromURL, "http_redirect_observed", "http_redirect_evidence", disc,
		statement, ConfidenceHigh, CurrentnessLiveVerified, metadata)
	evidenceID := evID(m.EventID, disc)
	// The 3xx came back from FromURL's authority, so the responding Endpoint gets the
	// same host edge an HttpEndpointDiscovered would have drawn. Without it the Endpoint
	// hangs off redirects_to alone and consumers cannot walk from the host to the URL
	// that answered. A later endpoint event on the same URL merges into this edge.
	g.upsertRelationship(Relationship{Type: RelServesEndpoint, From: fromHost, To: fromURL,
		EvidenceID: evidenceID, Confidence: ConfidenceHigh, Mode: m.Phase,
		SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt})
	g.upsertRelationship(Relationship{
		Type: RelRedirectsTo, From: fromURL, To: toHost, EvidenceID: evidenceID,
		Confidence: ConfidenceHigh, Mode: m.Phase, SourceEventID: m.EventID,
		FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt,
		Metadata: map[string]any{
			"to_urls": []string{toURL}, "dispositions": []string{string(e.Disposition)},
			"status_codes": []int{e.StatusCode}, "hops": []int{e.Hop},
		},
	})
	g.mergeRedirectRelationshipMetadata(fromURL, toHost, toURL, string(e.Disposition), e.Reason, e.StatusCode, e.Hop)
}

// mergeRedirectRelationshipMetadata retains every corroborating decision on a
// host edge rather than letting the first event freeze its summary metadata.
func (g *Graph) mergeRedirectRelationshipMetadata(fromURL, toHost, toURL, disposition, reason string, status, hop int) {
	rel := g.relIdx[string(RelRedirectsTo)+"\x00"+fromURL+"\x00"+toHost]
	if rel == nil {
		return
	}
	if rel.Metadata == nil {
		rel.Metadata = map[string]any{}
	}
	rel.Metadata["to_urls"] = unionSorted(stringSlice(rel.Metadata["to_urls"]), []string{toURL})
	rel.Metadata["dispositions"] = unionSorted(stringSlice(rel.Metadata["dispositions"]), []string{disposition})
	if reason != "" {
		rel.Metadata["reasons"] = unionSorted(stringSlice(rel.Metadata["reasons"]), []string{reason})
	}
	rel.Metadata["status_codes"] = unionSortedInts(intSlice(rel.Metadata["status_codes"]), status)
	rel.Metadata["hops"] = unionSortedInts(intSlice(rel.Metadata["hops"]), hop)
}

func stringSlice(value any) []string {
	values, _ := value.([]string)
	return values
}

func intSlice(value any) []int {
	values, _ := value.([]int)
	return values
}

func unionSortedInts(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Ints(values)
	return values
}
