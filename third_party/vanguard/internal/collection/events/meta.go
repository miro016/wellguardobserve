package events

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// Phase identifies the reconnaissance phase that produced an event.
type Phase string

const (
	// PhasePassive covers non-intrusive collection (crt.sh, DNS, ASN).
	PhasePassive Phase = "passive"
	// PhaseActive covers direct interaction with the target (port scan, HTTP probe).
	PhaseActive Phase = "active"
)

// ObservationKind states how a claim was obtained. It is independent of both
// confidence and time: a historical log can be highly trustworthy without proving
// that the subject is current.
type ObservationKind string

const (
	// ObservationKindInput marks a target supplied to Vanguard as scan input.
	ObservationKindInput ObservationKind = "input"
	// ObservationKindHistoricalLog marks a record retrieved from an append-only or
	// historical registry, such as a certificate transparency log.
	ObservationKindHistoricalLog ObservationKind = "historical_log"
	// ObservationKindPassiveSnapshot marks a third-party point-in-time claim.
	ObservationKindPassiveSnapshot ObservationKind = "passive_snapshot"
	// ObservationKindDNSAnswer marks data returned by a DNS query during the scan.
	ObservationKindDNSAnswer ObservationKind = "dns_answer"
	// ObservationKindActiveProbe marks a direct attempt to observe target behavior.
	// The payload records whether the attempt produced live verification.
	ObservationKindActiveProbe ObservationKind = "active_probe"
	// ObservationKindDerived marks an analysis result derived from other events.
	ObservationKindDerived ObservationKind = "derived"
	// ObservationKindLifecycle marks scan or phase control events rather than claims
	// about the target.
	ObservationKindLifecycle ObservationKind = "lifecycle"
	// ObservationKindOperational marks coverage, tool, or orchestration issues.
	ObservationKindOperational ObservationKind = "operational"
)

// Category groups events for filtering and rollups.
type Category string

const (
	// CategoryLifecycle marks a state transition or milestone event.
	CategoryLifecycle Category = "lifecycle"
	// CategoryDiscovery marks an asset discovery event.
	CategoryDiscovery Category = "discovery"
	// CategoryFinding marks a security finding event.
	CategoryFinding Category = "finding"
	// CategoryIssue marks a reconnaissance error or issue event.
	CategoryIssue Category = "issue"
)

// Severity ranks issues and findings. Higher values indicate greater impact.
// Ordered constants allow numeric comparison.
type Severity int

const (
	// SeverityInfo is the default severity for discovery events.
	SeverityInfo Severity = iota
	// SeverityLow indicates a minor finding or issue.
	SeverityLow
	// SeverityMedium indicates a non-fatal operational error or moderate finding.
	SeverityMedium
	// SeverityHigh indicates a fatal error or significant finding.
	SeverityHigh
	// SeverityCritical indicates a critical finding requiring immediate attention.
	SeverityCritical
)

// String returns the lowercase name of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RetrievalSource states how an observation reached Vanguard during this scan: from
// the provider itself, or from data compiled into the collector. It is orthogonal to
// EventMeta.Source, which always names the provider that produced the underlying data
// (for example "censys" or "crtsh") and never becomes a cache label - provider
// attribution, detector rules, data-quality comparisons, and projections keep their
// current meaning.
type RetrievalSource string

const (
	// RetrievalSourceService marks data the provider returned during this scan.
	RetrievalSourceService RetrievalSource = "service"
	// RetrievalSourceCacheEmbedded marks data returned from the development fixture
	// compiled into the tool package, so no provider request was made for it.
	RetrievalSourceCacheEmbedded RetrievalSource = "cache_embedded"
)

// EventMeta is the shared envelope embedded in every domain event.
type EventMeta struct {
	// EventID uniquely identifies this event (stable hash of payload + time).
	EventID string
	// ScanID correlates every event produced by a single scan run.
	ScanID string
	// CausationID is the EventID (domain or system) that triggered this event.
	// Empty for root lifecycle events.
	CausationID string
	// Source names the tool or component that produced the underlying data
	// (for example "crtsh", "dnsinfo", "asn", "orchestrator").
	Source string
	// Phase is the recon phase that produced the event.
	Phase Phase
	// Category groups the event for filtering.
	Category Category
	// Severity is meaningful for issues and findings; SeverityInfo otherwise.
	Severity Severity
	// ObservationKind states how the event's claim was obtained. It must not be
	// inferred from Source because one source can emit several kinds of claim.
	ObservationKind ObservationKind
	// CapturedAt is when Vanguard recorded the claim during this scan. It is not a
	// provider observation time, validity bound, or historical registry time.
	CapturedAt time.Time
	// UnscopedRequest marks an observation of a destination outside the engagement
	// scope, obtained by a request path that could not be authorized before it
	// dialed. It is false for every ordinary observation: Vanguard authorizes each
	// target-facing request, and only an explicitly enabled override (an embedded
	// tool whose own redirect loop cannot be gated) can produce a claim that is
	// checked after the fact and fails. Analysis and reporting use it to filter or
	// flag that data instead of mixing it with scope-enforced evidence.
	UnscopedRequest bool `json:"UnscopedRequest,omitempty"`
	// ToolCorrID optionally links this event back to the exact tool call that
	// produced it: it carries the same per-invocation correlation id the tool
	// events of that call were stamped with (tooleventlog CorrID), so an audit can
	// join a finding or discovery in events.jsonl to its provider response in
	// tooling.jsonl. Empty for events not derived from a single tool call
	// (lifecycle events, crawler discoveries, root-level enumeration results).
	// Stamped at event creation by the translator that reads CorrIDFrom(ctx).
	ToolCorrID string `json:"ToolCorrID,omitempty"`
	// RetrievalSource states whether the observation came from the provider during
	// this scan ([RetrievalSourceService]) or from the fixture compiled into the tool
	// package ([RetrievalSourceCacheEmbedded]). Empty is valid and is the value on
	// every event written before the field existed and on every tool that has not
	// adopted retrieval provenance, so absence means "not stated", never "service".
	// It never replaces Source: the producer stays the provider either way.
	RetrievalSource RetrievalSource `json:"RetrievalSource,omitempty"`
}

// NewEventID computes a stable, unique event ID from a timestamp and a payload.
// Duplicated from internal/collection/orchestration/crawler to keep this package dependency-free.
func NewEventID(t time.Time, payload any) string {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte(fmt.Sprintf("%#v", payload))
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%d_%x", t.UnixNano(), hash)
}

// VolatileMetaFields returns the names of the EventMeta envelope fields that are
// volatile: they differ between any two scan runs by construction (a per-event
// payload+time hash, per-run and per-call correlation ids, and wall-clock time), so
// anything comparing events across runs for a stable semantic identity must exclude
// them. The names are the JSON object keys; because EventMeta is embedded, they
// appear at the top level of a marshaled event. The remaining envelope fields
// (Source, Phase, Category, Severity, ObservationKind, UnscopedRequest,
// RetrievalSource) are semantic and retained. RetrievalSource in particular is
// deliberately not volatile: a cache-backed and a service-backed acquisition should
// stay distinguishable when comparing raw events across runs, even though their
// projections agree.
//
// This is the single source of truth for the volatile/semantic split. The
// scan-comparison feature (internal/projections/scandiff) consumes it instead of restating the
// list, and the meta reflection test asserts every name here is a real EventMeta
// field so the two cannot drift.
func VolatileMetaFields() []string {
	return []string{"EventID", "ScanID", "CausationID", "CapturedAt", "ToolCorrID"}
}
