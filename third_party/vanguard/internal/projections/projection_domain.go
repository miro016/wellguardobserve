package projections

import (
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/projections/findings"
)

// ProjectedFinding wraps a finding entity for presentation, so the app layers can
// render findings without importing the entities package.
type ProjectedFinding struct {
	entities.Finding
}

// Projection maintains the real-time in-memory state of a scan by applying domain
// events sequentially. Assets (domains, certificates, IPs, netblocks, services,
// endpoints) live in the [Inventory] relationship graph; this type adds the
// scan-health and weakness read models on top. All fields are safe to read after
// each ApplyDomain call.
type Projection struct {
	// Environments holds the reproducibility records in stream order. A collection
	// records one; the field is a slice because the fold copies what the stream
	// carried rather than deciding how many it should have carried.
	Environments []events.ScanEnvironmentRecorded
	// Issues holds all logged errors and failures (scan errors, not target weaknesses).
	Issues []Issue
	// ActiveApprovals holds the canonical positive target-traffic decisions in
	// stream order. Consumers deduplicate by kind and target when they need counts;
	// keeping every decision keeps the authorization history complete.
	ActiveApprovals []events.ActiveTargetApproved
	// Findings is the rollup read model over raised findings (target weaknesses),
	// deduplicated by Finding.ID and grouped by severity, category, and asset.
	Findings findings.Findings
	// Inventory is the relationship graph of every discovered asset and the edges
	// linking them. It is the single asset read model.
	Inventory Inventory
	// Lineage is the causal graph of every event in the scan, used to reconstruct
	// how any asset or finding was gathered.
	Lineage Lineage

	// latestCompletedAt is the latest ScanCompleted capture time seen so far, and
	// latestCapturedAt the latest capture time of any event. They are the two inputs
	// to the analysis cutoff (see AnalysisAsOf) and are tracked here because the fold
	// is streaming: nothing else knows when the collection finished.
	latestCompletedAt time.Time
	latestCapturedAt  time.Time
}

// AnalysisAsOf returns the fixed cutoff every temporal judgement over this projection
// must be evaluated against: the collection's completion time, or the latest
// observation when the stream carried no completion (flagged partial).
//
// It errors rather than returning a zero cutoff, because every event the orchestrator
// emits stamps CapturedAt: a stream with none is truncated or written by an
// incompatible vocabulary, and calling anything "current" against a zero cutoff would
// be silently wrong.
func (p *Projection) AnalysisAsOf() (events.AnalysisAsOf, error) {
	return events.AnalysisAsOfFrom(p.latestCompletedAt, p.latestCapturedAt)
}

// NewProjection creates a new Projection with initialized maps.
func NewProjection() Projection {
	return Projection{
		Inventory: NewInventory(),
		Findings:  findings.NewFindings(),
		Lineage:   NewLineage(),
	}
}

// HostView returns the unified, per-IP host model merged from the active scan and
// the censys/shodan/netlas provider facets. It is the single host model the
// risk model reasons over (see [HostView]).
func (p *Projection) HostView() HostView {
	return p.Inventory.HostView()
}

// SortedFindings returns the findings in priority order (severity desc) as
// presentation-friendly wrappers.
func (p *Projection) SortedFindings() []ProjectedFinding {
	sorted := p.Findings.Sorted()
	out := make([]ProjectedFinding, 0, len(sorted))
	for _, f := range sorted {
		out = append(out, ProjectedFinding{Finding: *f})
	}
	return out
}

// ApplyDomain updates the projection state based on the incoming domain event.
// Findings and issues are folded into their dedicated read models here; every
// asset and edge is folded by the inventory graph, and the causal lineage by the
// lineage graph. All three are driven from the same event stream.
func (p *Projection) ApplyDomain(evt events.DomainEvent) {
	// Normalize to the value form the orchestrator emits live so the findings/issue
	// arms below match a replayed (or test-built) pointer too; the inventory fold
	// normalizes again internally, which is a cheap no-op on a
	// value (see events.AsValue).
	evt = events.AsValue(evt)
	p.trackAnalysisTimes(evt)
	switch e := evt.(type) {
	case events.ScanEnvironmentRecorded:
		p.Environments = append(p.Environments, e)
	case events.ActiveTargetApproved:
		p.ActiveApprovals = append(p.ActiveApprovals, e)
	case events.FindingRaised:
		p.Findings.Apply(e)
	case events.IssueObserved:
		p.applyIssue(e)
	}

	p.Inventory.Apply(evt)
	p.Lineage.Apply(evt)
}

// trackAnalysisTimes records the two timestamps the analysis cutoff is derived from.
// A well-formed collection carries one completion; taking the latest rather than the
// first is corrupt-log tolerance, which keeps the cutoff at or after every
// observation. Every event keeps its own CapturedAt, so observation ages stay
// visible either way.
func (p *Projection) trackAnalysisTimes(evt events.DomainEvent) {
	at := evt.Meta().CapturedAt
	if at.After(p.latestCapturedAt) {
		p.latestCapturedAt = at
	}
	if _, ok := evt.(events.ScanCompleted); ok && at.After(p.latestCompletedAt) {
		p.latestCompletedAt = at
	}
}

func (p *Projection) applyIssue(e events.IssueObserved) {
	p.Issues = append(p.Issues, Issue{
		EventID:     e.Meta().EventID,
		At:          e.At(),
		Message:     e.Error,
		Source:      e.Meta().Source,
		Class:       e.Class,
		Severity:    e.Meta().Severity,
		Query:       e.Query,
		CausationID: e.Meta().CausationID,
		Payload:     e.Payload,
	})
}

// Issue represents a logged error or failure captured during a crawl.
type Issue struct {
	// EventID is the stable identity of the IssueObserved event.
	EventID string
	// At is when the issue occurred.
	At time.Time
	// Message is the structured issue description supplied by the producer. It is
	// kept separate from the event's log-oriented String rendering.
	Message string
	// Source is the component that raised the issue (for example "crawler",
	// "scope", "budget"), used to break out control decisions in the report.
	Source string
	// Class is the producer's own classification ("coverage", "timeout",
	// "dependency", ...), empty when the producer did not classify. The report
	// buckets on it in preference to guessing from Source.
	Class string
	// Severity ranks the issue.
	Severity events.Severity
	// Query is the domain search query if applicable.
	Query string
	// CausationID holds the unique ID of the system event that triggered this issue.
	CausationID string
	// Payload holds the raw JSON payload of the triggering system event.
	Payload string
}

// ProvenanceFromMeta derives an entity Provenance record from an event's
// metadata envelope. It lives in the projections layer so that the entities
// package never depends on the events package.
func ProvenanceFromMeta(m events.EventMeta) entities.Provenance {
	return entities.Provenance{
		EventID:         m.EventID,
		Source:          m.Source,
		Phase:           string(m.Phase),
		ObservationKind: string(m.ObservationKind),
		CapturedAt:      m.CapturedAt,
		UnscopedRequest: m.UnscopedRequest,
	}
}

// domainSource classifies how a domain was discovered from its parent linkage.
func domainSource(e events.DnsDomainNameDiscovered) entities.DiscoverySource {
	switch {
	case e.ParentDomain == "":
		return entities.SourceRoot
	case e.Domain == e.ParentDomain || strings.HasSuffix(e.Domain, "."+e.ParentDomain):
		return entities.SourceCrtshSubdomain
	default:
		return entities.SourceCrtshCert
	}
}

func toCertificate(c *events.CertificateData) entities.Certificate {
	cert, err := entities.NewCertificate(c.CommonName, c.IssuerName, c.SerialNumber, c.ValidFrom, c.ValidUntil, c.LoggedAt, c.LiveVerifiedAt, c.Domains)
	if err != nil {
		// Defensive fallback: certificates from crt.sh may occasionally lack a
		// serial or CN; keep what we have rather than dropping the discovery.
		cert = entities.Certificate{
			CommonName:     c.CommonName,
			IssuerName:     c.IssuerName,
			SerialNumber:   c.SerialNumber,
			ValidFrom:      c.ValidFrom,
			ValidUntil:     c.ValidUntil,
			LoggedAt:       c.LoggedAt,
			LiveVerifiedAt: c.LiveVerifiedAt,
			Domains:        append([]string(nil), c.Domains...),
		}
	}
	return cert
}
