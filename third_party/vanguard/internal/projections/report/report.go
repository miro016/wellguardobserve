package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections"
	"github.com/velgard-sk/vanguard/internal/projections/analysis"
	"github.com/velgard-sk/vanguard/internal/projections/collectionhealth"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
	"github.com/velgard-sk/vanguard/internal/projections/netaudit"
	"github.com/velgard-sk/vanguard/internal/projections/threats"
)

// topFindingsCap bounds how many findings the report details in full.
const (
	topFindingsCap = 10
	unknownLabel   = "unknown"
)

// Report is the operator-facing summary derived from the other read models. It
// is deterministic: every field is a pure function of the event stream, so the
// same scan always yields the same report.
type Report struct {
	ScanID      string
	RootTarget  string
	StartedAt   time.Time
	CompletedAt time.Time
	// Environments records the reproducibility inputs the collection recorded.
	Environments []events.ScanEnvironmentRecorded

	// AnalysisAsOf is the fixed cutoff every temporal claim in this report was
	// evaluated against. Every use of current, expired, expiring, recent, or stale
	// below is relative to it, so it is stated on the first page rather than left
	// for the reader to infer from the scan times.
	AnalysisAsOf time.Time
	// AnalysisAsOfPartial marks a cutoff taken from the latest observation because
	// the stream carried no scan completion. The scan may have been interrupted, so
	// evidence a finished run would have produced is missing, not absent.
	AnalysisAsOfPartial bool
	// DataView states that nothing was filtered out of this report: it is the
	// complete record with currentness classification applied. It describes event
	// filtering only; whether collection itself completed is SourceCollection.
	DataView string
	// SourceCollection is the capture manifest's verdict on the collection that
	// produced this report: how the collection ended and exactly what
	// collection work it lost. It is copied from the manifest, never derived from
	// the event stream or the tool log, and it is the first thing the report states
	// because a degraded collection makes every absence below unsafe to read as
	// evidence of absence. Nil for a caller with no capture manifest, and the report
	// then says nothing about source completeness rather than implying it was clean.
	SourceCollection *collectionhealth.Summary `json:",omitempty"`
	// FreshnessWindows is the declared per-source policy behind every recent-passive
	// verdict below, printed so a threshold can never hide the evidence it judged.
	FreshnessWindows string
	// Surface is the classified asset view over the same event stream: the exclusive
	// currentness breakdown that every mixed count below is decomposed by. Nil when
	// the caller had no facts graph, and the report then states totals without a
	// composition rather than implying one.
	Surface *facts.ClassifiedSurface `json:",omitempty"`
	// TemporalCoverage accounts for source dating, fallbacks, freshness, and detected
	// contradictions over the same complete event stream. It is the facts graph's own
	// temporal-quality accounting, serialized here byte-for-byte identical to the copy in
	// facts.json/facts.md so a reader diffing the two artifacts never sees a phantom
	// conflict. Report-only cross-projection checks live in Reconciliation, not here.
	TemporalCoverage *facts.TemporalCoverage `json:",omitempty"`
	// Reconciliation holds report-only entity-to-facts cross-checks that exist only where
	// both projections are available (the report path). It is kept out of TemporalCoverage
	// precisely so that block stays identical across artifacts. Nil when the caller had no
	// facts graph or when every view reconciled.
	Reconciliation *Reconciliation `json:",omitempty"`

	// Attack surface counts.
	DomainCount int
	// IPCount is len(Hosts): the same merged host-view count as the Hosts table
	// below, so the summary and the table never disagree. It includes
	// provider-only IPs (Censys/Shodan/Netlas reported, never actively scanned),
	// not just the actively/DNS-seeded ones.
	IPCount       int
	NetblockCount int
	CertCount     int
	// ServiceCount is the complete service surface: every service the facts graph
	// classifies on a socket, including provider-reported (Censys/Shodan/Netlas) services
	// that the active phase never confirmed. It is the headline total so a machine consumer
	// reading this field alone does not silently lose the passive service surface. When no
	// facts graph was built it falls back to ServiceCountActive.
	ServiceCount int
	// ServiceCountActive is the subset actively confirmed or DNS-seeded (the entity
	// ServiceDiscovered inventory). ServiceCount minus this is the provider-only surface;
	// the Attack Surface composition shows the same split by currentness (live_verified
	// versus recent_passive).
	ServiceCountActive int
	// ServiceCountUDP is the subset of ServiceCountActive confirmed on udp: a UDP
	// port that answered a probe. It is reported separately because a UDP service is
	// a different kind of surface, and because a reader comparing runs needs to see a
	// UDP pass appear or disappear rather than watch one number move. Ports the UDP
	// pass could not settle are not counted here: an unanswered UDP port is
	// open|filtered, which is neither a service nor a clean negative, and it is
	// recorded as a coverage gap instead.
	ServiceCountUDP int
	// UnreachableIPv6Count is the number of IPv6-only addresses the active phase
	// could not probe because the scanner has no IPv6 route. They are a coverage
	// gap, not part of the probed surface; surfaced so the gap drives a next step.
	UnreachableIPv6Count int

	// Hosts is the unified per-IP view merged from the active scan and the
	// censys/shodan/netlas provider facets, sorted by IP. It is the single host
	// model, so consumers do not reconcile separate provider facets.
	Hosts []Host

	// Services is the provider-inclusive service identity index: one row per socket
	// in the merged host view, including the passive-provider ones the active phase
	// never confirmed. It answers what is exposed, how it was identified, how certain
	// the observation is, who reported it, and how old the evidence is. It carries no
	// raw evidence: the banner text, script output, and CPEs stay in the service
	// entity snapshots.
	Services []ServiceIdentity

	// ServiceAssessments are the per-service TLS and SSH postures, in service order.
	// They sit beside Hosts rather than inside it because an assessment is about one
	// service and one server name, and a host row that averaged several of them
	// would hide the one endpoint that is misconfigured.
	ServiceAssessments []ServiceAssessment

	// WebApps are the HTTP(S) applications exposed on the estate: the endpoints
	// discovered in the active phase with their status, server software, and the
	// technologies fingerprinted on them. Sorted by URL.
	WebApps []WebApp

	// Findings rollup.
	FindingsBySeverity map[int]int
	TopFindings        []Finding // sorted, most severe first

	// Risk is the per-customer risk posture rolled up from the findings.
	Risk RiskModel
	// Threats are the curated attack-path scenarios that fired.
	Threats []threats.ThreatScenario

	// Operational health.
	IssueCount int
	// Issues is the complete structured issue ledger. The classified slices below
	// are sorted subsets used by the compact operator report.
	Issues []Issue
	// CoverageGaps are active-phase reachability/skip issues: a target was not
	// fully probed (e.g. unreachable IPv6-only host), so the missing port/TLS/web
	// data is a gap, not a clean result. ToolErrors are genuine tool failures. Both
	// are distinct from the scope/budget control decisions below.
	CoverageGaps []Issue
	ToolErrors   []Issue

	// Scope and budget control decisions (skips), for the audit trail.
	ScopeExclusions  []Issue
	BudgetExclusions []Issue

	// ScopeAccounting is the deterministic scope ledger (discovered, in-scope,
	// referenced, skipped, and redirect/provider/budget decision counts) derived
	// from the inventory and issue stream. Nil only for a zero projection.
	ScopeAccounting *ScopeAccounting `json:",omitempty"`
	// ThirdPartyRedirects is the normalized redirect dependency view: one row per
	// (source host, destination host, disposition), with the contributing tools and
	// rejection reasons unioned. A destination here is a reference, not a live
	// endpoint.
	ThirdPartyRedirects []RedirectEdge `json:",omitempty"`

	// NetworkAudit is the packet-capture evidence: one health/verdict row per
	// execution reconciling the engagement exclusions with the observed traffic. It
	// is a second, independent evidence source that supplements the event-derived
	// views and never alters findings or risk. Nil only for a library caller that
	// supplied no model; the operator report always provides one (which itself may
	// report every capture absent), so the field carries no omitempty: a machine
	// reader can always tell packet evidence was considered.
	NetworkAudit *netaudit.Model

	// Suggested follow-up actions for the operator.
	NextSteps []string
}

// Issue is one structured IssueObserved row retained by the report and complete
// issue ledger.
type Issue struct {
	// EventID is the stable event identity.
	EventID string
	// CapturedAt is when the issue was observed.
	CapturedAt time.Time
	// Source is the component that raised the issue.
	Source string
	// Class is the producer's classification and may be empty.
	Class string
	// Severity ranks the issue; higher values are more important.
	Severity events.Severity
	// Query is the affected target or provider query.
	Query string
	// Message is the producer's structured error or coverage description.
	Message string
	// CausationID identifies the triggering event when one exists.
	CausationID string `json:",omitempty"`
}

// Reconciliation is the report-only accounting of where the entity projection (which
// supplies the headline totals) and the classified facts surface (which supplies
// currentness) disagree. It is deliberately separate from [facts.TemporalCoverage]:
// the shared coverage block is identical wherever it is serialized, while these
// anomalies exist only on the report path, where both projections are in hand. Neither
// side is ever rescaled or dropped to force agreement; a mismatch is recorded, not hidden.
type Reconciliation struct {
	// Anomalies are the entity-to-facts count mismatches and cross-projection
	// currentness contradictions, sorted deterministically.
	Anomalies []facts.TemporalAnomaly
}

// coverageIssueSources are the active-probe sources whose IssueObserved entries
// are reachability/coverage gaps (a target was skipped or unreachable), not tool
// errors. Kept as string literals so the projections layer stays free of an
// orchestration import.
var coverageIssueSources = map[string]bool{
	"portscan":  true,
	"https":     true,
	"webinfo":   true,
	"httpprobe": true,
	"smtp":      true,
	// "coverage" is the passive-phase CT cross-check: crt.sh's certificate/subdomain
	// set came back materially shorter than the certspotter corroborator's, a likely
	// truncated crt.sh response - a coverage gap, not a tool error.
	"coverage": true,
}

// coverageIssueClasses are the producer-declared classes that mean a target went
// unmeasured. A tool that raises both kinds under one source - an unreachable host
// and a missing dependency - cannot be bucketed by source, and calling the
// unreachable host a "tool error" tells the reader the opposite of what happened.
var coverageIssueClasses = map[string]bool{
	"coverage": true,
	"timeout":  true,
}

// isCoverageIssue decides which half of the Issues section an issue belongs in.
// The producer's own class wins when it set one; otherwise the source decides, so
// a tool that never classified keeps behaving as it did.
func isCoverageIssue(class, source string) bool {
	if class != "" {
		return coverageIssueClasses[class]
	}
	return coverageIssueSources[source]
}

// WebApp is a web application surfaced in the report: an HTTP(S) endpoint,
// the status it returned, its server software, and the technologies fingerprinted
// on it (merged across every tool that probed the same URL).
type WebApp struct {
	URL          string
	Status       int
	Server       string
	Technologies []WebTechnology
	// Unscoped marks an application the scan reached outside the engagement scope:
	// the GoScans web modules, run with tools.goscans.ignore_http_scope, fetched it
	// before the destination could be refused, and the scope check that ran on the
	// result rejected it. The row is rendered as such so the reader never mistakes
	// it for scope-enforced evidence.
	Unscoped bool
}

// WebTechnology is one technology on a web application with the metadata merged
// from every tool that reported it. Categories, CPEs, and Sources are sorted sets;
// they are empty when no contributing tool carries that kind of data.
type WebTechnology struct {
	Name       string
	Version    string
	Categories []string
	CPEs       []string
	Sources    []string
}

// Label is the compact "name version" rendering used in tables.
func (t WebTechnology) Label() string {
	if t.Version == "" {
		return t.Name
	}
	return t.Name + " " + t.Version
}

// HasMetadata reports whether the entry carries anything beyond name and version,
// so the renderer can skip an empty detail section.
func (t WebTechnology) HasMetadata() bool {
	return len(t.Categories) > 0 || len(t.CPEs) > 0
}

// Host is one host's row in the unified host view: the merge of the active
// scan and the provider facets. ConfirmedPorts (observed open by the scan) versus
// TotalPorts distinguishes live attack surface from provider-only claims.
type Host struct {
	IP             string
	Reachability   string // "reachable", "unreachable (IPv6, no route)", "unreachable (no response; host down or filtered)", or "unknown"
	OS             string
	ConfirmedPorts int
	TotalPorts     int
	// TCPPorts, UDPPorts and UnknownTransportPorts split TotalPorts by transport.
	// They sum to TotalPorts. A port number can appear in more than one of them:
	// tcp/53 and udp/53 are two services, and the host view keeps them as two rows,
	// so a reader who only saw the total could not tell one dual-transport port from
	// two single-transport ones. UnknownTransportPorts counts rows a passive
	// provider reported without ever naming the transport it saw.
	TCPPorts              int
	UDPPorts              int
	UnknownTransportPorts int
	CVECount              int
	Sources               string // contributing providers/tools, comma-joined
	// SourceObservedAt is the newest real-world observation behind this row: a
	// provider's own scan time, or Vanguard's own capture time where Vanguard did the
	// observing. Zero means no contributing source dated its claim, which reads as
	// unknown age rather than as fresh.
	SourceObservedAt time.Time
}

// Finding is a finding plus a short lineage trail for the report.
type Finding struct {
	Title          string
	Severity       int
	Asset          string
	Evidence       string
	Recommendation string
	Confidence     string   // "confirmed" or "inferred"
	KnownExploited bool     // CVE is in the known-exploited snapshot
	HowFound       []string // human-readable lineage, root to leaf

	// TemporalStatus and TemporalReason state whether the evidence is current,
	// historical, mixed, or unknown, and which rule decided that. They are a
	// dimension beside Confidence, and the two can disagree.
	TemporalStatus string
	TemporalReason string
	// EvidenceObservedFirst and EvidenceObservedLast bound when the evidence was
	// actually observed. Zero means no source supplied an observation time, which
	// prints as unknown and never as the scan time.
	EvidenceObservedFirst time.Time
	EvidenceObservedLast  time.Time
	// EvidenceKinds are the acquisition methods behind the finding, sorted.
	EvidenceKinds []string
	// EvidenceSources are the tools that contributed evidence, sorted.
	EvidenceSources []string
}

// EvidenceStatement renders a finding's evidence in the one controlled shape the report
// uses everywhere, so prose can never claim more than the data supports.
//
// The bracket is not redundant with the sentence: the sentence is written by a detector
// that knew nothing about when its evidence would be read, and the bracket is what makes
// the sentence safe to read at any later time. Every element that is missing says so
// explicitly, because an omitted field reads as "not applicable" while an unknown
// observation time is a real gap.
func (f Finding) EvidenceStatement() string {
	status := f.TemporalStatus
	if status == "" {
		status = "unclassified"
	}
	sources := unknownLabel
	if len(f.EvidenceSources) > 0 {
		sources = strings.Join(f.EvidenceSources, "/")
	}
	observed := unknownLabel
	switch {
	case !f.EvidenceObservedFirst.IsZero() && !f.EvidenceObservedFirst.Equal(f.EvidenceObservedLast):
		observed = formatTime(f.EvidenceObservedFirst) + " to " + formatTime(f.EvidenceObservedLast)
	case !f.EvidenceObservedLast.IsZero():
		observed = formatTime(f.EvidenceObservedLast)
	}
	kinds := unknownLabel
	if len(f.EvidenceKinds) > 0 {
		kinds = strings.Join(f.EvidenceKinds, "/")
	}
	confidence := f.Confidence
	if confidence == "" {
		confidence = "confirmed"
	}
	return fmt.Sprintf("%s [status: %s; source: %s; observed: %s; how: %s; confidence: %s]",
		f.Evidence, status, sources, observed, kinds, confidence)
}

// Analysis is the temporal context a report is judged against, gathered into one
// argument so a caller cannot supply a cutoff and a surface derived from different
// streams.
type Analysis struct {
	// AsOf is the fixed cutoff every temporal judgement is made against.
	AsOf events.AnalysisAsOf
	// Freshness is the declared per-source policy behind every "recent passive"
	// verdict, printed with the output so a threshold never hides its evidence.
	Freshness analysis.FreshnessPolicy
	// Surface is the classified asset view computed from the same event stream. It
	// is nil when the caller had no facts graph to classify, and the report then
	// omits the temporal composition rather than inventing one.
	Surface *facts.ClassifiedSurface
	// Coverage is the temporal-quality accounting computed with Surface. It is nil
	// only when the caller did not build a facts graph.
	Coverage *facts.TemporalCoverage
	// NetAudit is the packet-capture evidence model built from the completed
	// captures for this session. It is nil for a library caller that has no capture
	// evidence; the operator report always supplies one, even when every execution's
	// capture is absent, so the report's network-audit section is always rendered.
	NetAudit *netaudit.Model
	// SourceCollection is the collection outcome mapped once from the capture
	// manifest by the projector. It is passed in rather than recomputed because the
	// manifest is the sole authority for it and this package reads no files. Nil for
	// a caller with no capture manifest.
	SourceCollection *collectionhealth.Summary
}

// BuildReport assembles the report from the inventory, findings, and lineage
// read models plus the scan identity.
//
// a.AsOf is the fixed cutoff every temporal judgement in the report is made against,
// passed in rather than read from a clock so the same capture always yields the same
// report. Callers derive it from the stream (Projection.AnalysisAsOf); passing a
// different value is the deliberate re-evaluation path, and the report then shows
// both the evidence capture time and the cutoff it was re-judged against.
//
// It classifies the findings against that cutoff as a finalize pass, because the
// cutoff is only known once the whole stream has been folded.
func BuildReport(p *projections.Projection, scan entities.Scan, a Analysis) Report {
	asOf := a.AsOf
	hostView := p.HostView()
	p.Findings.Classify(asOf.At, a.Freshness)

	r := Report{
		ScanID:              scan.ID,
		RootTarget:          scan.RootTarget,
		StartedAt:           scan.StartedAt,
		CompletedAt:         scan.CompletedAt,
		Environments:        slices.Clone(p.Environments),
		AnalysisAsOf:        asOf.At,
		AnalysisAsOfPartial: asOf.Partial,
		FreshnessWindows:    a.Freshness.String(),
		Surface:             a.Surface,
		// Assigned directly, never mutated: the report serializes the facts graph's
		// coverage unchanged so it matches the facts artifact exactly. Report-only
		// reconciliation goes to r.Reconciliation below.
		TemporalCoverage:   a.Coverage,
		NetworkAudit:       a.NetAudit,
		SourceCollection:   a.SourceCollection,
		DataView:           events.DataViewCompleteHistory,
		DomainCount:        p.Inventory.ObservedDomainCount(),
		IPCount:            len(hostView.Hosts),
		NetblockCount:      len(p.Inventory.Netblocks),
		CertCount:          len(p.Inventory.Certificates),
		ServiceCountActive: len(p.Inventory.Services),
		ServiceCountUDP:    udpServiceCount(&p.Inventory),
		ServiceCount:       completeServiceCount(a.Surface, len(p.Inventory.Services)),
		IssueCount:         len(p.Issues),

		UnreachableIPv6Count: len(p.Inventory.UnreachableIPv6()),
	}
	r.reconcileTemporalCounts()
	r.reconcileFindingCurrentness(p)

	r.FindingsBySeverity = make(map[int]int, len(p.Findings.BySeverity))
	for sev, n := range p.Findings.BySeverity {
		r.FindingsBySeverity[sev] = n
	}

	sorted := p.Findings.Sorted()
	for i, f := range sorted {
		if i >= topFindingsCap {
			break
		}
		r.TopFindings = append(r.TopFindings, Finding{
			Title:          f.Title,
			Severity:       f.Severity,
			Asset:          f.Asset.Kind + " " + f.Asset.ID,
			Evidence:       f.Evidence,
			Recommendation: f.Recommendation,
			Confidence:     string(f.Confidence),
			KnownExploited: f.KnownExploited,
			HowFound:       howFound(p, f),

			TemporalStatus:        string(f.TemporalStatus),
			TemporalReason:        f.TemporalReason,
			EvidenceObservedFirst: f.EvidenceObservedFirst,
			EvidenceObservedLast:  f.EvidenceObservedLast,
			EvidenceKinds:         f.EvidenceKinds,
			EvidenceSources:       evidenceSources(f),
		})
	}

	for i := range p.Issues {
		iss := p.Issues[i]
		ri := Issue{
			EventID: iss.EventID, CapturedAt: iss.At, Source: iss.Source, Class: iss.Class,
			Severity: iss.Severity, Query: iss.Query, Message: iss.Message,
			CausationID: iss.CausationID,
		}
		r.Issues = append(r.Issues, ri)
		switch iss.Source {
		case issueSourceScope:
			r.ScopeExclusions = append(r.ScopeExclusions, ri)
		case issueSourceBudget:
			r.BudgetExclusions = append(r.BudgetExclusions, ri)
		default:
			if isCoverageIssue(iss.Class, iss.Source) {
				r.CoverageGaps = append(r.CoverageGaps, ri)
			} else {
				r.ToolErrors = append(r.ToolErrors, ri)
			}
		}
	}
	sortIssues(r.Issues)
	sortIssues(r.CoverageGaps)
	sortIssues(r.ToolErrors)
	sortIssues(r.ScopeExclusions)
	sortIssues(r.BudgetExclusions)

	for _, h := range hostView.SortedHosts() {
		confirmed, tcp, udp, unknown := 0, 0, 0, 0
		for i := range h.Ports {
			if h.Ports[i].Confidence == entities.ConfidenceConfirmed {
				confirmed++
			}
			switch h.Ports[i].Protocol {
			case entities.ProtocolTCP:
				tcp++
			case entities.ProtocolUDP:
				udp++
			default:
				unknown++
			}
		}
		r.Hosts = append(r.Hosts, Host{
			IP:                    h.IP,
			Reachability:          reachabilityLabel(h.Reachability),
			OS:                    h.OS,
			ConfirmedPorts:        confirmed,
			TotalPorts:            len(h.Ports),
			TCPPorts:              tcp,
			UDPPorts:              udp,
			UnknownTransportPorts: unknown,
			CVECount:              len(h.CVEs),
			Sources:               strings.Join(h.Sources, ", "),
			SourceObservedAt:      h.SourceObservedAt,
		})
	}

	// Built from the one host view already folded above, so the Services index and
	// the Hosts table are two renderings of the same merge, never two merges.
	r.Services = buildServiceIdentities(hostView)
	r.ServiceAssessments = buildServiceAssessments(&p.Inventory)

	for _, ep := range p.Inventory.SortedEndpoints() {
		app := WebApp{
			URL:      ep.URL,
			Status:   ep.StatusCode,
			Server:   ep.Server,
			Unscoped: entities.AnyUnscopedRequest(ep.Provenance),
		}
		for _, t := range ep.Technologies {
			if t.Technology == "" {
				continue
			}
			app.Technologies = append(app.Technologies, WebTechnology{
				Name:       t.Technology,
				Version:    t.Version,
				Categories: t.Categories,
				CPEs:       t.CPEs,
				Sources:    t.Sources,
			})
		}
		r.WebApps = append(r.WebApps, app)
	}

	r.Risk = BuildRiskModel(p)
	r.Threats = p.BuildThreats()

	buildScopeAccounting(p, &r)

	r.NextSteps = nextSteps(p, &r)
	r.NextSteps = append(r.NextSteps, r.netAuditNextSteps()...)
	return r
}

// addReconciliationAnomaly records one report-only cross-projection anomaly, allocating
// the block on first use so it stays nil (and omitted from JSON) when every view agrees.
func (r *Report) addReconciliationAnomaly(a facts.TemporalAnomaly) {
	if r.Reconciliation == nil {
		r.Reconciliation = &Reconciliation{}
	}
	r.Reconciliation.Anomalies = append(r.Reconciliation.Anomalies, a)
}

// completeServiceCount is the headline service total: the classified facts surface count
// of Service assets when a surface exists (so provider-reported services are included),
// falling back to the active entity count when no facts graph was built.
func completeServiceCount(surface *facts.ClassifiedSurface, active int) int {
	if surface == nil {
		return active
	}
	total := 0
	for _, row := range surface.ByType {
		if row.Type == facts.AssetService {
			total += row.Total
		}
	}
	return total
}

// reconcileTemporalCounts compares the entity projection used for headline totals with
// the classified facts surface used for currentness. A difference is recorded as a
// report-only reconciliation anomaly; neither side is rescaled or discarded to make the
// views agree. The anomaly stays out of TemporalCoverage so that block remains identical
// to the facts artifact.
//
// Services are deliberately absent: the service headline (ServiceCount) is already the
// complete classified total, so it equals the classified surface by construction and the
// active-versus-complete split is shown in the Attack Surface composition and carried in
// ServiceCountActive, not raised as a mismatch anomaly.
func (r *Report) reconcileTemporalCounts() {
	if r.Surface == nil || r.TemporalCoverage == nil {
		return
	}
	checks := []struct {
		label    string
		entities int
		types    []facts.AssetType
	}{
		{label: "domains", entities: r.DomainCount, types: []facts.AssetType{facts.AssetDomain, facts.AssetSubdomain}},
		{label: "IP addresses", entities: r.IPCount, types: []facts.AssetType{facts.AssetIPAddress}},
		{label: "netblocks", entities: r.NetblockCount, types: []facts.AssetType{facts.AssetNetblock}},
		{label: "certificates", entities: r.CertCount, types: []facts.AssetType{facts.AssetCertificate}},
	}
	for _, check := range checks {
		classified := 0
		for _, row := range r.Surface.ByType {
			if slices.Contains(check.types, row.Type) {
				classified += row.Total
			}
		}
		if classified == check.entities {
			continue
		}
		r.addReconciliationAnomaly(facts.TemporalAnomaly{
			Type: "entity_classified_count_mismatch", Severity: events.SeverityMedium,
			SubjectKind: check.label,
			Detail:      fmt.Sprintf("entity projection counts %d; classified facts surface counts %d; both complete views are retained", check.entities, classified),
		})
	}
}

// reconcileFindingCurrentness catches a cross-projection contradiction: a finding in
// the current posture whose affected asset is historical-only in the classified facts
// surface. The finding remains in the complete ledger and the mismatch is made explicit
// as a report-only reconciliation anomaly. It also sorts the accumulated reconciliation
// anomalies deterministically, so it runs after reconcileTemporalCounts.
func (r *Report) reconcileFindingCurrentness(p *projections.Projection) {
	if r.Surface == nil || r.TemporalCoverage == nil {
		return
	}
	historical := make(map[string]bool)
	for _, asset := range r.Surface.Assets {
		if asset.Primary != facts.CurrentnessHistoricalOnly {
			continue
		}
		historical[asset.Key] = true
	}
	for _, finding := range p.Findings.All {
		if finding.TemporalStatus != entities.TemporalStatusCurrent {
			continue
		}
		// A finding's asset id is the canonical asset key for its kind, which is exactly
		// how the surface keys the asset, so the match needs no per-kind translation.
		if !historical[finding.Asset.ID] {
			continue
		}
		r.addReconciliationAnomaly(facts.TemporalAnomaly{
			Type: "current_finding_on_historical_asset", Severity: events.SeverityHigh,
			SubjectKind: "finding", Subject: finding.Title,
			Detail: fmt.Sprintf("finding is in current posture but affected asset %s is historical_only in the classified facts surface", finding.Asset.ID),
		})
	}
	if r.Reconciliation == nil {
		return
	}
	sort.Slice(r.Reconciliation.Anomalies, func(i, j int) bool {
		a, b := r.Reconciliation.Anomalies[i], r.Reconciliation.Anomalies[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.RawEventID < b.RawEventID
	})
}

// howFound renders the causal chain that led to a finding, root to leaf, by
// walking the lineage from the discovery event that caused the finding.
func howFound(p *projections.Projection, f *entities.Finding) []string {
	if len(f.Provenance) == 0 {
		return nil
	}
	findingEventID := f.Provenance[0].EventID
	node, ok := p.Lineage.Nodes[findingEventID]
	if !ok {
		return nil
	}
	// Chain from the event that caused the finding, so the trail describes how the
	// underlying asset was discovered rather than the finding being raised.
	chain := p.Lineage.Chain(node.CausationID)
	out := make([]string, 0, len(chain))
	for _, n := range chain {
		out = append(out, fmt.Sprintf("%s: %s", n.Source, n.Summary))
	}
	return out
}

// nextSteps derives deterministic follow-up actions from the read models.
func nextSteps(p *projections.Projection, r *Report) []string {
	var steps []string
	seen := make(map[string]bool)
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			steps = append(steps, s)
		}
	}

	for _, f := range p.Findings.Sorted() {
		if step := findingRemediation(f.Rule, f.Asset.ID); step != "" {
			add(step)
		}
	}

	// No actively confirmed services on known hosts suggests the active phase did not run.
	// Uses the active count, not the complete total: provider-reported services can exist
	// while the active probe never ran, which is exactly when this suggestion is useful.
	if r.IPCount > 0 && r.ServiceCountActive == 0 {
		add(fmt.Sprintf("Run the active phase to probe %d discovered host(s) for open services.", r.IPCount))
	}

	// IPv6-only assets the scanner could not route to are unprobed surface, not a
	// clean result. Name the gap and the remediation explicitly.
	if r.UnreachableIPv6Count > 0 {
		add(fmt.Sprintf("Re-run from an IPv6-capable host (or enable a dual-stack route) to cover %d IPv6-only asset(s) the scanner could not reach.", r.UnreachableIPv6Count))
	}

	return steps
}

// findingRemediation is the operator action for one finding rule on one asset, or ""
// for a rule with no specific step. Two rules share a sentence only where the same
// action fixes both; a rule whose remediation differs gets its own, because a step
// that names the wrong fix is worse than no step at all.
func findingRemediation(rule, asset string) string {
	switch rule {
	case "zone-transfer-open":
		return fmt.Sprintf("Review AXFR exposure on %s and enumerate the full zone.", asset)
	case "risky-open-port":
		return fmt.Sprintf("Validate exposed service %s for authentication and known CVEs.", asset)
	case "udp-management-plane-exposure":
		return fmt.Sprintf("Move the management plane at %s off the public internet, or put it behind a VPN and rotate its shared secrets.", asset)
	case "public-udp-reflector-surface":
		return fmt.Sprintf("Confirm %s is meant to answer the public internet; restrict it to its intended clients and apply response rate limiting.", asset)
	case "udp-remote-access-surface":
		return fmt.Sprintf("Confirm the remote-access edge at %s is intended, current, and enforcing multi-factor authentication.", asset)
	case "expired-cert", "long-lived-cert":
		return fmt.Sprintf("Confirm certificate lifecycle ownership for %s.", asset)
	case "plaintext-http":
		return fmt.Sprintf("Enforce HTTPS and HSTS for %s.", asset)
	case "missing-security-headers":
		return fmt.Sprintf("Add the missing security headers to %s.", asset)
	case "missing-dnssec":
		return fmt.Sprintf("Enable DNSSEC for %s.", asset)
	case "dmarc-missing", "dmarc-policy-none":
		return fmt.Sprintf("Publish an enforcing DMARC policy (p=quarantine/reject) for %s.", asset)
	case "spf-missing", "spf-over-limit":
		return fmt.Sprintf("Fix the SPF record for %s so it is published and resolves within 10 lookups.", asset)
	case "spf-pass-all":
		return fmt.Sprintf("Restrict the SPF record for %s to the authorized senders and replace the pass-all fallback.", asset)
	case "spf-neutral-policy":
		return fmt.Sprintf("Choose an intentional SPF terminal policy for %s after validating which senders it actually uses.", asset)
	case "spf-multiple-records":
		return fmt.Sprintf("Consolidate the SPF records for %s into one and recheck its lookup count.", asset)
	default:
		return ""
	}
}

// reachabilityLabel renders an IP reachability verdict for the report.
func reachabilityLabel(r entities.IPReachability) string {
	switch r {
	case entities.ReachabilityReachable:
		return "reachable"
	case entities.ReachabilityUnreachableIPv6:
		return "unreachable (IPv6, no route)"
	case entities.ReachabilityUnreachableNoResponse:
		return "unreachable (no response; host down or filtered)"
	default:
		return unknownLabel
	}
}

// severityOrder lists severities from most to least severe for stable rendering.
var severityOrder = []events.Severity{
	events.SeverityCritical,
	events.SeverityHigh,
	events.SeverityMedium,
	events.SeverityLow,
	events.SeverityInfo,
}

// Markdown renders the report as a Markdown document with stable section order.
func (r Report) Markdown() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "# Recon Report: %s\n\n", r.RootTarget)
	fmt.Fprintf(&sb, "- Scan ID: %s\n", r.ScanID)
	fmt.Fprintf(&sb, "- Started: %s\n", formatTime(r.StartedAt))
	fmt.Fprintf(&sb, "- Completed: %s\n\n", formatTime(r.CompletedAt))
	r.writeSourceCollection(&sb)
	r.writeRunEnvironment(&sb)

	r.writeTemporalScope(&sb)

	r.writeExecutiveSummary(&sb)

	r.writeAttackSurface(&sb)
	r.writeTemporalCoverage(&sb)
	r.writeReconciliation(&sb)

	r.writeHosts(&sb)
	r.writeServices(&sb)
	r.writeServiceAssessments(&sb)
	r.writeWebApplications(&sb)
	r.writeRiskiestAssets(&sb)

	r.writeFindings(&sb)

	r.writeIssues(&sb)

	r.writeScopeBudget(&sb)
	r.writeNetworkAudit(&sb)
	r.writeThirdPartyRedirects(&sb)

	sb.WriteString("## Recommended Next Steps\n\n")
	if len(r.NextSteps) == 0 {
		sb.WriteString("- No automated recommendations.\n")
	}
	for i, step := range r.NextSteps {
		fmt.Fprintf(&sb, "%d. %s\n", i+1, step)
	}

	return sb.String()
}

func (r Report) writeRunEnvironment(sb *strings.Builder) {
	if len(r.Environments) == 0 {
		return
	}
	sb.WriteString("## Run environment\n\n")
	// A collection records one environment. The loop still renders every record the
	// stream carried, unnumbered, so a corrupt log with more than one shows all of
	// them instead of passing the first off as the only one.
	for _, e := range r.Environments {
		fmt.Fprintf(sb, "- Collector: %s %s\n", orUnknown(e.Actor.Name), orUnknown(e.Actor.Version))
		fmt.Fprintf(sb, "- Config SHA-256: `%s`\n", e.ConfigSHA256)
		if e.Runtime.NmapVersion != "" {
			fmt.Fprintf(sb, "- nmap: %s (`%s`)\n", e.Runtime.NmapVersion, e.Runtime.NmapPath)
		}
		for _, s := range e.Snapshots {
			fmt.Fprintf(sb, "- %s: %s", s.Name, s.Version)
			if s.Released != "" {
				fmt.Fprintf(sb, " (%s)", s.Released)
			}
			if s.Count > 0 {
				fmt.Fprintf(sb, ", %d entries", s.Count)
			}
			if s.Digest != "" {
				fmt.Fprintf(sb, ", SHA-256 `%s`", s.Digest)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// writeTemporalCoverage exposes whether the timestamps behind currentness are complete
// and internally consistent. The anomaly ledger is additive: it flags evidence for
// review and never removes that evidence from the report. This block is the facts graph's
// own coverage, rendered identically to facts.md.
func (r Report) writeTemporalCoverage(sb *strings.Builder) {
	if r.TemporalCoverage == nil {
		return
	}
	sb.WriteString(r.TemporalCoverage.Markdown())
}

// writeReconciliation renders the report-only entity-to-facts cross-checks under their own
// heading, so a reader never confuses them with the shared temporal coverage above. It
// prints nothing when every view reconciled.
//
// These are few by construction - one per count mismatch or cross-projection
// contradiction, not one per subject - so unlike the coverage ledger they stay
// inline. They are repeated in the temporal-anomalies report so that ledger is the
// whole picture.
func (r Report) writeReconciliation(sb *strings.Builder) {
	if r.Reconciliation == nil || len(r.Reconciliation.Anomalies) == 0 {
		return
	}
	sb.WriteString("## Entity-facts reconciliation\n\n")
	sb.WriteString("Report-only cross-checks between the entity projection (headline totals) and the " +
		"classified facts surface. Both complete views are retained; neither is rescaled to agree.\n\n")
	sb.WriteString("| Type | Severity | Subject | Detail |\n|---|---:|---|---|\n")
	for _, a := range r.Reconciliation.Anomalies {
		subject := a.Subject
		if subject == "" {
			subject = a.SubjectKind
		}
		fmt.Fprintf(sb, "| %s | %d | %s | %s |\n", a.Type, a.Severity, subject, a.Detail)
	}
	sb.WriteString("\n")
}

// writeAttackSurface renders the complete asset totals with the temporal composition of
// each one beside it.
//
// A bare "Certificates | 128" asks the reader to infer what those 128 are, and for a
// long-lived estate the honest answer is mostly expired CT history. The composition
// column is not decoration: without it the heading is a claim about current surface that
// the number does not support. Every breakdown sums to the complete total, which stays
// the headline figure.
func (r Report) writeAttackSurface(sb *strings.Builder) {
	sb.WriteString("## Attack Surface\n\n")
	sb.WriteString("Counts are complete: they include historical evidence, not only what is current. ")
	sb.WriteString("The composition column splits the classified total by currentness at the as-of time and always sums to it. ")
	sb.WriteString("The service count is the complete surface, including provider-reported (Censys/Shodan/Netlas) ")
	sb.WriteString("services the active phase never confirmed; the live_verified part of its composition is the ")
	sb.WriteString("actively confirmed subset.\n\n")
	sb.WriteString("| Asset | Count | Composition |\n|-------|-------|-------------|\n")
	fmt.Fprintf(sb, "| Domains | %d | %s |\n", r.DomainCount, r.composition(r.DomainCount, facts.AssetDomain, facts.AssetSubdomain))
	fmt.Fprintf(sb, "| IP addresses | %d | %s |\n", r.IPCount, r.composition(r.IPCount, facts.AssetIPAddress))
	fmt.Fprintf(sb, "| Netblocks | %d | %s |\n", r.NetblockCount, r.composition(r.NetblockCount, facts.AssetNetblock))
	fmt.Fprintf(sb, "| Certificates | %d | %s |\n", r.CertCount, r.composition(r.CertCount, facts.AssetCertificate))
	fmt.Fprintf(sb, "| Services | %d | %s |\n", r.ServiceCount, r.composition(r.ServiceCount, facts.AssetService))
	if r.ServiceCountUDP > 0 {
		fmt.Fprintf(sb, "| Services (udp, confirmed) | %d | subset of the actively confirmed services |\n", r.ServiceCountUDP)
	}
	if r.UnreachableIPv6Count > 0 {
		fmt.Fprintf(sb, "| IPv6-only (unreachable, not probed) | %d | coverage gap, never probed |\n", r.UnreachableIPv6Count)
	}
	sb.WriteString("\n")
	if r.Surface != nil {
		fmt.Fprintf(sb, "Freshness windows behind any recent-passive verdict: %s.\n\n", r.Surface.FreshnessWindows)
	}
}

// composition renders the classified breakdown for one or more asset types as a single
// cell. It returns an explicit "not classified" rather than an empty cell when no
// classified surface was supplied: a blank would read as "nothing to say", and the
// difference between "no historical evidence" and "we did not look" is the whole point.
func (r Report) composition(entityCount int, types ...facts.AssetType) string {
	if r.Surface == nil {
		return "not classified"
	}
	totals := map[facts.Currentness]int{}
	classified := 0
	for _, t := range types {
		for _, bt := range r.Surface.ByType {
			if bt.Type != t {
				continue
			}
			classified += bt.Total
			for _, c := range bt.ByClass {
				totals[c.Class] += c.Count
			}
		}
	}
	parts := make([]string, 0, len(totals))
	for _, c := range r.Surface.ByClass {
		if n := totals[c.Class]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", c.Class, n))
		}
	}
	if len(parts) == 0 {
		return "no classified assets of this type"
	}
	out := strings.Join(parts, ", ")
	// The breakdown must visibly sum to something. When the facts graph classified a
	// different number of subjects than the entity model counts, that difference is a
	// fact about the two models and is stated rather than papered over by rescaling.
	if classified != entityCount {
		out += fmt.Sprintf(" (of %d classified)", classified)
	}
	return out
}

// writeTemporalRisk renders the four reconciled risk views. They are views, not filters:
// every finding in the ledger appears in exactly one of them, and the report prints the
// reconciliation so a reader can check that nothing was dropped to make the current
// posture look smaller.
func (r Report) writeTemporalRisk(sb *strings.Builder) {
	v := r.Risk.Views
	if v.Ledger == 0 {
		return
	}
	sb.WriteString("### Posture by evidence currentness\n\n")
	sb.WriteString("| View | Findings | Meaning |\n|------|----------|---------|\n")
	fmt.Fprintf(sb, "| Current posture | %d | supported as current at the as-of time |\n", v.Current)
	fmt.Fprintf(sb, "| Mixed evidence | %d | current and historical evidence combined |\n", v.Mixed)
	fmt.Fprintf(sb, "| Historical intelligence | %d | evidence is historical-only; retained, not current |\n", v.Historical)
	fmt.Fprintf(sb, "| Currentness unknown | %d | needs re-observation before any current claim |\n", v.Unknown)
	fmt.Fprintf(sb, "| **Complete finding ledger** | **%d** | every finding, unchanged and auditable |\n\n", v.Ledger)
	if !v.Reconciles() {
		sb.WriteString("The four views do not sum to the ledger; treat the split as unreliable and read the ledger.\n\n")
	}
	fmt.Fprintf(sb, "Historical-only evidence contributes %d%% of its weight to the risk score and unknown-currentness evidence %d%%, "+
		"so neither drives current posture invisibly and neither is silently cleared.\n\n",
		r.Risk.HistoricalPercent, r.Risk.UnknownPercent)
}

// writeTemporalScope states the reference time every temporal claim below is made
// against, before any count. Terms like current, expired, and recent are statements
// about a cutoff, so a reader who misses the cutoff misreads every one of them; a
// distant methodology section is not enough.
//
// It also states the data policy plainly: nothing was filtered out, historical
// evidence is retained and labelled, and unknown is its own answer rather than a
// polite way of saying clean.
func (r Report) writeTemporalScope(sb *strings.Builder) {
	sb.WriteString("## Temporal Scope\n\n")
	if r.AnalysisAsOfPartial {
		fmt.Fprintf(sb, "- Partial as of: %s (latest observation; this stream has no scan completion)\n", formatTime(r.AnalysisAsOf))
	} else {
		fmt.Fprintf(sb, "- As of: %s (scan completion)\n", formatTime(r.AnalysisAsOf))
	}
	// A cutoff later than the evidence means this report re-judged an older capture.
	// Showing both times keeps the original scan-time reading recoverable.
	if !r.CompletedAt.IsZero() && !r.AnalysisAsOf.Equal(r.CompletedAt) {
		fmt.Fprintf(sb, "- Evidence captured: %s\n- Re-evaluated: %s\n", formatTime(r.CompletedAt), formatTime(r.AnalysisAsOf))
	}
	fmt.Fprintf(sb, "- Data view: %s\n", r.DataView)
	// The two are routinely confused: a complete history is a statement about which
	// events were kept, and says nothing about whether the collection that produced
	// them finished. Only the Source collection section answers that.
	completeness := ""
	if r.SourceCollection != nil {
		completeness = "; Source collection above states whether collection completed"
	}
	fmt.Fprintf(sb, "- Data view describes event filtering only: nothing was dropped from this stream, "+
		"which is not a claim that collection completed%s\n", completeness)
	sb.WriteString("- Current means: directly observed or positively resolved during this scan\n")
	sb.WriteString("- Historical data is retained and labeled; unknown does not mean absent\n\n")
}

// writeSourceCollection states how the collection that produced this report ended,
// before any count or finding. A reader who takes an empty section as an absent
// exposure has to know first whether the scan actually looked; a degraded collection
// makes exactly that inference unsafe, and a section further down would be read too
// late.
//
// It renders the collection manifest's verdict and nothing else. It never relabels a
// failed or interrupted collection as degraded, never converts a collection loss into
// a target issue, and never changes a severity or a risk score: what was lost is a
// statement about the acquisition, not about the estate.
func (r Report) writeSourceCollection(sb *strings.Builder) {
	h := r.SourceCollection
	if h == nil {
		return
	}
	sb.WriteString("## Source collection\n\n")
	fmt.Fprintf(sb, "- Status: %s\n", h.StatusLine())
	fmt.Fprintf(sb, "- Phases this collection ran: %s\n", phaseList(h.Phases))
	if h.Clean() {
		sb.WriteString("\nEvery phase this collection ran completed and no tool reported lost work, " +
			"so an absence below is an observation rather than a gap.\n\n")
		return
	}
	if len(h.Problems) > 0 {
		sb.WriteString("\n| Problem | Tool | Component | Events |\n| --- | --- | --- | --- |\n")
		for _, p := range h.Problems {
			fmt.Fprintf(sb, "| %s | %s | %s | %d |\n", p.Code, p.Tool, orDash(p.Component), p.Count)
		}
	}
	sb.WriteString("\nCollection did not complete cleanly, so an absence below may be work this scan " +
		"never finished rather than something the estate does not have. Treat every negative " +
		"conclusion in this report as unproven for the sources named above.\n\n")
}

// phaseList renders a phase set for a reader, keeping the canonical order the
// manifest recorded and naming an empty set rather than printing nothing.
func phaseList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// writeFindings renders the severity rollup, the top-findings table, and the
// per-finding "how found" lineage trail.
func (r Report) writeFindings(sb *strings.Builder) {
	totalFindings := 0
	for _, n := range r.FindingsBySeverity {
		totalFindings += n
	}
	fmt.Fprintf(sb, "## Findings (%d)\n\n", totalFindings)
	parts := make([]string, 0, len(severityOrder))
	for _, sev := range severityOrder {
		parts = append(parts, fmt.Sprintf("%s %d", sev, r.FindingsBySeverity[int(sev)]))
	}
	fmt.Fprintf(sb, "Severity breakdown: %s\n\n", strings.Join(parts, ", "))

	if len(r.TopFindings) == 0 {
		return
	}
	if totalFindings > len(r.TopFindings) {
		fmt.Fprintf(sb, "Showing the %d most severe of %d findings.\n\n", len(r.TopFindings), totalFindings)
	}
	r.writeFindingsTable(sb)

	sb.WriteString("\n### How findings were discovered\n\n")
	for _, f := range r.TopFindings {
		fmt.Fprintf(sb, "**%s** (%s) on %s\n", f.Title, events.Severity(f.Severity), f.Asset)
		fmt.Fprintf(sb, "  - %s\n", f.EvidenceStatement())
		if len(f.HowFound) == 0 {
			sb.WriteString("  - (lineage unavailable)\n")
		}
		for i, line := range f.HowFound {
			fmt.Fprintf(sb, "  %d. %s\n", i+1, line)
		}
		sb.WriteString("\n")
	}
}

// writeFindingsTable renders the top-findings table.
func (r Report) writeFindingsTable(sb *strings.Builder) {
	sb.WriteString("| Severity | Title | Asset | Evidence |\n")
	sb.WriteString("|----------|-------|-------|----------|\n")
	for _, f := range r.TopFindings {
		fmt.Fprintf(sb, "| %s | %s | %s | %s |\n",
			events.Severity(f.Severity), f.Title, f.Asset, findingEvidenceCell(f))
	}
}

// evidenceAge renders how old the newest observation behind a row is, measured against
// the analysis cutoff rather than a wall clock so the report is replay-stable.
//
// An undated claim reads as "unknown", never as fresh: a source that supplied no
// observation time has told us nothing about age, which is a coverage gap and not a
// recent sighting. A negative age means the source timestamped its claim after the
// cutoff, which is clock skew worth seeing rather than hiding.
func evidenceAge(asOf, observed time.Time) string {
	if observed.IsZero() {
		return unknownLabel
	}
	d := asOf.Sub(observed)
	switch {
	case d < 0:
		return "ahead of as-of"
	case d < 24*time.Hour:
		return "<1d"
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// findingEvidenceCell renders a finding's evidence cell, tagging a known-exploited
// CVE (the headline prioritization signal) and marking an inferred, unverified
// finding so a reader does not read a banner-CVE as a confirmed weakness.
func findingEvidenceCell(f Finding) string {
	evidence := f.Evidence
	if f.KnownExploited {
		evidence = "[known-exploited] " + evidence
	}
	if f.Confidence == string(entities.ConfidenceInferred) {
		evidence += " (inferred, unverified)"
	}
	// Only current evidence is left to speak in the present tense. Anything else is
	// tagged in the cell itself, because a table row is read on its own and a note
	// further down the page does not travel with it.
	switch f.TemporalStatus {
	case string(entities.TemporalStatusHistorical):
		evidence += " (historical evidence, not observed as current)"
	case string(entities.TemporalStatusMixed):
		evidence += " (current and historical evidence combined)"
	case string(entities.TemporalStatusUnknown):
		evidence += " (currentness unknown)"
	}
	return evidence
}

// evidenceSources lists the tools that contributed a finding's evidence, sorted and
// deduplicated, so the controlled evidence statement can name them.
func evidenceSources(f *entities.Finding) []string {
	seen := make(map[string]bool, len(f.Provenance))
	out := make([]string, 0, len(f.Provenance))
	for _, pr := range f.Provenance {
		if pr.Source == "" || seen[pr.Source] {
			continue
		}
		seen[pr.Source] = true
		out = append(out, pr.Source)
	}
	sort.Strings(out)
	return out
}

// writeExecutiveSummary renders the top-line risk posture: band, severity
// breakdown, the riskiest assets by name, and the count of threat scenarios. The
// scenarios themselves are their own artifact, so the count carries the link to it
// rather than a section of narratives further down.
func (r Report) writeExecutiveSummary(sb *strings.Builder) {
	sb.WriteString("## Executive Risk Summary\n\n")
	fmt.Fprintf(sb, "- Overall risk: **%s** (total score %d)\n", strings.ToUpper(string(r.Risk.Band)), r.Risk.TotalScore)

	parts := make([]string, 0, len(severityOrder))
	for _, sev := range severityOrder {
		parts = append(parts, fmt.Sprintf("%s %d", sev, r.Risk.BySeverity[int(sev)]))
	}
	fmt.Fprintf(sb, "- Findings by severity: %s\n", strings.Join(parts, ", "))
	fmt.Fprintf(sb, "- Threat scenarios: %d (%s) - see [%s](%s)\n",
		len(r.Threats), threatComposition(r.Threats), threatLedgerLink, threatLedgerLink)

	if len(r.Risk.TopAssets) > 0 {
		top := r.Risk.TopAssets
		if len(top) > 3 {
			top = top[:3]
		}
		names := make([]string, 0, len(top))
		for _, a := range top {
			names = append(names, fmt.Sprintf("%s %s (%d)", a.Kind, a.ID, a.Score))
		}
		fmt.Fprintf(sb, "- Riskiest assets: %s\n", strings.Join(names, ", "))
	}
	sb.WriteString("\n")
	r.writeTemporalRisk(sb)
}

// threatComposition summarizes how many scenarios rest on current evidence versus
// historical, mixed, or unknown, so the headline count cannot read as "16 things are
// happening right now".
func threatComposition(ts []threats.ThreatScenario) string {
	counts := map[entities.TemporalStatus]int{}
	for _, t := range ts {
		counts[t.TemporalStatus]++
	}
	order := []entities.TemporalStatus{
		entities.TemporalStatusCurrent, entities.TemporalStatusMixed,
		entities.TemporalStatusHistorical, entities.TemporalStatusUnknown,
	}
	parts := make([]string, 0, len(order))
	for _, st := range order {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, st))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// writeWebApplications renders the discovered HTTP(S) endpoints as a table of
// URL -> status -> server -> scope -> technologies, so the operator can read the
// web applications exposed on the estate directly from the report, and can tell one
// that passed the request policy from one an unauthorized crawl reached outside the
// engagement scope.
//
// writeHosts renders the unified per-host view: one row per IP merged from the
// active scan and the provider facets. The confirmed/total port split shows what
// the active scan actually observed open versus what providers only claimed, and
// evidence age is measured against the report's fixed cutoff.
func (r Report) writeHosts(sb *strings.Builder) {
	fmt.Fprintf(sb, "## Hosts (%d)\n\n", len(r.Hosts))
	if len(r.Hosts) == 0 {
		sb.WriteString("No host intelligence merged (no active scan or provider host data).\n\n")
		return
	}
	sb.WriteString("Merged from the active scan and the censys/shodan/netlas facets. ")
	sb.WriteString("Confirmed ports were observed open by the active scan; the rest are provider-reported. Evidence age is unknown when no contributing source supplied an observation time. ")
	sb.WriteString("The transport column splits the same total: tcp/53 and udp/53 are two services on one number, and a provider that reported a port without naming the transport it saw counts as unknown rather than as tcp.\n\n")
	sb.WriteString("| Host | Reachability | OS | Ports (confirmed/total) | Transport | CVEs | Sources | Evidence age |\n")
	sb.WriteString("|------|--------------|----|-----------------------|-----------|------|---------|--------------|\n")
	for _, h := range r.Hosts {
		os := h.OS
		if os == "" {
			os = "-"
		}
		sources := h.Sources
		if sources == "" {
			sources = "-"
		}
		fmt.Fprintf(sb, "| %s | %s | %s | %d/%d | %s | %d | %s | %s |\n",
			h.IP, h.Reachability, os, h.ConfirmedPorts, h.TotalPorts, transportBreakdown(h), h.CVECount, sources,
			evidenceAge(r.AnalysisAsOf, h.SourceObservedAt))
	}
	sb.WriteString("\n")
}

// transportBreakdown renders a host's port count split by transport, omitting the
// transports with no rows. It never renders an empty cell: a host with no ports at
// all reads as "-" rather than as a blank a reader would take for missing data.
func transportBreakdown(h Host) string {
	parts := make([]string, 0, 3)
	for _, part := range []struct {
		label string
		count int
	}{
		{entities.ProtocolTCP, h.TCPPorts},
		{entities.ProtocolUDP, h.UDPPorts},
		{entities.ProtocolUnknown, h.UnknownTransportPorts},
	} {
		if part.count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", part.label, part.count))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// udpServiceCount counts the inventory services confirmed on udp. The inventory
// holds only services Vanguard observed itself, so this is the confirmed UDP
// surface and never a provider's claim about one.
func udpServiceCount(inv *projections.Inventory) int {
	n := 0
	for _, svc := range inv.Services {
		if svc.Protocol == entities.ProtocolUDP {
			n++
		}
	}
	return n
}

func (r Report) writeWebApplications(sb *strings.Builder) {
	fmt.Fprintf(sb, "## Web Applications (%d)\n\n", len(r.WebApps))
	if len(r.WebApps) == 0 {
		sb.WriteString("No web applications discovered.\n\n")
		return
	}
	if n := r.unscopedWebApps(); n > 0 {
		fmt.Fprintf(sb, "%d of these are out of engagement scope: the goscans web modules ran with pre-dial request authorization disabled (tools.goscans.ignore_http_scope) and fetched them before the scope could refuse them. The remaining rows passed the same request policy the rest of the scan enforces.\n\n", n)
	}
	sb.WriteString("| URL | Status | Server | Scope | Technologies |\n")
	sb.WriteString("|-----|--------|--------|-------|--------------|\n")
	for _, a := range r.WebApps {
		status := "-"
		if a.Status != 0 {
			status = fmt.Sprintf("%d", a.Status)
		}
		server := a.Server
		if server == "" {
			server = "-"
		}
		techs := "-"
		if len(a.Technologies) > 0 {
			labels := make([]string, 0, len(a.Technologies))
			for _, t := range a.Technologies {
				labels = append(labels, t.Label())
			}
			techs = strings.Join(labels, ", ")
		}
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s |\n", a.URL, status, server, a.scopeLabel(), techs)
	}
	sb.WriteString("\n")
	r.writeTechnologyDetail(sb)
}

// unscopedWebApps counts the applications reached outside the engagement scope, so
// the section can state the size of the caveat before the table.
func (r Report) unscopedWebApps() int {
	n := 0
	for _, a := range r.WebApps {
		if a.Unscoped {
			n++
		}
	}
	return n
}

// scopeLabel renders the per-row scope verdict. Every ordinary row says the
// destination passed the request policy, which is what the scan enforces; only an
// endpoint an operator-enabled unauthorized path reached outside the scope reads
// otherwise.
func (a WebApp) scopeLabel() string {
	if a.Unscoped {
		return "unscoped"
	}
	return "authorized"
}

// writeTechnologyDetail renders the fingerprint metadata that does not fit the
// compact table: categories, CPEs, and the tools that contributed each entry. Only
// apps with at least one entry carrying metadata are listed, so a scan whose tools
// report bare names renders exactly as before.
func (r Report) writeTechnologyDetail(sb *strings.Builder) {
	var apps []WebApp
	for _, a := range r.WebApps {
		for _, t := range a.Technologies {
			if t.HasMetadata() {
				apps = append(apps, a)
				break
			}
		}
	}
	if len(apps) == 0 {
		return
	}
	sb.WriteString("### Technology Detail\n\n")
	for _, a := range apps {
		fmt.Fprintf(sb, "**%s**\n\n", a.URL)
		for _, t := range a.Technologies {
			fmt.Fprintf(sb, "- %s", t.Label())
			if len(t.Sources) > 0 {
				fmt.Fprintf(sb, " (%s)", strings.Join(t.Sources, ", "))
			}
			sb.WriteString("\n")
			if len(t.Categories) > 0 {
				fmt.Fprintf(sb, "  - categories: %s\n", strings.Join(t.Categories, ", "))
			}
			if len(t.CPEs) > 0 {
				fmt.Fprintf(sb, "  - cpes: %s\n", strings.Join(t.CPEs, ", "))
			}
		}
		sb.WriteString("\n")
	}
}

// writeRiskiestAssets renders the per-asset risk table and, for each, its
// contributing findings and the reasons its criticality was raised. The severity
// weights are printed so the score stays explainable.
func (r Report) writeRiskiestAssets(sb *strings.Builder) {
	sb.WriteString("## Riskiest Assets\n\n")
	if len(r.Risk.TopAssets) == 0 {
		sb.WriteString("No scored assets (no findings against any asset).\n\n")
		return
	}
	weightParts := make([]string, 0, len(severityOrder))
	for _, sev := range severityOrder {
		weightParts = append(weightParts, fmt.Sprintf("%s=%d", sev, r.Risk.Weights[int(sev)]))
	}
	fmt.Fprintf(sb, "Severity weights: %s. Score = sum(weights) x criticality.\n\n", strings.Join(weightParts, ", "))

	for _, a := range r.Risk.TopAssets {
		reasons := "baseline"
		if len(a.Reasons) > 0 {
			reasons = strings.Join(a.Reasons, ", ")
		}
		fmt.Fprintf(sb, "**%s %s** - score %d (base %d x criticality %d: %s)\n",
			a.Kind, a.ID, a.Score, a.BaseScore, a.Criticality, reasons)
		for _, f := range a.Findings {
			// Show the weight factors so the score stays explainable: an inferred
			// finding is down-weighted, a known-exploited one is up-weighted.
			var notes []string
			if f.Confidence == string(entities.ConfidenceInferred) {
				notes = append(notes, "inferred")
			}
			if f.KnownExploited {
				notes = append(notes, "known-exploited")
			}
			if len(notes) > 0 {
				fmt.Fprintf(sb, "  - %s: %s (weight %d, %s)\n", events.Severity(f.Severity), f.Title, f.Weight, strings.Join(notes, ", "))
				continue
			}
			fmt.Fprintf(sb, "  - %s: %s (weight %d)\n", events.Severity(f.Severity), f.Title, f.Weight)
		}
		sb.WriteString("\n")
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05 MST")
}
