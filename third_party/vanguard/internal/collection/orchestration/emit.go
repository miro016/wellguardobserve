package orchestration

import (
	"context"
	"encoding/json"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/crawler"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// newLifecycleMeta builds EventMeta for orchestrator-emitted lifecycle events
// (ScanStarted/ScanCompleted). These bracket the whole scan rather than a single
// phase, so they are stamped with the passive phase by convention.
func (o *Orchestrator) newLifecycleMeta(at time.Time) events.EventMeta {
	return events.EventMeta{
		ScanID:          o.scanID,
		Source:          "orchestrator",
		Phase:           events.PhasePassive,
		Category:        events.CategoryLifecycle,
		ObservationKind: events.ObservationKindLifecycle,
		CapturedAt:      at,
	}
}

// emitLifecycle calls factory with the current time, then publishes the result.
// The factory pattern ensures EventID is computed after all other fields are set.
func (o *Orchestrator) emitLifecycle(ctx context.Context, factory func(time.Time) events.DomainEvent) {
	o.publish(ctx, []events.DomainEvent{factory(time.Now())})
}

// emitEnvironment records the immutable execution inputs immediately after its
// ScanStarted marker. The app supplies the payload; this method owns identity and
// timing, so the envelope is built in one place.
func (o *Orchestrator) emitEnvironment(ctx context.Context) {
	at := time.Now()
	e := o.cfg.Environment
	e.EventMeta = o.newLifecycleMeta(at)
	e.EventID = events.NewEventID(at, e)
	o.publish(ctx, []events.DomainEvent{e})
}

func elapsedDuration(start, end time.Time) time.Duration {
	d := end.Sub(start)
	if d <= 0 {
		return time.Nanosecond
	}
	return d
}

// crawlerInterceptor receives the crawler's system events, translates them into
// domain events, forwards them to the configured sink, and spawns a per-domain
// DNS lookup whenever a new domain is discovered.
type crawlerInterceptor struct {
	o          *Orchestrator
	ctx        context.Context
	rootDomain string
}

func (i *crawlerInterceptor) AppendSystem(ctx context.Context, evt crawler.SystemEvent) error {
	domainEvents := translate.CrawlerEvent(evt, i.o.scanID)
	i.o.publish(i.ctx, domainEvents)

	if d, ok := evt.(crawler.DomainNameFound); ok {
		causationID := firstEventID(domainEvents)
		i.o.spawnDns(i.ctx, d.Domain, causationID)
		i.o.spawnWhois(i.ctx, d.Domain, causationID)
		i.o.spawnMailsec(i.ctx, d.Domain, causationID)
		i.o.fanOutPaid(i.ctx, d.Domain, causationID)
	}

	// A degraded crt.sh empty is not terminal: the orchestrator consults the
	// independent CT sources for the same query and acts on the verdict (confirm and
	// backfill the lost names/certs, or downgrade toward a real empty).
	// corroborateDegraded emits the issue itself, so this event does not also fall
	// through to the generic crawler-issue path below.
	if d, ok := evt.(crawler.DomainSearchDegraded); ok {
		i.o.corroborateDegraded(i.ctx, d)
		return nil
	}

	if crawler.IsError(evt) || crawler.IsFailure(evt) {
		sev := events.SeverityMedium
		if crawler.IsFailure(evt) {
			sev = events.SeverityHigh
		}
		issue := crawlerIssue(i.o.scanID, evt, crawlerIssueQuery(evt, i.rootDomain), evt.String(), sev)
		i.o.publish(ctx, []events.DomainEvent{issue})
	}
	return nil
}

// crawlerIssue builds the coverage IssueObserved for a crawler error/failure event.
// msg is the human-readable detail (evt.String() for a raw crawler issue, or a
// corroboration verdict message for a resolved degraded empty); query and severity are
// supplied by the caller. Source stays "crawler" so a corroborated degraded issue
// files under the same classification as the raw one it replaces.
func crawlerIssue(scanID string, evt crawler.SystemEvent, query, msg string, sev events.Severity) events.IssueObserved {
	payloadBytes, _ := json.MarshalIndent(evt, "", "  ")
	issue := events.IssueObserved{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     evt.ID(),
			Source:          "crawler",
			Phase:           events.PhasePassive,
			Category:        events.CategoryIssue,
			Severity:        sev,
			ObservationKind: events.ObservationKindOperational,
			CapturedAt:      evt.At(),
		},
		Query:   query,
		Error:   msg,
		Payload: string(payloadBytes),
	}
	issue.EventID = events.NewEventID(evt.At(), issue)
	return issue
}

// publish forwards each event to the sink and then runs it through the detector
// set, publishing any findings it produces.
func (o *Orchestrator) publish(ctx context.Context, evts []events.DomainEvent) {
	for _, e := range evts {
		o.emit(ctx, e)
		o.runDetectors(ctx, e)
	}
}

// emit writes a single event to the sink and updates the passive counters. It is
// the terminal step shared by discovery events and derived findings; it does not
// run detectors, so findings never feed back into detection.
func (o *Orchestrator) emit(ctx context.Context, e events.DomainEvent) {
	if o.cfg.DomainEventSink == nil {
		return
	}
	o.recordDomainEventID(e)
	o.recordGoScansSeed(e)
	_ = o.cfg.DomainEventSink.AppendDomain(ctx, e)
}

// recordGoScansSeed captures the terminal GoScans substage's virtual-host seed from
// the event stream this run is producing: every name a passive observation
// attributes to an address becomes a candidate server name for that host's TLS and
// web jobs. It is a no-op unless the substage is enabled.
func (o *Orchestrator) recordGoScansSeed(e events.DomainEvent) {
	if ev, ok := e.(events.IPAddressDiscovered); ok {
		o.recordGoScansHostName(ev.IP, ev.Domain)
	}
}

// recordDomainEventID remembers the EventID of the first DnsDomainNameDiscovered
// for each domain, so the active per-domain sweep can thread causation back to
// the discovery event.
func (o *Orchestrator) recordDomainEventID(e events.DomainEvent) {
	d, ok := e.(events.DnsDomainNameDiscovered)
	if !ok {
		return
	}
	o.targets.recordDomainDiscovery(d.Domain, d.Meta().EventID, d.Depth)

	// Track which source contributed each distinct name, so the passive phase can
	// cross-check crt.sh's CT coverage against the certspotter corroborator.
	// certCoverage self-synchronizes, so it is recorded into outside any other
	// state owner's lock.
	//
	// The root input is skipped: it is emitted with Source crtsh for scheduling
	// reasons and ObservationKind input, but it is the scan target, not a name crt.sh
	// returned. Counting it would let a certless target report crt.sh coverage of 1 and
	// raise a false certspotter-inert issue. A name crt.sh genuinely returns from CT
	// carries ObservationKind historical_log and is still recorded.
	if src := d.Meta().Source; src != "" && d.Meta().ObservationKind != events.ObservationKindInput {
		o.certCoverage.Record(src, d.Domain)
	}
}

// runDetectors passes a discovery event through the registered rules and emits
// any resulting findings, stamping each with scan-correlation metadata derived
// from the triggering event.
func (o *Orchestrator) runDetectors(ctx context.Context, src events.DomainEvent) {
	corrID := tooleventlog.CorrIDFrom(ctx)
	findings := o.detectors.Apply(src)
	for i := range findings {
		f := findings[i]
		o.stampFinding(&f, src)
		// A finding is derived from the same tool call as the event that triggered
		// it; stamp it here because FindingRaised is a value type that emit cannot
		// address. Set after stampFinding's EventID so identity is unaffected.
		f.ToolCorrID = corrID
		o.emit(ctx, f)
	}
}

// stampFinding completes a finding's envelope from the triggering event: it
// inherits the source event's phase and timestamp, links back to it via
// CausationID, and gets a stable EventID. Severity and category are set by the
// rule and left untouched.
//
// The envelope's own ObservationKind is always "derived" - a finding is derived
// from another event, never observed directly - so the acquisition method of the
// evidence is carried separately on EvidenceObservationKind. Without that a
// consumer could not tell a live-probe finding from one inferred off a passive
// third-party snapshot.
func (o *Orchestrator) stampFinding(f *events.FindingRaised, src events.DomainEvent) {
	srcMeta := src.Meta()
	f.ScanID = o.scanID
	f.CausationID = srcMeta.EventID
	f.Source = sourceDetector
	f.Phase = srcMeta.Phase
	f.Category = events.CategoryFinding
	f.ObservationKind = events.ObservationKindDerived
	f.CapturedAt = srcMeta.CapturedAt
	stampFindingEvidenceTime(f, srcMeta)
	f.EventID = events.NewEventID(f.CapturedAt, *f)
}

// stampFindingEvidenceTime fills the evidence-time fields a rule left unset.
//
// The acquisition kind is always the triggering event's; a rule may pre-set it when
// one event carries claims of more than one kind, and that choice wins.
//
// The observation instant is only defaulted when Vanguard itself did the observing:
// for an active probe or a DNS answer, the capture time is the observation time. For
// a passive snapshot or a historical log the provider observed the subject at its own
// time, so a rule that could not read one from the payload leaves the field zero and
// it stays zero. Defaulting those to the capture time would assert that the provider
// observed the subject during this scan.
func stampFindingEvidenceTime(f *events.FindingRaised, srcMeta events.EventMeta) {
	if f.EvidenceObservationKind == "" {
		f.EvidenceObservationKind = srcMeta.ObservationKind
	}
	if !f.EvidenceObservedAt.IsZero() {
		return
	}
	switch f.EvidenceObservationKind {
	case events.ObservationKindActiveProbe, events.ObservationKindDNSAnswer:
		f.EvidenceObservedAt = srcMeta.CapturedAt
	case events.ObservationKindInput, events.ObservationKindHistoricalLog,
		events.ObservationKindPassiveSnapshot, events.ObservationKindDerived,
		events.ObservationKindLifecycle, events.ObservationKindOperational:
		// Someone other than Vanguard did the observing, at a time only they know.
		// The rule reads it from the payload when the source supplied one; there is
		// nothing to default to here, and the scan time would be a false claim.
	}
}

// firstEventID returns the EventID of the first event in evts, or "" if empty.
// It is used to thread causation from a parent event to events it spawns.
func firstEventID(evts []events.DomainEvent) string {
	if len(evts) == 0 {
		return ""
	}
	return evts[0].Meta().EventID
}

// crawlerIssueQuery extracts the most relevant query/target string from a
// crawler error or failure event for inclusion in an IssueObserved.
func crawlerIssueQuery(evt crawler.SystemEvent, rootDomain string) string {
	switch e := evt.(type) {
	case crawler.DomainProcessingFailed:
		return e.Domain
	case crawler.DomainSearchDegraded:
		return e.Domain
	case crawler.CrawlCanceled:
		return rootDomain
	default:
		return ""
	}
}
