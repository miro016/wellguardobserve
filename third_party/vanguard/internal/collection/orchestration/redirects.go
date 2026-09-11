package orchestration

import (
	"context"
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// publishHTTPRedirects translates and publishes a tool's redirect trail before
// the caller decides whether the final response is usable. Rejected destinations
// also produce one active scope issue per normalized source/destination host pair.
func (o *Orchestrator) publishHTTPRedirects(ctx context.Context, trail []scopecheck.RedirectObservation, causationID, source, corrID string) {
	for _, domainEvent := range translate.HTTPRedirects(trail, o.scanID, causationID, source, corrID) {
		redirect := events.AsValue(domainEvent).(events.HttpRedirectObserved)
		o.publish(ctx, []events.DomainEvent{redirect})
		if redirect.Disposition == events.HttpRedirectRejected {
			o.emitRedirectScopeIssue(ctx, redirect)
		}
	}
}

// emitRedirectScopeIssue records a rejected redirect once per normalized host
// pair while preserving the redirect event as the issue's cause and tool join.
func (o *Orchestrator) emitRedirectScopeIssue(ctx context.Context, redirect events.HttpRedirectObserved) {
	fromHost, err := scopecheck.NormalizeURL(redirect.FromURL)
	if err != nil {
		return
	}
	toHost, err := scopecheck.NormalizeURL(redirect.ToURL)
	if err != nil || !o.gate.recordRequestRejection(fromHost, toHost) {
		return
	}

	at := time.Now()
	issue := events.IssueObserved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			CausationID:     redirect.EventID,
			Source:          "scope",
			Phase:           events.PhaseActive,
			Category:        events.CategoryIssue,
			Severity:        events.SeverityInfo,
			ObservationKind: events.ObservationKindOperational,
			CapturedAt:      at,
			ToolCorrID:      redirect.ToolCorrID,
		},
		Query: toHost,
		Error: fmt.Sprintf("HTTP redirect from %s to %s rejected before contact: %s",
			fromHost, toHost, redirect.Reason),
		Class: events.IssueClassScopeRedirect,
	}
	issue.EventID = events.NewEventID(at, issue)
	o.publish(ctx, []events.DomainEvent{issue})
}
