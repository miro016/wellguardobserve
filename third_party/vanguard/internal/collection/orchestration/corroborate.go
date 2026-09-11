package orchestration

import (
	"context"
	"errors"
	"sync"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/certs"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/crawler"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/censys"
	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

// certspotterMemo caches certspotter fetch results per domain for one scan so the
// discovery pass and the degraded-empty corroboration never issue a second certspotter
// query for a root the other already fetched. The certspotter client's own singleflight
// collapses two *concurrent* misses into one HTTP request; this memo covers the
// *sequential* case - the corroboration fires mid-crawl, the discovery pass runs after it
// - by serving the later caller from cache. A domain is cached only on a successful
// fetch, so a transient error does not suppress a later retry.
//
// Its Certs method matches certs.LiveCertSource, so the memo backs the corroboration's
// live source directly; runCertspotter calls the same method for its discovery fetch.
type certspotterMemo struct {
	fetch func(ctx context.Context, domain string) (names []string, present bool, err error)
	mu    sync.Mutex
	cache map[string]certspotterMemoEntry
}

// certspotterMemoEntry is one cached certspotter result: the in-scope names and whether
// any issuance was seen. Only successful fetches are stored.
type certspotterMemoEntry struct {
	names   []string
	present bool
}

// newCertspotterMemo builds a memo over fetch (the certspotter client's Certs method).
func newCertspotterMemo(fetch func(context.Context, string) ([]string, bool, error)) *certspotterMemo {
	return &certspotterMemo{fetch: fetch, cache: make(map[string]certspotterMemoEntry)}
}

// Certs returns certspotter's in-scope names and presence for domain, fetching once per
// domain and serving every later call for the same domain from the cache. It satisfies
// certs.LiveCertSource.
func (m *certspotterMemo) Certs(ctx context.Context, domain string) (names []string, present bool, err error) {
	m.mu.Lock()
	if e, ok := m.cache[domain]; ok {
		m.mu.Unlock()
		return e.names, e.present, nil
	}
	m.mu.Unlock()

	names, present, err = m.fetch(ctx, domain)
	if err != nil {
		return nil, false, err
	}

	m.mu.Lock()
	m.cache[domain] = certspotterMemoEntry{names: names, present: present}
	m.mu.Unlock()
	return names, present, nil
}

// historyCertAdapter adapts *censys.Client to certs.HistoryCertSource, copying the
// censys certificate result into the tool-agnostic certs types so the certs package
// stays free of the censys import.
type historyCertAdapter struct{ client *censys.Client }

func (a historyCertAdapter) Certificates(ctx context.Context, domain string) (*certs.Certs, error) {
	dc, err := a.client.Certificates(ctx, domain)
	if err != nil {
		return nil, err
	}
	if dc == nil {
		// A cache-only client with no fixture entry for the domain: a source that
		// could not be consulted, not a domain with no certificates.
		return nil, nil //nolint:nilnil // "not consulted" is neither a result nor a failure
	}
	out := &certs.Certs{Present: dc.Present, Names: dc.Names, RetrievalSource: dc.RetrievalSource}
	for i := range dc.Certs {
		c := dc.Certs[i]
		out.Certs = append(out.Certs, certs.CertMeta{
			FingerprintSHA256: c.FingerprintSHA256,
			Names:             c.Names,
			CommonName:        c.CommonName,
			IssuerDN:          c.IssuerDN,
			SerialNumber:      c.SerialNumber,
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
		})
	}
	return out, nil
}

// initCorroborationSources wires the constructed CT clients to the corroboration source
// interfaces. censys is adapted to the history source; certspotter is wrapped in the
// per-scan memo (which also backs runCertspotter's discovery fetch) and set as the live
// source. A nil client leaves its source nil (an unconfigured source is not consulted);
// guarding on the client here avoids storing a non-nil interface wrapping a nil pointer.
func (o *Orchestrator) initCorroborationSources() {
	if o.tools.censys != nil {
		o.historyCerts = historyCertAdapter{client: o.tools.censys}
	}
	if o.tools.certspotter != nil {
		o.certspotterMemo = newCertspotterMemo(o.tools.certspotter.Certs)
		o.liveCerts = o.certspotterMemo
	}
}

// corroborateDegraded handles a crt.sh DomainSearchDegraded: it consults the available
// second CT sources for the same query, applies the pure certs.Decide, and acts on the
// verdict - raising a High confirmed issue and backfilling the recovered names/certs,
// lowering the issue toward a real empty, or falling back to the pre-corroboration
// generic Medium issue when no source could corroborate.
//
// When no second source is configured it emits the generic issue synchronously (the
// NoCorroboration outcome). Otherwise the consult-and-act runs on o.wg so it does not
// block the crawler's event sink; the wg.Add here in the crawler callback (before
// runDiscovery's single wg.Wait) keeps the child counted by the end-of-run barrier.
func (o *Orchestrator) corroborateDegraded(ctx context.Context, evt crawler.DomainSearchDegraded) {
	if ctx.Err() != nil {
		return
	}
	if o.historyCerts == nil && o.liveCerts == nil {
		o.emitDegradedIssue(ctx, evt, evt.String(), events.SeverityMedium)
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()

		consulted, results := o.consultCertSourcesUnderSem(ctx, evt.Domain)
		if ctx.Err() != nil {
			return
		}

		verdict := certs.Decide(consulted, results)
		switch verdict.Outcome {
		case certs.Confirmed:
			o.emitDegradedIssue(ctx, evt, verdict.Message, mapSeverity(verdict.Severity))
			o.backfillCorroboration(ctx, evt.Domain, verdict)
		case certs.Downgraded:
			o.emitDegradedIssue(ctx, evt, verdict.Message, mapSeverity(verdict.Severity))
		default: // NoCorroboration: every available source errored or was budget-skipped.
			o.emitDegradedIssue(ctx, evt, evt.String(), events.SeverityMedium)
		}
	}()
}

// consultCertSourcesUnderSem bounds the two network consultations with a single sem
// slot, released before it returns so the backfill fan-out (whose spawns take their own
// slots in the caller) never holds two slots at once - which would deadlock at a low
// MaxConcurrency.
func (o *Orchestrator) consultCertSourcesUnderSem(ctx context.Context, query string) (int, []certs.SourceResult) {
	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, nil
	}
	defer func() { <-o.sem }()
	return o.consultCertSources(ctx, query)
}

// consultCertSources queries the available second CT sources for query and returns the
// count actually consulted alongside their results. censys (history) is consulted first
// because it carries the decision; it is gated by the circuit breaker and paid budget.
// certspotter (live) is free. Any error is treated as "did not corroborate": the source
// produces no result and is not counted, so an all-errored consultation yields
// NoCorroboration rather than a false downgrade.
func (o *Orchestrator) consultCertSources(ctx context.Context, query string) (consulted int, results []certs.SourceResult) {
	if o.historyCerts != nil && !o.toolIsUnavailable(sourceCensys) && o.takeCensysPaidBudget(ctx) {
		callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, query), newToolCorrID(o.scanID, sourceCensys, query))
		dc, err := o.historyCerts.Certificates(callCtx, query)
		switch {
		case err != nil:
			if errors.Is(err, toolerr.ErrProviderUnavailable) {
				o.markToolUnavailable(ctx, sourceCensys, err)
			}
		case dc != nil:
			consulted++
			results = append(results, certs.SourceResult{
				Source:          sourceCensys,
				History:         true,
				Present:         dc.Present,
				Names:           dc.Names,
				Certs:           dc.Certs,
				RetrievalSource: dc.RetrievalSource,
			})
		}
	}

	if o.liveCerts != nil {
		callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, query), newToolCorrID(o.scanID, sourceCertspotter, query))
		names, present, err := o.liveCerts.Certs(callCtx, query)
		if err == nil {
			consulted++
			results = append(results, certs.SourceResult{
				Source:  sourceCertspotter,
				History: false,
				Present: present,
				Names:   names,
			})
		}
	}
	return consulted, results
}

// backfillCorroboration repopulates the asset graph a confirmed degraded empty lost:
// each recovered name re-enters the same per-domain fan-out a crawler-discovered name
// does (the existing seen-sets dedup a name already found), and each recovered
// certificate is emitted as a CertificateDiscovered so entity_Certificate.json is
// repopulated. Certs are non-empty only for a history-source confirmation.
//
// It runs without holding a sem slot (corroborateDegraded released it), so the fan-out
// spawns can acquire their own slots without hold-and-wait.
func (o *Orchestrator) backfillCorroboration(ctx context.Context, query string, verdict certs.Verdict) {
	source := verdict.ConfirmedBy
	// The deciding source's retrieval provenance rides onto everything it recovered,
	// so a name or certificate backfilled from compiled-in data is distinguishable
	// from one recovered by a live provider request.
	retrieval := events.RetrievalSource(verdict.RetrievalSource)

	for _, name := range verdict.Names {
		evts := translate.CorroboratedSubdomain(name, query, source, o.scanID, retrieval)
		o.publish(ctx, evts)
		causationID := firstEventID(evts)
		o.spawnDns(ctx, name, causationID)
		o.spawnWhois(ctx, name, causationID)
		o.spawnMailsec(ctx, name, causationID)
		o.fanOutPaid(ctx, name, causationID)
	}

	corrID := tooleventlog.CorrIDFrom(ctx)
	for i := range verdict.Certs {
		o.publish(ctx, translate.CorroboratedCertificate(verdict.Certs[i], query, source, o.scanID, corrID, retrieval))
	}
}

// emitDegradedIssue publishes the coverage issue for a degraded crt.sh empty, keeping
// the crawler source/causation of the pre-corroboration issue it replaces and carrying
// the given message and severity (the corroboration verdict's, or the generic
// evt.String()/Medium for the no-corroboration fallback).
func (o *Orchestrator) emitDegradedIssue(ctx context.Context, evt crawler.DomainSearchDegraded, msg string, sev events.Severity) {
	o.publish(ctx, []events.DomainEvent{crawlerIssue(o.scanID, evt, evt.Domain, msg, sev)})
}

// mapSeverity maps the certs subpackage's local severity to the domain events
// severity, keeping certs free of the events dependency.
func mapSeverity(s certs.Severity) events.Severity {
	switch s {
	case certs.SeverityHigh:
		return events.SeverityHigh
	case certs.SeverityLow:
		return events.SeverityLow
	default:
		return events.SeverityMedium
	}
}
