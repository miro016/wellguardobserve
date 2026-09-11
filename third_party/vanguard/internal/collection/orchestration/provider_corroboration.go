package orchestration

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

// providerHostCandidate is a provider-attributed address waiting for an active
// probe decision. domain is also the SNI name for the bounded certificate check.
type providerHostCandidate struct {
	ip          string
	domain      string
	causationID string
}

// providerHostEvidence is the independent ownership evidence collected for one
// provider-only address. All fields are guarded by Orchestrator.mu.
type providerHostEvidence struct {
	ptrNames  []string
	certNames []string
}

// handleProviderHost applies the configured policy before a provider-attributed IP
// can reach the ordinary host scheduler. needsASN says whether the corroboration
// collector still owes this address its ASN lookup: it is set for the event that
// first registered the address, so exactly one lookup per address is made in a run.
func (o *Orchestrator) handleProviderHost(ctx context.Context, candidate providerHostCandidate, needsASN bool) {
	if !o.corroborationCollectorRuns() || ctx.Err() != nil {
		return
	}
	// A hard exclusion is applied before any provider policy, corroboration queue, or
	// TLS certificate preflight, so an excluded address is never dialed for evidence
	// and an excluded source name never admits its provider-attributed addresses.
	// Both boundaries are audited here because a provider-only or portscan-only run
	// need not schedule the source name's per-domain probes.
	if o.ipHardExcluded(ctx, candidate.ip) {
		return
	}
	if o.rejectExcludedDomain(ctx, candidate.domain) {
		return
	}

	switch o.cfg.ProviderHostProbePolicy {
	case ProviderHostProbeAlways:
		o.emitProviderProbeDecision(ctx, candidate.ip, true, "approved for active probing because policy is always")
		o.scheduleHostScan(ctx, candidate.ip, candidate.causationID)
	case ProviderHostProbeCorroborated:
		// enqueue checks DNS confirmation under the provider-state lock. Keeping the
		// shortcut there closes the gap where DNS can confirm the address after a
		// separate isDNSConfirmed check but before the candidate is queued.
		o.queueProviderHostCorroboration(ctx, candidate, needsASN)
	case ProviderHostProbeNever, "":
		o.emitProviderProbeDecision(ctx, candidate.ip, false, "not actively probed because policy is never")
	default:
		// Config validation rejects unknown values. Programmatic callers still fail
		// closed rather than broadening active scope.
		o.emitProviderProbeDecision(ctx, candidate.ip, false,
			fmt.Sprintf("not actively probed because policy %q is invalid", o.cfg.ProviderHostProbePolicy))
	}
}

// corroborationCollectorRuns reports whether this execution can reach the provider
// evidence collector and the host scheduler at all. Without the active phase and at
// least one per-IP tool there is nothing to decide, so provider hosts stay inferred
// assets and their passive ASN enrichment runs in ingestProviderHosts instead.
func (o *Orchestrator) corroborationCollectorRuns() bool {
	return o.cfg.EnableActive && o.hostToolsEnabled()
}

// queueProviderHostCorroboration records one candidate and launches at most one
// evidence collector for its IP. The caller may hold a sem slot, so the collector
// acquires its own slot inside the child goroutine.
func (o *Orchestrator) queueProviderHostCorroboration(ctx context.Context, candidate providerHostCandidate, needsASN bool) {
	confirmed, startCollector := o.providers.enqueue(candidate)
	if confirmed {
		o.completeProviderHostASN(ctx, candidate, needsASN)
		o.scheduleHostScan(ctx, candidate.ip, candidate.causationID)
		return
	}
	if !startCollector {
		// Another provider result can queue the same address before the result that
		// first registered it arrives here. That earlier caller does not own the ASN
		// lookup, so the registering caller must still complete it.
		o.completeProviderHostASN(ctx, candidate, needsASN)
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		select {
		case o.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-o.sem }()
		o.collectProviderHostEvidence(ctx, candidate, needsASN)
	}()
}

// collectProviderHostEvidence performs passive ASN/PTR checks first. Only when
// neither corroborates ownership does it send the one TLS ClientHello/handshake
// allowed by the certificate preflight; no HTTP request or host sweep occurs here.
func (o *Orchestrator) collectProviderHostEvidence(ctx context.Context, candidate providerHostCandidate, needsASN bool) {
	o.completeProviderHostASN(ctx, candidate, needsASN)

	if o.tools.dns != nil {
		callCtx := tooleventlog.WithCorrID(
			tooleventlog.WithTarget(ctx, candidate.ip),
			newToolCorrID(o.scanID, sourceDnsinfo, candidate.ip),
		)
		if records, err := o.tools.dns.LookupPTR(callCtx, candidate.ip); err == nil {
			names := make([]string, 0, len(records))
			for _, record := range records {
				names = append(names, record.Hostname)
			}
			o.providers.addPTRNames(candidate.ip, names)
		}
	}

	if len(o.providerOwnershipReasons(candidate.ip)) > 0 || o.tools.providerTLS == nil || candidate.domain == "" {
		return
	}
	tlsCtx := tooleventlog.WithScan(ctx, o.scanID, string(events.PhaseActive))
	tlsCtx = o.withActiveExclusionAudit(tlsCtx)
	tlsCtx = tooleventlog.WithTarget(tlsCtx, candidate.ip)
	tlsCtx = tooleventlog.WithCorrID(tlsCtx, newToolCorrID(o.scanID, sourceHTTPS, candidate.ip))
	if evidence, err := o.tools.providerTLS.ProbeCertificate(tlsCtx, candidate.ip, candidate.domain); err == nil {
		o.providers.addCertificateNames(candidate.ip, evidence.DNSNames)
	}
}

// completeProviderHostASN performs the lookup owned by the provider registration
// path when that path cannot leave it to an evidence collector. DNS confirmation
// can make corroboration unnecessary, and another provider result can start the
// collector without owning ASN work; neither ordering may discard the lookup. A
// restored or concurrently recorded prefix makes the helper a no-op.
func (o *Orchestrator) completeProviderHostASN(ctx context.Context, candidate providerHostCandidate, needsASN bool) {
	if !needsASN || o.tools.asn == nil || o.providers.hasNetblock(candidate.ip) || ctx.Err() != nil {
		return
	}
	callCtx := tooleventlog.WithCorrID(
		tooleventlog.WithTarget(ctx, candidate.ip),
		newToolCorrID(o.scanID, sourceAsn, candidate.ip),
	)
	record, err := o.tools.asn.Lookup(callCtx, candidate.ip)
	if err != nil {
		return
	}
	o.recordIPNetblock(candidate.ip, false, record.Prefix)
	o.publish(callCtx, translate.Netblock(record, o.scanID, candidate.causationID, tooleventlog.CorrIDFrom(callCtx)))
}

// finalizeProviderHosts makes deterministic decisions after every passive evidence
// collector has drained. Approved hosts enter the ordinary dedup/budget scheduler;
// skipped hosts remain inferred assets with one explicit audit issue.
func (o *Orchestrator) finalizeProviderHosts(ctx context.Context) {
	if o.cfg.ProviderHostProbePolicy != ProviderHostProbeCorroborated {
		return
	}

	candidates := o.providers.drainCandidates()

	for _, candidate := range candidates {
		if o.providers.isDNSConfirmed(candidate.ip) {
			o.scheduleHostScan(ctx, candidate.ip, candidate.causationID)
			continue
		}
		reasons := o.providerOwnershipReasons(candidate.ip)
		if len(reasons) == 0 {
			o.emitProviderProbeDecision(ctx, candidate.ip, false,
				"not actively probed because no in-scope PTR, shared DNS-confirmed netblock, or in-scope certificate SAN was found")
			continue
		}
		o.emitProviderProbeDecision(ctx, candidate.ip, true, "approved for active probing after "+strings.Join(reasons, "; "))
		o.scheduleHostScan(ctx, candidate.ip, candidate.causationID)
	}
}

// recordIPNetblock records one ASN result, ignoring an empty prefix so an
// unresolved lookup cannot register a blank routed prefix for the address.
func (o *Orchestrator) recordIPNetblock(ip string, confirmed bool, prefix string) {
	if prefix == "" {
		return
	}
	o.providers.recordNetblock(ip, confirmed, prefix)
}

// providerOwnershipReasons returns stable, human-readable independent evidence
// that ties ip to the configured estate.
func (o *Orchestrator) providerOwnershipReasons(ip string) []string {
	ptrNames, certNames, prefix, sharedNetblock := o.providers.evidenceFor(ip)

	scope := o.gate.scopeRef()
	reasons := make([]string, 0, 3)
	if name := firstInScopeName(scope, ptrNames); name != "" {
		reasons = append(reasons, "in-scope PTR "+name)
	}
	if sharedNetblock {
		reasons = append(reasons, "shared DNS-confirmed netblock "+prefix)
	}
	if name := firstInScopeName(scope, certNames); name != "" {
		reasons = append(reasons, "in-scope certificate SAN "+name)
	}
	return reasons
}

// firstInScopeName returns the first sorted name inside the root/include boundary.
// Depth is irrelevant for ownership evidence, so the scope check uses depth zero.
func firstInScopeName(scope Scope, names []string) string {
	names = append([]string(nil), names...)
	sort.Strings(names)
	for _, name := range names {
		if ok, _ := scope.InScope(name, 0); ok {
			return normalizeName(name)
		}
	}
	return ""
}
