package orchestration

import (
	"context"
	"fmt"
	"github.com/velgard-sk/vanguard/internal/collection/events"
	"time"
)

// fanOutPaid runs the paid per-domain lookups (breach, censys, virustotal, shodan,
// netlas) for an in-scope domain. Out-of-scope domains are still fully discovered
// and get the cheap passive treatment; only the expensive fan-out is skipped, and
// that decision is emitted once per domain so the report and audit stay complete.
func (o *Orchestrator) fanOutPaid(ctx context.Context, domain, causationID string) {
	depth, _ := o.targets.depth(domain)
	if ok, reason := o.gate.inScope(domain, depth); !ok {
		o.emitScopeExclusion(ctx, domain, fmt.Sprintf("paid lookups skipped for %s: %s", domain, reason))
		return
	}
	o.spawnBreach(ctx, domain, causationID)
	o.spawnCensys(ctx, domain, causationID)
	o.spawnShodan(ctx, domain, causationID)
	o.spawnNetlas(ctx, domain, causationID)
	o.spawnVirustotal(ctx, domain, causationID)
}

// takePaidBudget reserves one paid call for tool against the per-tool cap, returning
// false (and emitting one budget event per tool) when the cap is reached. A cap of
// -1 means unlimited and 0 permits no calls.
func (o *Orchestrator) takePaidBudget(ctx context.Context, tool string) bool {
	allowed, firstReport := o.gate.takePaidBudget(tool, o.cfg.MaxPaidLookupsPerTool)
	if !allowed && firstReport {
		o.emitBudgetExclusion(ctx, tool, fmt.Sprintf("%s paid budget reached after %d calls", tool, o.cfg.MaxPaidLookupsPerTool))
	}
	return allowed
}

// takeCensysPaidBudget applies the paid-request budget to a Censys call only when the
// configured mode actually reaches the Censys API. Cache-only work is answered from
// compiled-in data, so it costs nothing: it must neither be throttled by the budget
// nor decrement it, or a fixture-backed scan would exhaust a budget it never spent.
func (o *Orchestrator) takeCensysPaidBudget(ctx context.Context) bool {
	if !o.cfg.Censys.Mode.UsesService() {
		return true
	}
	return o.takePaidBudget(ctx, sourceCensys)
}

// toolIsUnavailable reports whether the circuit breaker has tripped for tool, so a
// paid spawn can skip the provider without consuming budget or emitting noise.
func (o *Orchestrator) toolIsUnavailable(tool string) bool {
	return o.gate.toolIsUnavailable(tool)
}

// markToolUnavailable trips the circuit breaker for a paid tool after it reported
// (via toolerr.ErrProviderUnavailable) that it cannot serve the scan. It records the
// reason once and emits a single IssueObserved so the report explains the gap,
// mirroring the budget-exclusion dedup. Later spawns short-circuit on
// toolIsUnavailable.
func (o *Orchestrator) markToolUnavailable(ctx context.Context, tool string, err error) {
	if o.gate.markToolUnavailable(tool, err.Error()) {
		o.emitControlIssue(ctx, sourceCircuitBreaker, "", tool,
			fmt.Sprintf("%s unavailable: %v; skipping for remainder of scan", tool, err))
	}
}

// takeActiveBudget reserves one host for the active sweep against the cap,
// returning false (and emitting one budget event) when the cap is reached. A cap of
// -1 means unlimited and 0 permits no hosts. It is the shared gate for both the per-domain probe and the
// per-IP host scan, so the budget bounds the combined active work. Callers iterate
// in a deterministic order (domains shallowest-then-name, IPs sorted) so the budget
// is spent on the most likely in-scope assets first.
func (o *Orchestrator) takeActiveBudget(ctx context.Context) bool {
	allowed, firstReport := o.gate.takeActiveBudget(o.cfg.MaxActiveHosts)
	if !allowed && firstReport {
		o.emitBudgetExclusion(ctx, "active", fmt.Sprintf("active host budget reached after %d hosts", o.cfg.MaxActiveHosts))
	}
	return allowed
}

// inScopeForActive reports whether the active sweep should probe domain, emitting a
// scope exclusion (once per domain) when it should not.
func (o *Orchestrator) inScopeForActive(ctx context.Context, domain string) bool {
	depth, _ := o.targets.depth(domain)
	if ok, reason := o.gate.inScope(domain, depth); !ok {
		o.emitScopeExclusion(ctx, domain, fmt.Sprintf("active probe skipped for %s: %s", domain, reason))
		return false
	}
	return true
}

// emitScopeExclusion records a scope decision as an auditable issue event, once per
// domain, so the event stream stays the single source of truth for what was done.
func (o *Orchestrator) emitScopeExclusion(ctx context.Context, domain, msg string) {
	if o.gate.recordScopeExclusion(domain) {
		o.emitControlIssue(ctx, sourceScope, events.IssueClassScopeSchedule, domain, msg)
	}
}

// emitActiveExclusion records a hard-exclusion denial of an active target as an
// auditable active-phase issue, once per (kind, normalized target, matched rule). It
// names the target, whether the matching rule was a domain or an IP/CIDR, and the
// canonical matched entry (carried in reason). It is never emitted as a network
// failure or an unreachability result, and no ActiveTargetApproved accompanies it.
func (o *Orchestrator) emitActiveExclusion(ctx context.Context, kind events.ActiveTargetKind, target, reason string) {
	if !o.gate.recordActiveExclusion(string(kind), target, reason) {
		return
	}
	o.emitControlIssuePhase(ctx, events.PhaseActive, sourceScope, events.IssueClassExclusion, target,
		fmt.Sprintf("active %s target %s denied: %s", kind, target, reason))
}

// emitBudgetExclusion records a budget decision as an auditable issue event.
func (o *Orchestrator) emitBudgetExclusion(ctx context.Context, target, msg string) {
	o.emitControlIssue(ctx, sourceBudget, events.IssueClassBudget, target, msg)
}

// emitProviderProbeDecision records, once per IP, why a provider-only host was
// approved or skipped, so ownership policy is explicit in the event stream. The
// approved flag selects the issue class so scope accounting can count admitted and
// withheld provider hosts separately without parsing the reason text.
func (o *Orchestrator) emitProviderProbeDecision(ctx context.Context, ip string, approved bool, reason string) {
	if o.gate.recordProviderProbeDecision(ip) {
		class := events.IssueClassProviderSkipped
		if approved {
			class = events.IssueClassProviderApproved
		}
		o.emitControlIssue(ctx, sourceProviderProbe, class, ip,
			fmt.Sprintf("provider-only host %s: %s", ip, reason))
	}
}

// emitControlIssue publishes an info-level IssueObserved from a scope/budget
// control decision. It reuses the issue vocabulary (category issue) rather than
// inventing a new event, keeping the decision in the canonical, replayable stream.
// The class is one of the events.IssueClass* control-plane constants so the
// decision kind survives into the report's scope accounting.
func (o *Orchestrator) emitControlIssue(ctx context.Context, source, class, query, msg string) {
	o.emitControlIssuePhase(ctx, events.PhasePassive, source, class, query, msg)
}

// emitControlIssuePhase is emitControlIssue with an explicit phase. Scope and budget
// decisions in the passive fan-out stay passive-phase; active-admission decisions
// (a hard exclusion refused before approval) are active-phase, so the stream places
// the decision in the phase whose work it withheld.
func (o *Orchestrator) emitControlIssuePhase(ctx context.Context, phase events.Phase, source, class, query, msg string) {
	at := time.Now()
	issue := events.IssueObserved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			Source:          source,
			Phase:           phase,
			Category:        events.CategoryIssue,
			Severity:        events.SeverityInfo,
			ObservationKind: events.ObservationKindOperational,
			CapturedAt:      at,
		},
		Query: query,
		Error: msg,
		Class: class,
	}
	issue.EventID = events.NewEventID(at, issue)
	o.publish(ctx, []events.DomainEvent{issue})
}
