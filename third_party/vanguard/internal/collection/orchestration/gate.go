package orchestration

import (
	"net/netip"
	"sync"

	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// gate groups the cross-cutting run policy: scope decisions, paid and active
// budget counters, per-tool circuit breakers, and the dedup sets that prevent
// redundant audit events. All mutable state is guarded by mu. The orchestrator
// owns one gate for the lifetime of a run; the gate owns only the policy state,
// never the event emission (that stays in the orchestrator because it needs
// scanID, publish, and the event vocabulary).
type gate struct {
	mu sync.Mutex

	// scope decides which discovered names get expensive (paid) and active work.
	scope Scope

	// exclusions is the compiled hard traffic boundary derived from scope's domain
	// and IP exclusion lists. It is set once by setScope and read by the admission
	// gates. A nil value (no exclusions) excludes nothing.
	exclusions *scopecheck.Exclusions

	// paidUsed tracks how many paid calls each tool has made against the per-tool
	// budget cap. Key is tool name (e.g. "breach", "censys").
	paidUsed map[string]int

	// activeProbed tracks how many hosts the active sweep has probed against the
	// combined active-host budget cap.
	activeProbed int

	// toolUnavailable is the per-tool circuit breaker: once a paid provider reports
	// it cannot serve the scan (toolerr.ErrProviderUnavailable), its name maps to a
	// short reason and every later spawn is skipped. Guarded by mu.
	toolUnavailable map[string]string

	// scopeExcluded dedups the per-domain scope-exclusion audit event so only one
	// IssueObserved is emitted per out-of-scope domain.
	scopeExcluded map[string]bool

	// budgetReported dedups the per-tool and per-category (e.g. "active") budget
	// exhaustion event so only one IssueObserved fires per cap hit.
	budgetReported map[string]bool

	// providerProbeDecided dedups the per-IP provider-host policy decision event.
	providerProbeDecided map[string]bool

	// activeExcluded dedups the active-phase exclusion audit event so one
	// IssueObserved fires per (target kind, normalized target, matched rule).
	activeExcluded map[exclusionKey]bool

	// approvedDomains and approvedIPs are the authorization registry. A target
	// enters only after every applicable pre-traffic gate succeeds; discovery and
	// scan dedup maps deliberately have no authority here.
	approvedDomains map[string]targetApproval
	approvedIPs     map[string]targetApproval

	// rejectedRequests deduplicates request-time scope issues by normalized source
	// and destination host. Later enforcement steps emit the corresponding event.
	rejectedRequests map[requestPair]bool
}

// targetApproval records why a normalized target may receive active traffic.
type targetApproval struct {
	// depth is the DNS discovery depth. It is negative for IP targets.
	depth int
	// source names the scheduler or ownership policy that admitted the target.
	source string
}

// requestPair is the scan-wide dedup key for one rejected request relationship.
type requestPair struct {
	source      string
	destination string
}

// exclusionKey is the scan-wide dedup key for one hard-exclusion audit event. It
// distinguishes the target kind (domain or IP), the normalized target, and the
// canonical matched rule, so an IP and a name that share text, or two targets caught
// by different rules, each get their own audit line.
type exclusionKey struct {
	kind   string
	target string
	rule   string
}

// newGate creates a gate with empty counters and no scope set.
func newGate() gate {
	return gate{
		paidUsed:             make(map[string]int),
		toolUnavailable:      make(map[string]string),
		scopeExcluded:        make(map[string]bool),
		budgetReported:       make(map[string]bool),
		providerProbeDecided: make(map[string]bool),
		activeExcluded:       make(map[exclusionKey]bool),
		approvedDomains:      make(map[string]targetApproval),
		approvedIPs:          make(map[string]targetApproval),
		rejectedRequests:     make(map[requestPair]bool),
	}
}

// setScope configures the scope rules. Called once at Run start; not called
// concurrently with the gating methods.
func (g *gate) setScope(s Scope) {
	// Compile the exclusion matcher once, outside the lock. The lists were validated
	// when FromConfig built the run, so an error here can only come from direct
	// programmatic construction. New records the same compilation error in initErr so
	// production execution stops before traffic; keep an empty matcher here so tests
	// and diagnostic callers do not panic while inspecting the invalid scope.
	excl, err := s.Exclusions()
	if err != nil {
		excl, _ = scopecheck.NewExclusions(nil, nil)
	}
	g.mu.Lock()
	g.scope = s
	g.exclusions = excl
	g.mu.Unlock()
}

// excludedHost reports whether host - a DNS name or IP literal - is denied by a hard
// exclusion, with the canonical matched rule. It is the single question the active
// admission gates ask before trusting scope, approval, provider, or budget state.
func (g *gate) excludedHost(host string) (excluded bool, reason string) {
	g.mu.Lock()
	excl := g.exclusions
	g.mu.Unlock()
	return excl.HostExcluded(host)
}

// excludedAddr reports whether a resolved address is denied by a hard IP/CIDR
// exclusion, with the canonical matched prefix reason.
func (g *gate) excludedAddr(addr netip.Addr) (excluded bool, reason string) {
	g.mu.Lock()
	excl := g.exclusions
	g.mu.Unlock()
	return excl.AddrExcluded(addr)
}

// exclusionsSnapshot returns the compiled exclusion matcher for a tool that enforces
// the boundary at its own dial (the dnsinfo zone transfer resolves and filters
// nameserver addresses itself). The matcher is immutable after setScope, so the
// caller may retain it for the duration of one tool call.
func (g *gate) exclusionsSnapshot() *scopecheck.Exclusions {
	g.mu.Lock()
	excl := g.exclusions
	g.mu.Unlock()
	return excl
}

// recordActiveExclusion marks one (kind, target, rule) triple as audited and returns
// true only on its first occurrence, so the caller emits one IssueObserved per
// distinct exclusion decision.
func (g *gate) recordActiveExclusion(kind, target, rule string) (first bool) {
	key := exclusionKey{kind: kind, target: target, rule: rule}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.activeExcluded[key] {
		return false
	}
	g.activeExcluded[key] = true
	return true
}

// root returns the scope's root domain.
func (g *gate) root() string {
	g.mu.Lock()
	r := g.scope.Root
	g.mu.Unlock()
	return r
}

// scopeRef returns a snapshot of the Scope for read-only use. The caller must
// not mutate the returned value.
func (g *gate) scopeRef() Scope {
	g.mu.Lock()
	s := g.scope
	g.mu.Unlock()
	return s
}

// inScope reports whether domain at depth is in scope, delegating to Scope.InScope.
func (g *gate) inScope(domain string, depth int) (ok bool, reason string) {
	g.mu.Lock()
	s := g.scope
	g.mu.Unlock()
	return s.InScope(domain, depth)
}

// takePaidBudget reserves one paid call for tool against limit, returning false
// when the cap is reached. A limit of -1 means unlimited and 0 allows none. When the cap is hit
// for the first time, firstReport is true so the caller can emit one audit event.
func (g *gate) takePaidBudget(tool string, limit int) (allowed, firstReport bool) {
	if limit < 0 {
		return true, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paidUsed[tool] >= limit {
		first := !g.budgetReported[tool]
		g.budgetReported[tool] = true
		return false, first
	}
	g.paidUsed[tool]++
	return true, false
}

// takeActiveBudget reserves one host for the active sweep against limit,
// returning false when the cap is reached. A limit of -1 means unlimited and 0 allows none. When
// the cap is hit for the first time, firstReport is true.
func (g *gate) takeActiveBudget(limit int) (allowed, firstReport bool) {
	if limit < 0 {
		return true, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.activeProbed >= limit {
		first := !g.budgetReported["active"]
		g.budgetReported["active"] = true
		return false, first
	}
	g.activeProbed++
	return true, false
}

// toolIsUnavailable reports whether the circuit breaker has tripped for tool.
func (g *gate) toolIsUnavailable(tool string) bool {
	g.mu.Lock()
	_, tripped := g.toolUnavailable[tool]
	g.mu.Unlock()
	return tripped
}

// markToolUnavailable trips the circuit breaker for tool with the given reason.
// Returns true only on the first trip (so the caller emits one audit event).
func (g *gate) markToolUnavailable(tool, reason string) (firstTrip bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, seen := g.toolUnavailable[tool]; seen {
		return false
	}
	g.toolUnavailable[tool] = reason
	return true
}

// recordScopeExclusion marks domain as scope-excluded and returns true only on
// the first exclusion (so the caller emits one audit event per domain).
func (g *gate) recordScopeExclusion(domain string) (first bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.scopeExcluded[domain] {
		return false
	}
	g.scopeExcluded[domain] = true
	return true
}

// recordProviderProbeDecision marks ip as decided and returns true only on the
// first verdict, so the caller emits one audit event per IP.
func (g *gate) recordProviderProbeDecision(ip string) (first bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.providerProbeDecided[ip] {
		return false
	}
	g.providerProbeDecided[ip] = true
	return true
}

// approveDomain records a normalized DNS target after scope and budget admission.
func (g *gate) approveDomain(domain string, depth int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.approvedDomains[domain]; !exists {
		g.approvedDomains[domain] = targetApproval{depth: depth, source: "active domain scheduler"}
	}
}

// approveIP records a canonical IP target after ownership, dedup, and budget admission.
func (g *gate) approveIP(ip, source string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.approvedIPs[ip]; !exists {
		g.approvedIPs[ip] = targetApproval{depth: -1, source: source}
	}
}

// approvedDomain returns the admission record for a normalized DNS target.
func (g *gate) approvedDomain(domain string) (targetApproval, bool) {
	g.mu.Lock()
	approval, ok := g.approvedDomains[domain]
	g.mu.Unlock()
	return approval, ok
}

// approvedIP returns the admission record for a canonical IP target.
func (g *gate) approvedIP(ip string) (targetApproval, bool) {
	g.mu.Lock()
	approval, ok := g.approvedIPs[ip]
	g.mu.Unlock()
	return approval, ok
}

// recordRequestRejection returns true only for the first normalized source and
// destination pair in the scan.
func (g *gate) recordRequestRejection(source, destination string) (first bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	pair := requestPair{source: source, destination: destination}
	if g.rejectedRequests[pair] {
		return false
	}
	g.rejectedRequests[pair] = true
	return true
}
