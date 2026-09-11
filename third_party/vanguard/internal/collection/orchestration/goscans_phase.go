package orchestration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/portscan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/whois"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// sourceGoScansCoverage marks a gap in what the substage could assess at all (an
// approved host it cannot reach, or a run that ended degraded), kept apart from
// both the tool's own source and a tool failure. The substage's other issues file
// under sourceGoScans, the same label its translated observations carry, so an
// operator filtering the stream by source sees exactly what this tool did and did
// not do, separately from the port scanner that may have probed the same host.
const sourceGoScansCoverage = "goscans-coverage"

// sourceGoScansUnscoped marks what is neither a tool result nor a coverage gap: the
// operator turned pre-dial request authorization off for the substage's web modules,
// so the run could contact a destination before the scope could refuse it. Two kinds
// of issue file under it - the override itself, once per run, and each destination
// the modules reached that the request policy would have refused - so an audit finds
// every unscoped run and every host it touched by filtering the event stream, without
// reading issue text.
const sourceGoScansUnscoped = "goscans-unscoped"

// goscansPhase runs the terminal GoScans substage over the hosts the active
// schedulers already approved. It runs after the streaming active workers drain, for
// three reasons: it gets the complete passive host view, its child processes are gone
// before the run ends (the actor cleans up before Run returns), and its own nmap does
// not race the port scanner's.
//
// With GoScansDiscoveryFromPortScan the ordering is also a data dependency, not only
// a traffic one: the substage aims its scan at the ports the port scanner found, so
// it cannot start until that sweep has finished for the hosts it will assess.
//
// It is inert unless the active phase and the tool are both enabled. Every skip is
// audited: no approved hosts, an over-budget target, a tool that could not start,
// and a run that ended degraded each produce an info-level IssueObserved rather than
// an absence a reader could mistake for a clean result.
func (o *Orchestrator) goscansPhase(ctx context.Context) {
	if !o.cfg.EnableActive || !o.cfg.EnableGoScans {
		return
	}

	// Re-stamp the active phase and one per-run correlation id, so the tool's events
	// and anything derived from them share the audit join, exactly like the other
	// terminal stage.
	ctx = tooleventlog.WithScan(ctx, o.scanID, string(events.PhaseActive))
	corrID := newToolCorrID(o.scanID, sourceGoScans, o.gate.root())
	ctx = tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, o.gate.root()), corrID)

	targets := o.goscansPlan(ctx)
	if len(targets) == 0 {
		o.emitGoScansIssue(ctx, sourceGoScans, o.gate.root(),
			"goscans assessment skipped: no host was approved for the active sweep")
		return
	}

	// The actor gets its own copy of the run snapshot with the interceptor spliced in
	// front of the wired sink. Nothing else about the snapshot is derived from another
	// tool's state, so enabling or disabling any other tool cannot change what runs
	// here.
	cfg := o.cfg.GoScans
	o.applyGoScansWebPolicy(ctx, &cfg)
	intercept := &goscansInterceptor{
		o:    o,
		ctx:  ctx,
		next: cfg.Sink,
		in:   o.goscansTranslateInput(corrID),
		web:  cfg.Modules.WebCrawl || cfg.Modules.WebEnum,
	}
	cfg.Sink = intercept

	build := o.cfg.GoScansBuilder
	if build == nil {
		build = newGoScansActor
	}
	runner, err := build(cfg, targets)
	if err != nil {
		o.emitGoScansIssue(ctx, sourceCircuitBreaker, o.gate.root(),
			fmt.Sprintf("goscans could not start: %v; the substage assessed %d approved host(s) not at all", err, len(targets)))
		return
	}

	// The tool's own deadline is applied here rather than inside the actor: it is a
	// stage-level policy, and expiring it has to become a recorded coverage gap,
	// which is this layer's job. The actor drains what it has in flight before
	// returning, so the bound is when new work stops, not when the process does.
	//
	// An unset bound means unbounded, never "already expired". The configuration
	// layer requires a positive timeout, so a zero here comes from a snapshot built
	// in code, and reading it as an instant deadline would silently skip the whole
	// stage while reporting a coverage gap that the operator never asked for.
	runCtx, cancel := ctx, context.CancelFunc(func() {})
	if o.cfg.GoScansTimeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, o.cfg.GoScansTimeout)
	}
	defer cancel()

	runErr := runner.Run(runCtx)
	o.reportGoScansOutcome(ctx, intercept.result(), len(targets), runErr, runCtx.Err())
}

// applyGoScansWebPolicy decides whether the upstream web modules may run and
// records that decision. The two modules are the one HTTP path in the scan whose
// destinations cannot be authorized before the dial: upstream owns the redirect and
// link following, and third-party vendor code is not modified.
//
// The default clears them and records the lost application coverage, so a thin web
// result is never read as an estate with nothing to crawl. With
// GoScansIgnoreHTTPScope the operator has explicitly traded the pre-dial guarantee
// for the crawler's reach: the modules run, the actor is told to accept them, and
// the override is stated once for the run. The boundary is then applied to what came
// back rather than to what was about to be sent - see
// [goscansInterceptor.markWebScope] - so an endpoint the policy would have allowed
// stays ordinary evidence and only a destination it would have refused is marked
// unscoped and reported.
func (o *Orchestrator) applyGoScansWebPolicy(ctx context.Context, cfg *goscans.Config) {
	if !cfg.Modules.WebCrawl && !cfg.Modules.WebEnum {
		return
	}
	// A hard exclusion cannot be relaxed by the out-of-scope HTTP override. Until the
	// upstream webcrawler and webenum modules gain a pre-dial exclusion boundary, they
	// have no way to refuse an excluded destination a crawl leads to, so they are
	// withheld outright whenever any explicit exclusion is set - even with
	// tools.goscans.ignore_http_scope enabled. The restriction is recorded as a
	// coverage gap; see the scope-safe crawler backlog item.
	if !o.gate.exclusionsSnapshot().Empty() {
		cfg.Modules.WebCrawl = false
		cfg.Modules.WebEnum = false
		o.emitGoScansIssue(ctx, sourceGoScansCoverage, o.gate.root(),
			"goscans webcrawler and webenum disabled: engagement exclusions are set and these modules have no pre-dial exclusion boundary, so they are withheld even when tools.goscans.ignore_http_scope is enabled (temporary; pending scope-safe crawler coverage)")
		return
	}
	if !o.cfg.GoScansIgnoreHTTPScope {
		cfg.Modules.WebCrawl = false
		cfg.Modules.WebEnum = false
		o.emitGoScansIssue(ctx, sourceGoScansCoverage, o.gate.root(),
			"goscans webcrawler and webenum disabled: upstream owns an internal redirect loop that cannot enforce engagement scope, and third-party vendor code is not modified")
		return
	}
	cfg.AllowUnscopedWebModules = true
	o.emitGoScansIssueAt(ctx, sourceGoScansUnscoped, o.gate.root(), events.SeverityMedium,
		fmt.Sprintf("goscans %s running with pre-dial request authorization disabled by configuration (tools.goscans.ignore_http_scope): upstream follows redirects and links itself, so a destination outside the engagement scope can be contacted before it can be refused; the scope is applied to each result instead, and any endpoint it would have refused is reported and marked unscoped",
			goscansWebModuleList(cfg.Modules)))
}

// goscansWebModuleList names the web modules the override actually enabled, so the
// audit issue states what ran rather than both names regardless.
func goscansWebModuleList(m goscans.Modules) string {
	switch {
	case m.WebCrawl && m.WebEnum:
		return "webcrawler and webenum"
	case m.WebCrawl:
		return "webcrawler"
	default:
		return "webenum"
	}
}

// newGoScansActor is the default builder: it constructs the real, isolated actor.
// The actor validates its configuration and its whole target list here, before the
// first packet, so a bad snapshot fails the stage instead of half a scan.
func newGoScansActor(cfg goscans.Config, targets []goscans.Target) (GoScansRunner, error) {
	return goscans.New(cfg, targets)
}

// goscansPlan builds the deterministic target snapshot: every approved host, in
// canonical address order, capped by GoScansMaxTargets, each carrying the in-scope
// passive names that resolve to it. The order and the cap are computed from the
// collected set rather than from arrival order, so the same passive input always
// produces the same plan.
func (o *Orchestrator) goscansPlan(ctx context.Context) []goscans.Target {
	ips := o.seeds.goscansTargetIPs()
	sortTargetIPs(ips)

	// Recheck every candidate address against the hard IP/CIDR exclusions before the
	// actor is built or any subprocess is spawned. The scheduler already refuses an
	// excluded address, so this is the second, independent check that keeps an
	// excluded IP out of a GoScans command argument whatever admitted it.
	ips = o.filterExcludedGoScansIPs(ctx, ips)

	if limit := o.cfg.GoScansMaxTargets; limit > 0 && len(ips) > limit {
		for _, skipped := range ips[limit:] {
			o.emitGoScansIssue(ctx, sourceBudget, skipped,
				fmt.Sprintf("goscans target %s skipped: max_targets budget of %d reached", skipped, limit))
		}
		ips = ips[:limit]
	}

	order := o.goscansDomainOrder()
	targets := make([]goscans.Target, 0, len(ips))
	for _, ip := range ips {
		targets = append(targets, goscans.Target{
			IP:          ip,
			Vhosts:      o.goscansVhosts(ip),
			DomainOrder: order,
			Ports:       o.seeds.goscansPortsFor(ip),
		})
	}
	return targets
}

// filterExcludedGoScansIPs drops every address matching a hard IP/CIDR exclusion,
// emitting one active-phase exclusion audit per dropped address (deduped with the
// scheduler's own), and returns the allowed addresses in the same order.
func (o *Orchestrator) filterExcludedGoScansIPs(ctx context.Context, ips []string) []string {
	allowed := make([]string, 0, len(ips))
	for _, ip := range ips {
		if addr, err := netip.ParseAddr(ip); err == nil {
			if excluded, reason := o.gate.excludedAddr(addr); excluded {
				o.emitActiveExclusion(ctx, events.ActiveTargetIP, addr.Unmap().String(), reason)
				continue
			}
		}
		allowed = append(allowed, ip)
	}
	return allowed
}

// captureGoScansTarget records an approved host for the terminal substage. It is
// called from the host scheduler once the IP has passed every existing gate (scope,
// provider-only, dedup, active-host budget), so the substage inherits those
// decisions instead of re-deriving them, and costs no second budget unit: the budget
// guards targets, not the number of implementations probing one target.
//
// It is deliberately independent of whether the port scanner ran. A GoScans-only
// configuration approves and assesses hosts exactly as a combined one does.
func (o *Orchestrator) captureGoScansTarget(ctx context.Context, ip, causationID string) {
	if !o.cfg.EnableGoScans {
		return
	}
	// An IPv6-only host is unreachable from an IPv4-only scanner: discovery would
	// report an empty host, indistinguishable from one with nothing open. Record the
	// gap under this tool's own source and do not capture the target - a coverage
	// gap is only honest if it names the tool that did not run.
	if isIPv6(ip) && !o.ipv6Usable {
		o.emitCoverageIssue(ctx, sourceGoScansCoverage, ip,
			fmt.Sprintf("%s is IPv6-only and the scanner has no IPv6 route; goscans assessment skipped (coverage gap, not a clean result)", ip))
		return
	}

	o.seeds.captureGoScansTarget(ip, causationID)
}

// recordGoScansHostName records that name resolves to ip, building the virtual-host
// candidates the substage passes to its TLS and web modules. The source is ordinary
// passive inventory only: no other active tool's output may add, remove, or
// reprioritize a name here, which is what keeps the two tools' results independent
// enough to corroborate each other.
//
// It is a no-op unless the substage is enabled, so a scan that never runs it does
// not carry the map.
func (o *Orchestrator) recordGoScansHostName(ip, name string) {
	if !o.cfg.EnableGoScans || ip == "" || name == "" {
		return
	}
	o.seeds.recordGoScansHostName(ip, name)
}

// goscansVhosts returns the in-scope passive names recorded for ip, sorted. The
// scope policy is re-applied here rather than trusted from collection time, because
// a name can be recorded against an IP before its crawl depth is known. The actor
// lowercases, deduplicates, and applies the per-host virtual-host cap itself, so
// this does not repeat that work.
func (o *Orchestrator) goscansVhosts(ip string) []string {
	candidates := o.seeds.goscansHostNamesFor(ip)
	names := make([]string, 0, len(candidates))
	for _, name := range candidates {
		depth, _ := o.targets.depth(name)
		if ok, _ := o.gate.inScope(name, depth); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// goscansDomainOrder ranks domain suffixes by plausibility for the discovery
// module's DNS-name choice: upstream matches a discovered name against these
// suffixes in order and keeps the earliest match, so a name under the scanned root
// wins over an unrelated reverse-DNS name the hosting provider happens to publish.
func (o *Orchestrator) goscansDomainOrder() []string {
	root := o.gate.root()
	if root == "" {
		return nil
	}
	order := []string{root}
	if apex := whois.RegistrableApex(root); apex != "" && apex != root {
		order = append(order, apex)
	}
	return order
}

// sortTargetIPs orders addresses canonically: numerically, IPv4 before IPv6. The cap
// selects a prefix of this order, so which hosts are dropped depends on the address
// set alone and not on the order discovery happened to produce it in. An address
// that does not parse (which the schedulers should never admit) sorts last by text
// rather than being silently reordered.
func sortTargetIPs(ips []string) {
	parsed := make(map[string]netip.Addr, len(ips))
	for _, ip := range ips {
		if addr, err := netip.ParseAddr(ip); err == nil {
			parsed[ip] = addr
		}
	}
	sort.Slice(ips, func(i, j int) bool {
		a, aok := parsed[ips[i]]
		b, bok := parsed[ips[j]]
		if aok && bok {
			return a.Compare(b) < 0
		}
		if aok != bok {
			return aok
		}
		return ips[i] < ips[j]
	})
}

// goscansInterceptor sits between the isolated actor and the orchestrator. It does
// three independent things with every tool event, in order: forwards it to the
// wired sink so the per-tool log and the canonical tool-event stream stay the
// record of what the tool did; translates the result-bearing ones into domain
// observations; and keeps the terminal run summary, which is the only channel the
// actor has for reporting its own totals.
//
// The actor knows nothing of this. It emits tool events into a sink, exactly as it
// would with no orchestrator present, and the orchestrator remains the single
// translator from tool vocabulary to domain vocabulary.
type goscansInterceptor struct {
	o    *Orchestrator
	ctx  context.Context
	next tooleventlog.EventSink
	in   translate.GoScansInput
	mu   sync.Mutex
	// summary is the actor's terminal ScanCompleted, absent when the actor never got
	// far enough to emit one.
	summary *goscans.ScanCompleted
	// web reports whether the unauthorized web modules were admitted for this run,
	// which is the only case where an observation can need the post-hoc scope check.
	web bool
	// unscopedHosts deduplicates the operator issue for a destination the web modules
	// contacted outside the engagement scope, one per normalized host per run.
	unscopedHosts map[string]bool
}

// Emit persists the event, then publishes whatever domain observations it carries.
// Persistence happens first: an observation that was not written must not be
// treated as recorded.
//
// The actor's own context is used for persistence (it carries the module's target)
// while the domain events are published on the stage context, which is what carries
// the substage's scan and correlation identity.
func (i *goscansInterceptor) Emit(ctx context.Context, e tooleventlog.Event) {
	if i.next != nil {
		i.next.Emit(ctx, e)
	}
	if done, ok := e.(goscans.ScanCompleted); ok {
		i.mu.Lock()
		i.summary = &done
		i.mu.Unlock()
	}

	tool, ok := e.(goscans.Event)
	if !ok {
		return
	}
	translated := i.o.goscansInScope(translate.GoScansEvent(tool, i.in))
	i.markWebScope(translated)
	i.o.publish(i.ctx, translated)
}

// markWebScope applies the engagement boundary to what the upstream web modules
// already fetched. Their requester dials before Vanguard can authorize anything, so
// the check runs on the answer instead of on the request: an endpoint whose host
// would have passed the request policy is ordinary evidence and is left alone, and
// only a host that would have been refused is stamped unscoped and reported once.
//
// Endpoints are the only observations marked. They are what the modules requested;
// a name a crawl merely learned about is not traffic, and the scope filter above has
// already dropped the out-of-scope ones from the asset graph.
func (i *goscansInterceptor) markWebScope(evts []events.DomainEvent) {
	if !i.web {
		return
	}
	for idx, e := range evts {
		ep, ok := e.(events.HttpEndpointDiscovered)
		if !ok {
			continue
		}
		host, inScope, reason := i.o.goscansWebScope(ep.URL)
		if inScope {
			continue
		}
		ep.UnscopedRequest = true
		evts[idx] = ep
		i.reportUnscopedDestination(host, reason)
	}
}

// reportUnscopedDestination records one out-of-scope destination the web modules
// contacted, once per host for the run. The dedup is per interceptor, which is per
// substage run, so a crawl that walks fifty paths on one out-of-scope host produces
// one operator issue rather than fifty.
func (i *goscansInterceptor) reportUnscopedDestination(host, reason string) {
	i.mu.Lock()
	if i.unscopedHosts == nil {
		i.unscopedHosts = make(map[string]bool)
	}
	first := !i.unscopedHosts[host]
	i.unscopedHosts[host] = true
	i.mu.Unlock()
	if !first {
		return
	}
	i.o.emitGoScansIssueAt(i.ctx, sourceGoScansUnscoped, host, events.SeverityMedium,
		fmt.Sprintf("goscans web module contacted %s, which the request policy would have refused (%s); the module dials before the destination can be authorized, so the traffic was already sent and every observation of this host is marked unscoped",
			host, reason))
}

// goscansWebScope answers, after the fact, whether a URL the web modules fetched
// would have been allowed had the request been authorizable. It restates
// allowRequest for a destination whose request context is long gone: an IP literal
// must be an approved target, a DNS name the scan already knows is judged at its
// recorded discovery depth, and a name it had not seen is judged at
// ipOriginDerivedDepth, because a crawl reaches a new name from the approved address
// it was aimed at. It returns the normalized host so a caller can report and
// deduplicate on the same key the policy decided on.
func (o *Orchestrator) goscansWebScope(rawURL string) (host string, inScope bool, reason string) {
	normalized, err := scopecheck.NormalizeURL(rawURL)
	if err != nil {
		return rawURL, false, fmt.Sprintf("invalid request URL: %v", err)
	}
	// A hard exclusion wins over the out-of-scope HTTP override: a URL the web modules
	// fetched that names an excluded host is reported unscoped regardless of the
	// approval registries, so the override can tolerate unknown destinations but never
	// a named exclusion.
	if excluded, reason := o.gate.excludedHost(normalized); excluded {
		return normalized, false, reason
	}
	if ip, err := netip.ParseAddr(normalized); err == nil {
		if _, approved := o.gate.approvedIP(ip.Unmap().String()); approved {
			return normalized, true, ""
		}
		return normalized, false, reasonIPNotApproved
	}
	depth, known := o.targets.depth(normalized)
	if !known {
		depth = ipOriginDerivedDepth
	}
	ok, why := o.gate.inScope(normalized, depth)
	return normalized, ok, why
}

// goscansTranslateInput snapshots the identity every translated observation is
// stamped with, including the per-IP causation so an observation about a host
// threads back to the discovery that introduced it.
func (o *Orchestrator) goscansTranslateInput(corrID string) translate.GoScansInput {
	causation := o.seeds.goscansCausation()
	for ip, id := range causation {
		if id == "" {
			causation[ip] = o.targets.ipEventID(ip)
		}
	}
	return translate.GoScansInput{
		ScanID:    o.scanID,
		Root:      o.gate.root(),
		CorrID:    corrID,
		Causation: causation,
	}
}

// goscansInScope drops the discovered names the scan policy excludes. A name this
// tool found on a live reply is still a name, but the scope decides which names the
// run is allowed to record as assets, and that decision belongs to the orchestrator
// rather than to a pure translator. Everything that is not a name passes through.
func (o *Orchestrator) goscansInScope(evts []events.DomainEvent) []events.DomainEvent {
	out := evts[:0]
	for _, e := range evts {
		d, ok := e.(events.DnsDomainNameDiscovered)
		if !ok {
			out = append(out, e)
			continue
		}
		depth, _ := o.targets.depth(d.Domain)
		if ok, _ := o.gate.inScope(d.Domain, depth); ok {
			out = append(out, e)
		}
	}
	return out
}

// result returns the recorded run summary, or nil when the actor emitted none.
func (i *goscansInterceptor) result() *goscans.ScanCompleted {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.summary
}

// reportGoScansOutcome records the substage's outcome in the domain stream. A run
// that failed, was cancelled, or completed with failed jobs is stated as such, so a
// thin result is never read as an honest empty one. A clean run adds nothing: its
// observations are the report.
func (o *Orchestrator) reportGoScansOutcome(ctx context.Context, summary *goscans.ScanCompleted, planned int, runErr, deadlineErr error) {
	// A run cut short by the tool's own deadline is reported before anything else,
	// because the operator needs to know the bound bit rather than read a short
	// result as the estate's answer. It is separated from an outer cancellation: the
	// scan was not stopped, this tool ran out of the time it was given.
	if errors.Is(deadlineErr, context.DeadlineExceeded) {
		assessed := 0
		if summary != nil {
			assessed = summary.Targets
		}
		o.emitGoScansIssue(ctx, sourceGoScansCoverage, o.gate.root(),
			fmt.Sprintf("goscans hit its configured timeout of %s with %d of %d approved host(s) assessed; "+
				"the rest went unassessed, which is a coverage gap rather than a clean result",
				o.cfg.GoScansTimeout, assessed, planned))
		return
	}
	if runErr != nil {
		o.emitGoScansIssue(ctx, sourceGoScans, o.gate.root(),
			fmt.Sprintf("goscans assessment of %d approved host(s) did not complete: %v", planned, runErr))
		return
	}
	if summary == nil {
		o.emitGoScansIssue(ctx, sourceGoScans, o.gate.root(),
			fmt.Sprintf("goscans assessment of %d approved host(s) reported no run summary; treat its results as incomplete", planned))
		return
	}
	if !summary.Degraded {
		return
	}
	o.emitGoScansIssue(ctx, sourceGoScansCoverage, o.gate.root(),
		fmt.Sprintf("goscans completed degraded over %d target(s): %d job(s) failed and %d were skipped, so its coverage of those hosts is partial",
			summary.Targets, summary.Failed, summary.Skipped))
}

// emitGoScansIssue records a substage decision as an info-level, active-phase
// IssueObserved, reusing the issue vocabulary rather than inventing a parallel skip
// event, exactly as the detection stage does.
func (o *Orchestrator) emitGoScansIssue(ctx context.Context, source, query, msg string) {
	o.emitGoScansIssueAt(ctx, source, query, events.SeverityInfo, msg)
}

// emitGoScansIssueAt is emitGoScansIssue with an explicit severity, for the one
// decision that is not an informational skip: running the web modules without
// request authorization is a property of the engagement, not a coverage note.
func (o *Orchestrator) emitGoScansIssueAt(ctx context.Context, source, query string, severity events.Severity, msg string) {
	at := time.Now()
	issue := events.IssueObserved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			Source:          source,
			Phase:           events.PhaseActive,
			Category:        events.CategoryIssue,
			Severity:        severity,
			ObservationKind: events.ObservationKindOperational,
			CapturedAt:      at,
		},
		Query: query,
		Error: msg,
	}
	issue.EventID = events.NewEventID(at, issue)
	o.publish(ctx, []events.DomainEvent{issue})
}

// recordGoScansPorts records the TCP ports the port scanner found open on ip, so
// the terminal substage can aim its own scan at them instead of sweeping the host a
// second time.
//
// It is called only on the path where the sweep produced a definitive answer. A
// host that errored, or that answered no probe at all, never reaches here and so
// stays absent from the map, which the substage reads as "sweep this one yourself".
// Recording an empty set for such a host would turn a coverage gap into a confident
// claim that nothing is open.
func (o *Orchestrator) recordGoScansPorts(ip string, open []portscan.OpenPort) {
	if !o.cfg.EnableGoScans || !o.cfg.GoScansDiscoveryFromPortScan || ip == "" {
		return
	}
	ports := make([]int, 0, len(open))
	for i := range open {
		ports = append(ports, open[i].Port)
	}
	o.seeds.recordGoScansPorts(ip, ports)
}
