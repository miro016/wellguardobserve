package goscans

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/plan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/preflight"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/probes"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/upstream"
)

// Phase names used on cancellation events, and the status used when a module
// broke its contract by returning nothing at all.
const (
	phaseDiscovery = "discovery"
	phaseJobs      = "subordinate jobs"
	phaseTargets   = "target loop"
	statusNoResult = "upstream returned no result"
)

// Actor runs the GoScans pipeline over a fixed, scope-approved target list. One
// Actor owns one run: it creates its own temporary tree, drives every upstream
// module, and reports everything it learns as events. Nothing is readable
// afterwards, and nothing is shared with another Vanguard tool.
type Actor struct {
	cfg     Config
	targets []Target
	up      upstream.Upstream
	sel     plan.Selector
	// workers is the subordinate job parallelism within one target.
	workers int
	// jobSlots is the tool-wide job ceiling, held for the lifetime of one job. It is
	// a field rather than a local because targets run concurrently and the ceiling
	// has to be the same one for all of them: a per-target pool would multiply by
	// the number of targets in flight and quietly exceed the configured bound.
	jobSlots chan struct{}

	// tempRoot is the actor-owned temporary directory, created in Run and removed
	// before Run returns, on every path including cancellation.
	tempRoot string
	// probesFile is the materialized enumeration probe set, inside tempRoot.
	probesFile string
}

// counters aggregates job outcomes across concurrent workers, and the highest
// number of jobs ever in flight at once. The peak is reported next to the planned
// pool size so an operator can confirm the traffic bound the configuration promised
// is the bound the run actually observed.
type counters struct {
	succeeded atomic.Int64
	failed    atomic.Int64
	skipped   atomic.Int64
	inFlight  atomic.Int64
	peak      atomic.Int64
}

// enter records one job starting and raises the peak when this is a new high.
func (c *counters) enter() {
	now := c.inFlight.Add(1)
	for {
		peak := c.peak.Load()
		if now <= peak || c.peak.CompareAndSwap(peak, now) {
			return
		}
	}
}

// leave records one job finishing.
func (c *counters) leave() { c.inFlight.Add(-1) }

// New validates the configuration and the target list and returns a ready Actor.
// Validation happens here, before any network operation, because a scan that
// discovers a bad timeout or a missing interpreter halfway through has already
// spent traffic against real hosts.
//
// Targets are normalized and sorted by address, and duplicates are dropped, so the
// same passive inventory always yields the same plan and the same event order.
func New(cfg Config, targets []Target) (*Actor, error) {
	if err := cfg.validate(); err != nil {
		emitTo(cfg.Sink, InvalidInput{Field: "Config", Err: err})
		return nil, err
	}
	if err := validateTargets(targets); err != nil {
		emitTo(cfg.Sink, InvalidInput{Field: "Targets", Err: err})
		return nil, err
	}

	normalized := make([]Target, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		n := t.normalize(cfg.Limits.MaxVhosts)
		if _, dup := seen[n.IP]; dup {
			continue
		}
		seen[n.IP] = struct{}{}
		normalized = append(normalized, n)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].IP < normalized[j].IP })

	up := cfg.Upstream
	if up == nil {
		up = upstream.New()
	}

	// A host is never probed harder than the per-host cap, and never harder than the
	// tool-wide one either, so a per-host cap above it cannot bind.
	workers := min(cfg.MaxConcurrencyPerHost, cfg.MaxConcurrency)

	return &Actor{
		cfg:      cfg,
		targets:  normalized,
		up:       up,
		sel:      plan.NewSelector(cfg.selectorOptions()),
		workers:  workers,
		jobSlots: make(chan struct{}, cfg.MaxConcurrency),
	}, nil
}

// Run drives the whole pipeline and returns when every target is done, the context
// ends, or setup fails. Results leave only as events; the returned error says
// whether the run completed, not what it found.
//
// Cancellation is honored between targets, between jobs, and inside every module
// that upstream gave a context. Discovery and banner collection have no context
// upstream, so a cancellation that arrives while one of them is running is
// recorded and then waited out: draining an nmap or banner probe is slower than
// abandoning it, but abandoning it would leave a live child process behind.
func (a *Actor) Run(ctx context.Context) (err error) {
	started := time.Now()

	root, ferr := os.MkdirTemp(a.cfg.TempRoot, "vanguard-goscans-*")
	if ferr != nil {
		wrapped := fmt.Errorf("goscans: create temporary root: %w", ferr)
		a.emit(ctx, FilesystemError{Op: "create temp root", Path: a.cfg.TempRoot, Err: ferr})
		return wrapped
	}
	a.tempRoot = root
	defer func() { err = errors.Join(err, a.cleanup(ctx)) }()

	if a.cfg.Modules.WebEnum {
		path, perr := probes.Write(a.tempRoot)
		if perr != nil {
			a.emit(ctx, FilesystemError{Op: "write probe set", Path: a.tempRoot, Err: perr})
			return fmt.Errorf("goscans: materialize probe set: %w", perr)
		}
		a.probesFile = path
	}

	a.emit(ctx, ScanStarted{
		Targets:        len(a.targets),
		Modules:        a.cfg.Modules.Names(),
		Workers:        cap(a.jobSlots),
		ProbeSetDigest: a.probeDigestForRun(),
		Runtime:        a.cfg.Runtime,
		Library:        preflight.GoScansVersion,
	})

	var totals counters
	var hostCount, jobCount atomic.Int64
	var runErr error

	// Targets are independent, so they overlap up to the configured bound. Starting
	// order stays the address order the snapshot fixed; completion order does not,
	// which is why nothing downstream may depend on the order events arrive in
	// across targets.
	slots := make(chan struct{}, a.cfg.MaxParallelTargets)
	var wg sync.WaitGroup
dispatch:
	for _, t := range a.targets {
		// Checked before the acquire rather than only as a select case: a select with
		// a free slot and a cancelled context has two ready cases and would pick
		// between them at random, so an already-cancelled run could still dispatch.
		if ctx.Err() != nil {
			a.emit(ctx, Cancelled{Phase: phaseTargets, IP: t.IP, Err: ctx.Err()})
			runErr = ctx.Err()
			break
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			a.emit(ctx, Cancelled{Phase: phaseTargets, IP: t.IP, Err: ctx.Err()})
			runErr = ctx.Err()
			break dispatch
		}
		// Emitted here rather than inside the goroutine so the start of a target is
		// still a fact about this loop: TargetStarted keeps the snapshot's address
		// order even when the work behind it overlaps. TargetCompleted does not, and
		// cannot, because completion order is whatever the hosts decide.
		a.emit(ctx, TargetStarted{IP: t.IP, Vhosts: len(t.Vhosts)})

		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			defer func() { <-slots }()
			h, j := a.runTarget(ctx, t, &totals)
			hostCount.Add(int64(h))
			jobCount.Add(int64(j))
		}(t)
	}
	// In-flight targets are always waited out, on cancellation too: each one may
	// hold a live nmap or SSLyze child process, and returning without it would leave
	// that process behind and race the temporary directory this run is about to
	// remove.
	wg.Wait()

	hosts, jobs := int(hostCount.Load()), int(jobCount.Load())
	failed := int(totals.failed.Load())
	a.emit(ctx, ScanCompleted{
		Targets:   len(a.targets),
		Hosts:     hosts,
		Jobs:      jobs,
		Succeeded: int(totals.succeeded.Load()),
		Failed:    failed,
		Skipped:   int(totals.skipped.Load()),
		Workers:   cap(a.jobSlots),
		Peak:      int(totals.peak.Load()),
		Degraded:  runErr != nil || failed > 0,
		Duration:  time.Since(started),
	})

	return runErr
}

// probeDigestForRun returns the embedded probe set digest when enumeration runs,
// so a replay can tell which probe set produced the hits.
func (a *Actor) probeDigestForRun() string {
	if !a.cfg.Modules.WebEnum {
		return ""
	}
	return probes.Digest()
}

// runTarget runs discovery for one target and then its subordinate jobs. It
// returns the number of hosts discovery reported and the number of jobs scheduled.
func (a *Actor) runTarget(ctx context.Context, t Target, totals *counters) (hosts, scheduled int) {
	started := time.Now()

	result, ok := a.runDiscovery(ctx, t)
	if !ok {
		totals.failed.Add(1)
		a.emit(ctx, TargetCompleted{IP: t.IP, Duration: time.Since(started)})
		return 0, 0
	}

	hosts = len(result.Data)
	if hosts == 0 {
		a.emit(ctx, DiscoveryEmpty{IP: t.IP, Status: result.Status})
		a.emit(ctx, TargetCompleted{IP: t.IP, Duration: time.Since(started)})
		return 0, 0
	}

	var jobs []plan.Job
	var skips []plan.Skip
	services := 0
	scripts := 0

	for _, host := range result.Data {
		if host == nil {
			continue
		}
		ip := host.Ip
		if ip == "" {
			ip = t.IP
		}
		sorted := plan.SortServices(host.Services)
		services += len(sorted)
		a.emitHostProfile(ctx, ip, host)
		scripts += a.emitScripts(ctx, ip, host.Scripts)
		a.emitServices(ctx, ip, sorted)

		hostJobs, hostSkips := a.sel.Services(sorted, ip, t.Vhosts)
		jobs = append(jobs, hostJobs...)
		skips = append(skips, hostSkips...)
	}

	a.emit(ctx, DiscoveryCompleted{
		IP:       t.IP,
		Hosts:    hosts,
		Services: services,
		Scripts:  scripts,
		Status:   result.Status,
		Duration: time.Since(started),
	})

	plan.SortSkips(skips)
	for _, s := range skips {
		a.emit(ctx, JobSkipped{IP: s.IP, Port: s.Port, Protocol: s.Protocol, Module: s.Module.String(),
			Reason: s.Reason, Eligible: s.Reason == plan.ReasonServiceCap})
	}
	totals.skipped.Add(int64(len(skips)))

	plan.SortJobs(jobs)
	succeeded, failed := a.runJobs(ctx, jobs, totals)
	totals.succeeded.Add(int64(succeeded))
	totals.failed.Add(int64(failed))

	a.emit(ctx, TargetCompleted{
		IP:        t.IP,
		Attempted: len(jobs),
		Succeeded: succeeded,
		Failed:    failed,
		Skipped:   len(skips),
		Partial:   succeeded > 0 && failed > 0,
		Duration:  time.Since(started),
	})

	return hosts, len(jobs)
}

// runDiscovery builds and runs one discovery scan. It reports false when the
// target produced no usable result, in which case no subordinate work may run:
// discovery is the only permitted input to the other modules.
func (a *Actor) runDiscovery(ctx context.Context, t Target) (*upstream.DiscoveryResult, bool) {
	timeout := remaining(ctx, a.cfg.DiscoveryTimeout)
	if timeout <= 0 {
		a.emit(ctx, ModuleTimeout{Module: plan.Discovery.String(), IP: t.IP, Timeout: a.cfg.DiscoveryTimeout})
		return nil, false
	}

	args, scoped := discoveryArgs(a.cfg.NmapArgs, t.Ports)
	a.emit(ctx, DiscoveryScope{IP: t.IP, Ports: len(t.Ports), Scoped: scoped})

	log := upstreamLogger{actor: a, ctx: ctx, module: plan.Discovery, ip: t.IP}
	runner, err := a.up.Discovery(log, upstream.DiscoveryRequest{
		Targets:     []string{t.IP},
		NmapPath:    a.cfg.NmapPath,
		NmapArgs:    args,
		DomainOrder: t.DomainOrder,
		DialTimeout: a.cfg.DiscoveryDialTimeout,
	})
	if err != nil {
		a.emit(ctx, ModuleSetupFailed{Module: plan.Discovery.String(), IP: t.IP, Err: err})
		return nil, false
	}

	// Discovery has no context setter, so the only bound is this timeout. On
	// cancellation the goroutine is drained rather than abandoned: it holds a live
	// nmap child process, and returning without it would orphan that process.
	done := make(chan *upstream.DiscoveryResult, 1)
	go func() { done <- runner.Run(timeout) }()

	select {
	case result := <-done:
		return a.checkDiscoveryResult(ctx, t, result)
	case <-ctx.Done():
		a.emit(ctx, Cancelled{Phase: phaseDiscovery, IP: t.IP, Draining: true, Err: ctx.Err()})
		<-done
		return nil, false
	}
}

// checkDiscoveryResult rejects an unusable discovery outcome and emits why.
func (a *Actor) checkDiscoveryResult(ctx context.Context, t Target, result *upstream.DiscoveryResult) (*upstream.DiscoveryResult, bool) {
	if result == nil {
		a.failMissing(ctx, plan.Discovery, t.IP, 0)
		return nil, false
	}
	if result.Exception {
		a.failException(ctx, plan.Discovery, t.IP, 0, result.Status)
		return nil, false
	}
	return result, true
}

// emitServices reports the discovered services, capped at the per-host limit. The
// services beyond the cap are recorded as skips by the planner, so the cap is
// visible in the stream rather than silently applied.
func (a *Actor) emitServices(ctx context.Context, ip string, services []upstream.DiscoveryService) {
	for i, svc := range services {
		if i >= a.cfg.Limits.MaxServicesPerHost {
			return
		}
		cpes := append([]string(nil), svc.Cpes...)
		sort.Strings(cpes)
		a.emit(ctx, ServiceDiscovered{
			IP:         ip,
			Port:       svc.Port,
			Protocol:   svc.Protocol,
			Name:       svc.Name,
			Tunnel:     svc.Tunnel,
			Product:    svc.Product,
			Version:    svc.Version,
			ExtraInfo:  svc.Info,
			CPEs:       dedupSorted(cpes),
			Method:     svc.Method,
			DeviceType: svc.DeviceType,
			Flavor:     svc.Flavor,
			TTL:        svc.Ttl,
		})
	}
}

// emitHostProfile reports the host-level evidence discovery gathered beside the
// service list. It is emitted even when every field is empty, because "discovery
// reported this host and learned nothing more about it" is itself the observation
// a later scan is compared against.
//
// The upstream host struct also carries asset-inventory annotations (company,
// department, owner, criticality), Active Directory enrichment, and privileged
// user lists. None of them are read here: the first four are fields an operating
// agent fills in, and the rest require the credentialed enrichment this
// integration never enables, so they are always empty by construction.
func (a *Actor) emitHostProfile(ctx context.Context, ip string, host *upstream.DiscoveryHost) {
	limit := a.cfg.Limits.MaxVhosts

	dnsName := strings.ToLower(strings.TrimSpace(host.DnsName))

	names := append([]string(nil), host.OtherNames...)
	for i := range names {
		names[i] = strings.ToLower(strings.TrimSpace(names[i]))
	}
	sort.Strings(names)
	names = dedupSorted(names)

	// Upstream can report a name it generated rather than observed. Judge that
	// against everything this host answered with, because the generated label and
	// the name it was derived from can arrive in either field.
	reported := make(map[string]bool, len(names)+1)
	for _, n := range names {
		reported[n] = true
	}
	if dnsName != "" {
		reported[dnsName] = true
	}
	kept := names[:0]
	for _, n := range names {
		if isWildcardSample(n, reported) {
			continue
		}
		kept = append(kept, n)
	}
	if isWildcardSample(dnsName, reported) {
		dnsName = ""
	}
	names, nameTrunc := capStrings(kept, limit)

	ips := append([]string(nil), host.OtherIps...)
	sort.Strings(ips)
	ips, ipTrunc := capStrings(dedupSorted(ips), limit)

	// OS candidates and traceroute hops keep upstream's order: the first guess is
	// the most plausible one and a hop list is a path, so sorting either would
	// destroy the only information the order carries.
	guesses, guessTrunc := capStrings(host.OsGuesses, limit)
	hops, hopTrunc := capStrings(host.Hops, limit)

	a.emit(ctx, HostProfileCollected{
		IP:              ip,
		DnsName:         dnsName,
		OtherNames:      names,
		OtherIPs:        ips,
		MacAddress:      host.MacAddress,
		OSGuesses:       guesses,
		OSFromSMB:       host.OsSmb,
		LastBoot:        host.LastBoot,
		Uptime:          host.Uptime,
		DetectionReason: host.DetectionReason,
		Hops:            hops,
		Truncated:       nameTrunc || ipTrunc || guessTrunc || hopTrunc,
	})
}

// runJobs runs the planned subordinate jobs through one bounded pool and returns
// the outcome counts. A failing job never stops an unrelated one: only the context
// stops the pool.
func (a *Actor) runJobs(ctx context.Context, jobs []plan.Job, totals *counters) (succeeded, failed int) {
	var ok, bad atomic.Int64
	sem := make(chan struct{}, a.workers)
	var wg sync.WaitGroup

	// Two bounds, both held for the whole job: this target's own pool, and the
	// tool-wide ceiling shared with every other target in flight. Taking the
	// per-host slot first means a target queues on its own budget before competing
	// for the shared one, so a host that is already at its cap cannot hold shared
	// slots away from other targets.
	for _, j := range jobs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			a.emit(ctx, Cancelled{Phase: phaseJobs, IP: j.IP, Err: ctx.Err()})
			wg.Wait()
			return int(ok.Load()), int(bad.Load())
		}
		select {
		case a.jobSlots <- struct{}{}:
		case <-ctx.Done():
			<-sem
			a.emit(ctx, Cancelled{Phase: phaseJobs, IP: j.IP, Err: ctx.Err()})
			wg.Wait()
			return int(ok.Load()), int(bad.Load())
		}

		wg.Add(1)
		go func(j plan.Job) {
			defer wg.Done()
			defer func() { <-a.jobSlots }()
			defer func() { <-sem }()
			totals.enter()
			defer totals.leave()
			if a.runJob(ctx, j) {
				ok.Add(1)
				return
			}
			bad.Add(1)
		}(j)
	}

	wg.Wait()
	return int(ok.Load()), int(bad.Load())
}

// runJob dispatches one job to its module and reports whether it produced a usable
// result. Every failure path has already emitted its own event.
func (a *Actor) runJob(ctx context.Context, j plan.Job) bool {
	if ctx.Err() != nil {
		a.emit(ctx, Cancelled{Phase: j.Module.String(), IP: j.IP, Err: ctx.Err()})
		return false
	}
	switch j.Module {
	case plan.Banner:
		return a.runBanner(ctx, j)
	case plan.TLS:
		return a.runTLS(ctx, j)
	case plan.SSH:
		return a.runSSH(ctx, j)
	case plan.Crawl:
		return a.runCrawl(ctx, j)
	case plan.Enum:
		return a.runEnum(ctx, j)
	case plan.Discovery:
		// Discovery is never scheduled as a subordinate job: it is the input to them.
		return false
	default:
		return false
	}
}

// jobDir returns a per-job directory inside the actor-owned temporary root,
// creating it on demand. Nothing this tool writes ever lives outside that root.
func (a *Actor) jobDir(j plan.Job) (string, error) {
	dir := filepath.Join(a.tempRoot, fmt.Sprintf("%s-%s-%d", j.Module, sanitizePathPart(j.IP), j.Port))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create job directory: %w", err)
	}
	return dir, nil
}

// cleanup removes the actor-owned temporary tree. A failure is reported and joined
// into the returned error rather than swallowed: leftover scan files are a real
// defect even when the scan itself succeeded.
func (a *Actor) cleanup(ctx context.Context) error {
	if a.tempRoot == "" {
		return nil
	}
	if err := os.RemoveAll(a.tempRoot); err != nil {
		a.emit(ctx, CleanupError{Path: a.tempRoot, Err: err})
		return fmt.Errorf("goscans: remove temporary root %s: %w", a.tempRoot, err)
	}
	a.tempRoot = ""
	return nil
}

// emit sends one event to the configured sink.
func (a *Actor) emit(ctx context.Context, e Event) {
	if a.cfg.Sink == nil {
		return
	}
	a.cfg.Sink.Emit(ctx, e)
}

// emitTo sends one event to a sink that is not attached to an Actor yet, which is
// the case for the validation failures New reports.
func emitTo(sink tooleventlog.EventSink, e Event) {
	if sink == nil {
		return
	}
	sink.Emit(context.Background(), e)
}

// remaining returns the smaller of want and the time left on the context, so no
// module is ever given a deadline that outlives the run.
func remaining(ctx context.Context, want time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return want
	}
	if left := time.Until(deadline); left < want {
		return left
	}
	return want
}

// discoveryArgs returns the nmap arguments for one discovery scan and reports
// whether the scan was scoped to a supplied port set.
//
// Scoping is skipped when the operator already chose a port range. Appending a
// second port argument would leave nmap to resolve the conflict, and which one wins
// is not something a scan should discover at runtime: an operator who wrote a range
// meant it, so their argument stands and the scan is simply not narrowed.
func discoveryArgs(configured []string, ports []int) (args []string, scoped bool) {
	if len(ports) == 0 || hasPortArgument(configured) {
		return configured, false
	}
	out := make([]string, 0, len(configured)+2)
	out = append(out, configured...)
	return append(out, "-p", joinPorts(ports)), true
}

// hasPortArgument reports whether the operator's arguments already choose which
// ports to scan, in any of the forms the configuration allows: "-p 80", "-p=80",
// "-p80", or "--top-ports N".
func hasPortArgument(args []string) bool {
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if name == "-p" || name == "--top-ports" || (strings.HasPrefix(a, "-p") && len(a) > 2) {
			return true
		}
	}
	return false
}

// joinPorts renders a normalized port set as an nmap port list.
func joinPorts(ports []int) string {
	var b strings.Builder
	for i, p := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(p))
	}
	return b.String()
}
