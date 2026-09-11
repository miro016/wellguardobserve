package orchestration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/certs"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/crawler"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/detectors"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Orchestrator coordinates the execution of the crawler and the tool actors. It is
// the composition root of a scan and the single place that translates system events
// into domain events.
//
// It owns execution coordination - the wait group every scheduled unit of work is
// counted on, the concurrency semaphores, the immutable configuration and tool
// clients, the scan identity, and a construction failure - plus references to the
// state owners that hold everything the run accumulates. It deliberately holds no
// bookkeeping maps of its own: each of those belongs to exactly one owner with one
// lock, described in the package documentation's state-ownership section.
type Orchestrator struct {
	cfg   Config
	tools toolset
	wg    sync.WaitGroup
	sem   chan struct{}
	// portScanSem independently bounds simultaneous naabu runners so packet rate
	// and host concurrency are both explicit in configuration.
	portScanSem chan struct{}

	// targets owns discovery and scheduling identity: the per-tool claim sets, each
	// domain's first-discovery event id and depth, the per-domain reachability
	// signals, and the registered addresses. None of it authorizes traffic.
	targets *targetState
	// providers owns the provider-host corroboration evidence: DNS-confirmed
	// addresses, routed prefixes, queued candidates, and collected PTR and
	// certificate names.
	providers *providerState
	// seeds owns the terminal stages' target seeds: the detection stage's URLs and
	// tags, and the GoScans substage's hosts, virtual-host names, and observed ports.
	seeds *terminalSeedState
	// gate groups the cross-cutting run policy: scope, paid and active budget
	// counters, approved request targets, per-tool circuit breakers, and the dedup
	// sets for audit events. All gate state is guarded by its own mutex, and no other
	// state owner's lock is ever held across a call into it.
	gate gate

	// ipv6Usable records whether the scanner has a routable IPv6 address, checked
	// once at the start of an execution that will add active work. When false, an
	// IPv6-only target is unreachable and the active probes against it would record
	// an empty result indistinguishable from a clean one, so they are skipped with a
	// coverage Issue. It is written before any goroutine that reads it is started.
	ipv6Usable bool
	// certCoverage records the distinct domain names each discovery source
	// contributed, so the passive phase can cross-check crt.sh's
	// certificate-transparency coverage against the certspotter second CT source and
	// flag a likely-truncated crt.sh response. It self-synchronizes (its own mutex),
	// so it is recorded into outside any other state owner's lock.
	certCoverage *certs.Coverage
	// historyCerts and liveCerts are the second CT sources the degraded-empty
	// corroboration consults for a crt.sh degraded query: censys (CT history, the
	// authoritative source) and certspotter (currently-valid certs). They are adapters
	// over the tool clients, left nil when the client is absent so an unconfigured
	// source is simply not consulted. Kept as interfaces so tests inject fakes.
	historyCerts certs.HistoryCertSource
	liveCerts    certs.LiveCertSource
	// certspotterMemo caches certspotter results per domain for the scan so the
	// discovery pass and the degraded-empty corroboration never query certspotter twice
	// for one root. It backs liveCerts and is called directly by runCertspotter; nil
	// when certspotter is absent.
	certspotterMemo *certspotterMemo
	// requestAllow is the run-scoped callback later HTTP-tool steps inject. It is
	// bound before tool construction and owns no process-global state.
	requestAllow scopecheck.Allow
	// scanID is the identity every event of this execution carries. It is written
	// once at the top of an execution, before any goroutine that reads it is started.
	scanID    string
	detectors *detectors.Registry
	// httpProbePorts is the set of open ports the active phase probes over HTTP,
	// copied from defaultHTTPProbePorts at construction. Non-HTTP services (ssh,
	// smtp, mysql, ...) are dialled by the port scan but skipped by the HTTP probe.
	httpProbePorts map[int]bool
	// initErr holds a construction failure of an enabled tool client. New has no
	// error return, so the failure is carried here and refused by Run before the scan
	// emits a lifecycle event or sends a single request. A scan that cannot run the
	// tools the operator enabled must not silently produce a clean-looking result for
	// work that never happened.
	initErr error
}

// New creates a new Orchestrator and initialises tool clients.
// Sink fields in cfg are optional; nil means events are silently dropped.
func New(cfg *Config) *Orchestrator {
	limit := cfg.MaxConcurrency
	if limit <= 0 {
		limit = 10
	}
	hostLimit := cfg.PortScanHostConcurrency
	if hostLimit <= 0 {
		hostLimit = 1
	}

	o := &Orchestrator{
		cfg:            *cfg,
		sem:            make(chan struct{}, limit),
		portScanSem:    make(chan struct{}, hostLimit),
		targets:        newTargetState(),
		providers:      newProviderState(),
		seeds:          newTerminalSeedState(),
		certCoverage:   certs.NewCoverage(),
		gate:           newGate(),
		detectors:      detectors.DefaultRegistry(),
		httpProbePorts: maps.Clone(defaultHTTPProbePorts),
	}

	o.requestAllow = o.allowRequest
	o.cfg.PortScan.Allow = o.requestAllow
	o.cfg.HttpProbe.Allow = o.requestAllow
	// Compile the engagement exclusions once from the immutable config and inject the
	// dial-time boundary into every target-facing tool that resolves and dials on its
	// own. The values are the same ones setScope compiles into the gate, so the tool
	// dialer and the admission gate share one policy.
	toolExclusions, exclusionErr := scopecheck.NewExclusions(o.cfg.ScopeExclude, o.cfg.ScopeExcludeIPs)
	o.cfg.HttpProbe.Exclusions = toolExclusions
	o.cfg.Https.Exclusions = toolExclusions
	o.cfg.Smtp.Allow = o.requestAllow
	o.cfg.Smtp.Exclusions = toolExclusions
	o.cfg.WebInfo.Exclusions = toolExclusions
	o.cfg.Wappalyzer.Exclusions = toolExclusions
	o.cfg.Https.Allow = o.requestAllow
	o.cfg.WebInfo.Allow = o.requestAllow
	o.cfg.Wappalyzer.Allow = o.requestAllow
	// Create a client only for an enabled tool, so a disabled tool is inert. An
	// enabled tool that fails to construct is held here and refused by Run before any
	// traffic leaves the machine: New keeps its shape (it has no error return), but
	// the failure is never swallowed into a silently nil client.
	o.tools, o.initErr = newToolset(&o.cfg)
	if exclusionErr != nil {
		o.initErr = fmt.Errorf("compile engagement exclusions: %w", exclusionErr)
	}

	// Adapt the constructed CT clients to the corroboration source interfaces. Done
	// after the clients exist so an absent client leaves its source nil (not consulted).
	o.initCorroborationSources()

	return o
}

// RequestAuthorizer returns the run-scoped callback used by target-facing tools.
// Callers may retain it before a run starts; decisions use the scope and approved
// targets present when the callback is invoked.
func (o *Orchestrator) RequestAuthorizer() scopecheck.Allow {
	return o.requestAllow
}

// Source names stamped onto EventMeta.Source, identifying the tool that produced
// the underlying data for a translated domain event. The tool labels are defined
// once in the translate package (which stamps them on the events it builds) and
// aliased here for the orchestrator's per-call correlation IDs (newToolCorrID), so
// the tool name on a call and the source on its events share one definition. The
// control-plane labels (coverage, detector) are owned by the orchestrator.
const (
	sourceCrtsh         = translate.SourceCrtsh
	sourceCertspotter   = translate.SourceCertspotter
	sourceCoverage      = "coverage"
	sourceSubfinder     = translate.SourceSubfinder
	sourceDnsinfo       = translate.SourceDnsinfo
	sourceAsn           = translate.SourceAsn
	sourceWhois         = translate.SourceWhois
	sourceMailsec       = translate.SourceMailsec
	sourceBreach        = translate.SourceBreach
	sourceCensys        = translate.SourceCensys
	sourceVirustotal    = translate.SourceVirustotal
	sourceWebsearch     = translate.SourceWebsearch
	sourceShodan        = translate.SourceShodan
	sourceNetlas        = translate.SourceNetlas
	sourceDetector      = "detector"
	sourceProviderProbe = "provider-probe"
	// Control-plane labels shared by every stage that can be capped or tripped: a
	// budget refusal and a stage-level failure read the same whichever tool hit it.
	sourceBudget         = "budget"
	sourceCircuitBreaker = "circuit-breaker"
	sourceScope          = "scope"
	sourcePortscan       = translate.SourcePortscan
	sourceHTTP           = translate.SourceHTTP
	sourceHTTPS          = translate.SourceHTTPS
	sourceSMTP           = translate.SourceSMTP
	sourceWebinfo        = translate.SourceWebinfo
	sourceWappalyzer     = translate.SourceWappalyzer
	sourceGoScans        = translate.SourceGoScans
)

// NewScanID returns a fresh opaque scan identity for one collection. The app mints
// it here and injects it through Config.ScanID, so the identity the capture manifest
// records and the identity every event carries are one value chosen in one place.
func NewScanID() string {
	return newScanID()
}

// newScanID generates a unique, opaque identifier for a single scan run. It uses
// random bytes rather than a timestamp so two scans started in the same instant
// cannot collide and the ID leaks no timing information.
func newScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}
	return "scan_" + hex.EncodeToString(b[:])
}

// newToolCorrID returns a per-invocation correlation id for one tool call. It
// hashes the scan, tool, target, and attempt time so two calls to the same tool
// against the same target (e.g. a retry) still get distinct ids. The orchestrator
// stamps it on the call's context (so PersistSink tags every tool event with it)
// and onto the domain events derived from the call's result, forming the audit
// join between tooling.jsonl and events.jsonl.
func newToolCorrID(scanID, tool, target string) string {
	return events.NewEventID(time.Now(), scanID+"|"+tool+"|"+target)
}

// Run executes the orchestration: it crawls the root domain named by Config.Root
// and fans out per-domain DNS/ASN lookups as new domains are discovered. It is the
// one entry point, and everything it plans comes from the configuration and the
// events this invocation observes.
//
// A test may set the scope itself before calling; the scope is derived from the
// configuration only when it has not been set, so one run never has two roots.
func (o *Orchestrator) Run(ctx context.Context) error {
	if o.initErr != nil {
		return o.initErr
	}
	// The scope's root is the scanned domain; include/exclude/depth refine it.
	if o.gate.root() == "" {
		o.gate.setScope(Scope{
			Root:      o.cfg.Root,
			Include:   o.cfg.ScopeInclude,
			Exclude:   o.cfg.ScopeExclude,
			ExcludeIP: o.cfg.ScopeExcludeIPs,
			DepthCap:  o.cfg.ScopeDepthCap,
		})
	}

	return o.runLifecycle(ctx, o.gate.root())
}

// runStages is the whole of a run's scanning work: it checks IPv6 once before any
// active probe is scheduled, drives live passive discovery (whose streaming children
// fan out the active work), and then runs the terminal stages. Discovery is skipped
// when passive is disabled, matching the recon-only configuration, and its error is
// returned so the lifecycle shell can report it without swallowing it.
func (o *Orchestrator) runStages(ctx context.Context, domain string) error {
	if o.cfg.EnableActive {
		o.checkIPv6Once()
	}

	var runErr error
	if o.cfg.EnablePassive {
		runErr = o.runDiscovery(ctx, domain)
	}

	// Every run reaches the terminal stages; each is inert unless its own
	// configuration enables it. GoScans runs after the streaming active workers drain
	// (inside runDiscovery).
	o.runTerminalStages(ctx)
	return runErr
}

// runDiscovery drives the crawler and the other discovery sources, then waits for
// the whole bounded-concurrency pipeline to drain. There is no passive/active
// phase split: each discovery source fans out the per-domain passive lookups, and
// each resolved domain/IP immediately schedules its own active probes (under the
// same sem/wg limiter, gated by scope/budget/reachability). The single wg.Wait
// below is therefore the one barrier for both passive and active work. The crawler
// requires the crt.sh client, so it only runs when crtsh is enabled; the DNS and
// ASN sub-tools are gated independently by their own enable flags (a nil client
// is skipped in spawnDns/spawnAsn).
func (o *Orchestrator) runDiscovery(ctx context.Context, domain string) error {
	// Stamp the scan onto the context so every tool event the PersistSink writes is
	// correlated back to this scan. Tool code stays pure; the correlation rides the
	// context into each tool call. The active schedulers re-stamp the active phase
	// onto their own call contexts.
	ctx = tooleventlog.WithScan(ctx, o.scanID, string(events.PhasePassive))

	var runErr error
	if o.tools.crtsh != nil {
		crawlerCfg := crawler.Config{
			CrtshClient:    o.tools.crtsh,
			MaxDepth:       o.cfg.MaxDepth,
			RestrictToRoot: o.cfg.RestrictToRoot,
			EventSink:      &crawlerInterceptor{o: o, ctx: ctx, rootDomain: domain},
		}
		c, err := crawler.NewCrawlerActor(&crawlerCfg, valueobjects.DnsDomainName(domain))
		if err != nil {
			return fmt.Errorf("failed to create crawler: %w", err)
		}
		runErr = c.Run(ctx)
	}

	// Certspotter is the second Certificate Transparency source: it both feeds the
	// discovery pipeline (its names enrich the asset graph) and, crucially,
	// corroborates the crt.sh crawler's coverage for the post-crawl cross-check.
	if o.tools.certspotter != nil {
		o.runCertspotter(ctx, domain)
	}

	// Subfinder is an independent passive subdomain source: it runs alongside the
	// crt.sh crawler and feeds the same per-domain DNS/whois fan-out.
	if o.tools.subfinder != nil {
		o.runSubfinder(ctx, domain)
	}

	// VirusTotal subdomain enumeration is another root-level passive source. It is
	// gated separately so the reputation lookup (which runs per-domain) can be used
	// without paying for subdomain enumeration.
	if o.tools.virustotal != nil && o.cfg.Virustotal.EnableSubdomains {
		o.runVirustotalSubdomains(ctx, domain)
	}

	// Web search (Google dorks) is a root-level pass: its site:*.<root> dork already
	// surfaces subdomains, so it runs once on the root rather than per discovered
	// domain (which would multiply paid SerpAPI calls).
	if o.tools.websearch != nil {
		o.runWebsearch(ctx, domain)
	}

	// Wait for the whole pipeline to drain: the background passive DNS/whois/ASN
	// lookups and every active probe they scheduled (all tracked on o.wg).
	o.wg.Wait()
	// Corroborated provider hosts wait for all passive PTR/ASN evidence so their
	// verdict is independent of goroutine arrival order. Approved scans are a second,
	// bounded wave and must drain before terminal phases begin.
	o.finalizeProviderHosts(ctx)
	o.wg.Wait()

	// Cross-check crt.sh's CT coverage against the certspotter corroborator now that
	// both sources have fully reported, raising a coverage Issue if crt.sh is short.
	o.crossCheckCTCoverage(ctx, domain)

	// Backstop the whole discovery phase: if every enumeration source together found
	// nothing past the bare root, raise a coverage Issue so a collapsed surface can
	// never present as a clean, low-risk scan.
	o.flagDiscoveryCollapse(ctx, domain)
	return runErr
}
