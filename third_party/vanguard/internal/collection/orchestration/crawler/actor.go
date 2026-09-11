package crawler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/crtsh"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Actor walks a root domain and its subdomains via crt.sh searches,
// emitting crawler system events as discoveries occur.
type Actor struct {
	cfg        Config
	rootDomain valueobjects.DnsDomainName
	inbox      chan any
	state      crawlerState
}

// NewCrawlerActor returns a new CrawlerActor for the given root domain.
func NewCrawlerActor(cfg *Config, rootDomain valueobjects.DnsDomainName) (*Actor, error) {
	if cfg.EventSink == nil {
		return nil, fmt.Errorf("EventSink is mandatory")
	}

	return &Actor{
		cfg:        *cfg,
		rootDomain: normalizeDomain(rootDomain),
		inbox:      make(chan any, 100),
	}, nil
}

// Run drives the crawl to completion or context cancellation.
func (a *Actor) Run(ctx context.Context) error {
	reply := make(chan crawlerResult, 1)
	a.inbox <- startCrawl{ctx: ctx, reply: reply}

	go a.loop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case res := <-reply:
		return res.err
	}
}

// -----------------------------------------------------------------------------
// State and message types
// -----------------------------------------------------------------------------

type qitem struct {
	domain valueobjects.DnsDomainName
	depth  int
}

type crawlerState struct {
	Reply                 chan crawlerResult
	Queue                 []qitem
	Seen                  map[valueobjects.DnsDomainName]int
	TotalDomainsProcessed int
	TotalCertsFound       int
	PendingExactCerts     int // certs from FetchDomain, held until FetchSubdomains completes
	// WildcardCovered holds domains whose "%.domain" wildcard search succeeded.
	// crt.sh's % matches across dots, so a successful "%.ancestor" search already
	// returned every certificate for that name and all its subdomains at any depth.
	// A later queued name that is this domain or under it needs no crt.sh query of
	// its own - its certificates are a subset of the ancestor wildcard's result - so
	// it is skipped, collapsing the old per-label exact+wildcard fan-out to one pair
	// of searches per uncovered zone. Only successful wildcards are recorded, so a
	// failed ancestor wildcard correctly falls back to querying the name directly.
	WildcardCovered map[valueobjects.DnsDomainName]struct{}
	Finished        bool
}

type startCrawl struct {
	ctx   context.Context
	reply chan crawlerResult
}

type crawlerResult struct {
	err error
}

type doNext struct {
	ctx context.Context
}

// exactFetchResult carries the outcome of FetchDomain. It is sent to the inbox
// as soon as the exact search completes, before FetchSubdomains is called.
type exactFetchResult struct {
	ctx      context.Context
	domain   valueobjects.DnsDomainName
	depth    int
	certs    []crtsh.Certificate
	degraded bool // empty result returned only after crt.sh was degraded
	// retrievalSource is the crt.sh client's SearchResult.RetrievalSource: where the
	// certificates came from ("service" or "cache_embedded"). It rides onto every
	// event this result produces so the provenance is not re-derived downstream.
	retrievalSource string
	err             error
}

// domainResult carries the outcome of FetchSubdomains.
type domainResult struct {
	ctx      context.Context
	domain   valueobjects.DnsDomainName
	depth    int
	certs    []crtsh.Certificate
	degraded bool // empty result returned only after crt.sh was degraded
	// retrievalSource mirrors exactFetchResult.retrievalSource for the wildcard search.
	retrievalSource string
	err             error
}

// -----------------------------------------------------------------------------
// Actor loop
// -----------------------------------------------------------------------------

func (a *Actor) loop() {
	for msg := range a.inbox {
		switch m := msg.(type) {
		case startCrawl:
			a.handleStart(m)
		case doNext:
			a.handleDoNext(m)
		case *exactFetchResult:
			a.handleExactFetchResult(m)
		case *domainResult:
			a.handleDomainResult(m)
		}

		if a.state.Finished {
			close(a.inbox)
			return
		}
	}
}

func (a *Actor) handleStart(msg startCrawl) {
	if a.rootDomain == "" {
		a.failNow("invalid root domain")
		return
	}

	a.state = crawlerState{
		Reply:           msg.reply,
		Queue:           []qitem{{domain: a.rootDomain, depth: 0}},
		Seen:            map[valueobjects.DnsDomainName]int{a.rootDomain: 0},
		WildcardCovered: make(map[valueobjects.DnsDomainName]struct{}),
	}

	_ = a.emitSystem(msg.ctx, CrawlStarted{
		RootDomain: string(a.rootDomain),
		MaxDepth:   a.cfg.MaxDepth,
		Timestamp:  time.Now(),
	})

	_ = a.emitSystem(msg.ctx, DomainNameFound{
		Domain:       string(a.rootDomain),
		ParentDomain: "",
		Depth:        0,
		Timestamp:    time.Now(),
	})

	a.inbox <- doNext{ctx: msg.ctx}
}

func (a *Actor) handleDoNext(msg doNext) {
	if msg.ctx.Err() != nil {
		a.cancel(msg.ctx, msg.ctx.Err())
		return
	}

	if len(a.state.Queue) == 0 {
		a.succeed(msg.ctx)
		return
	}

	item := a.state.Queue[0]
	a.state.Queue = a.state.Queue[1:]

	// If a successful ancestor "%.domain" wildcard already covers this name, its
	// certificates were all returned there (crt.sh's % matches across dots). Skip
	// its redundant exact+wildcard searches rather than re-hitting an already-flaky
	// endpoint. The name was still discovered (DomainNameFound) and fed to the rest
	// of discovery, so only the duplicate crt.sh load is dropped, not any data.
	if a.isWildcardCovered(item.domain) {
		a.state.TotalDomainsProcessed++
		_ = a.emitSystem(msg.ctx, DomainProcessingSkipped{
			Domain:    string(item.domain),
			Depth:     item.depth,
			Timestamp: time.Now(),
		})
		a.inbox <- doNext{ctx: msg.ctx}
		return
	}

	_ = a.emitSystem(msg.ctx, DomainProcessingStarted{
		Domain:    string(item.domain),
		Depth:     item.depth,
		Timestamp: time.Now(),
	})

	go func(ctx context.Context, domain valueobjects.DnsDomainName, depth int) {
		exact, exactErr := a.cfg.CrtshClient.FetchDomain(ctx, domain)
		// Send exact results immediately so the actor can emit domain events
		// before FetchSubdomains is called.
		a.inbox <- &exactFetchResult{
			ctx:             ctx,
			domain:          domain,
			depth:           depth,
			certs:           exact.Certs,
			degraded:        exact.DegradedEmpty,
			retrievalSource: exact.RetrievalSource,
			err:             exactErr,
		}
		if exactErr != nil {
			return
		}
		wildcard, wildcardErr := a.cfg.CrtshClient.FetchSubdomains(ctx, domain)
		a.inbox <- &domainResult{
			ctx:             ctx,
			domain:          domain,
			depth:           depth,
			certs:           wildcard.Certs,
			degraded:        wildcard.DegradedEmpty,
			retrievalSource: wildcard.RetrievalSource,
			err:             wildcardErr,
		}
	}(msg.ctx, item.domain, item.depth)
}

// handleExactFetchResult processes the result of FetchDomain, emitting events
// for any certificates and new domains discovered. On error the domain is
// marked failed and the next item is dequeued immediately (FetchSubdomains is
// skipped because the goroutine exits early on exactErr != nil).
func (a *Actor) handleExactFetchResult(msg *exactFetchResult) {
	if msg.err != nil {
		a.state.TotalDomainsProcessed++
		_ = a.emitSystem(msg.ctx, DomainProcessingFailed{
			Domain:    string(msg.domain),
			Err:       msg.err.Error(),
			Timestamp: time.Now(),
		})
		a.inbox <- doNext{ctx: msg.ctx}
		return
	}

	if msg.degraded {
		a.emitDegraded(msg.ctx, msg.domain, string(msg.domain))
	}

	a.state.PendingExactCerts = len(msg.certs)
	a.state.TotalCertsFound += len(msg.certs)

	seenNames := make(map[valueobjects.DnsDomainName]struct{})
	for i := range msg.certs {
		cert := &msg.certs[i]
		_ = a.emitSystem(msg.ctx, &CertificateFound{
			SearchQuery:     string(msg.domain),
			Certificate:     *cert,
			RetrievalSource: msg.retrievalSource,
			Timestamp:       time.Now(),
		})
		a.enqueueDomainsFromCert(msg.ctx, cert, msg.domain, msg.depth, msg.retrievalSource, seenNames)
	}
	// Do not call doNext — wait for the corresponding domainResult from FetchSubdomains.
}

// handleDomainResult processes the result of FetchSubdomains. It combines the
// pending exact-cert count with the wildcard results before emitting
// DomainProcessingSucceeded, then dequeues the next item.
func (a *Actor) handleDomainResult(msg *domainResult) {
	a.state.TotalDomainsProcessed++

	if msg.err != nil {
		_ = a.emitSystem(msg.ctx, DomainProcessingFailed{
			Domain:    string(msg.domain),
			Err:       msg.err.Error(),
			Timestamp: time.Now(),
		})
		a.state.PendingExactCerts = 0
		a.inbox <- doNext{ctx: msg.ctx}
		return
	}

	if msg.degraded {
		a.emitDegraded(msg.ctx, msg.domain, "%."+string(msg.domain))
	}

	a.state.TotalCertsFound += len(msg.certs)
	totalCerts := a.state.PendingExactCerts + len(msg.certs)
	a.state.PendingExactCerts = 0
	// The wildcard search succeeded, so it returned the certificates for this name
	// and every subdomain under it. Record coverage so queued descendants skip their
	// own redundant searches. Only set on success: a failed wildcard must fall back
	// to querying descendants directly so no certificate data is lost.
	a.state.WildcardCovered[msg.domain] = struct{}{}

	_ = a.emitSystem(msg.ctx, DomainProcessingSucceeded{
		Domain:    string(msg.domain),
		Certs:     totalCerts,
		Timestamp: time.Now(),
	})

	seenNames := make(map[valueobjects.DnsDomainName]struct{})
	for i := range msg.certs {
		cert := &msg.certs[i]
		_ = a.emitSystem(msg.ctx, &CertificateFound{
			SearchQuery:     string(msg.domain),
			Certificate:     *cert,
			RetrievalSource: msg.retrievalSource,
			Timestamp:       time.Now(),
		})
		a.enqueueDomainsFromCert(msg.ctx, cert, msg.domain, msg.depth, msg.retrievalSource, seenNames)
	}

	a.inbox <- doNext{ctx: msg.ctx}
}

// enqueueDomainsFromCert emits DomainNameFound for each new domain in cert and
// adds it to the queue if within depth and root restrictions. seenNames
// deduplicates within the current batch of certs (a.state.Seen handles
// cross-domain deduplication across the whole crawl).
func (a *Actor) enqueueDomainsFromCert(
	ctx context.Context,
	cert *crtsh.Certificate,
	parent valueobjects.DnsDomainName,
	depth int,
	retrievalSource string,
	seenNames map[valueobjects.DnsDomainName]struct{},
) {
	for _, d := range cert.Domains {
		domainName := normalizeDomain(valueobjects.DnsDomainName(d))
		if domainName == "" {
			continue
		}
		if a.cfg.RestrictToRoot && !withinRoot(domainName, a.rootDomain) {
			continue
		}
		if _, ok := seenNames[domainName]; ok {
			continue
		}
		seenNames[domainName] = struct{}{}

		if _, ok := a.state.Seen[domainName]; ok {
			continue
		}
		a.state.Seen[domainName] = depth + 1

		_ = a.emitSystem(ctx, DomainNameFound{
			Domain:          string(domainName),
			ParentDomain:    string(parent),
			Depth:           depth + 1,
			RetrievalSource: retrievalSource,
			Timestamp:       time.Now(),
		})

		if depth < a.cfg.MaxDepth {
			a.state.Queue = append(a.state.Queue, qitem{domain: domainName, depth: depth + 1})
		}
	}
}

func (a *Actor) succeed(ctx context.Context) {
	_ = a.emitSystem(ctx, CrawlSucceeded{
		TotalDomainsProcessed: a.state.TotalDomainsProcessed,
		TotalCertsFound:       a.state.TotalCertsFound,
		Timestamp:             time.Now(),
	})
	a.state.Reply <- crawlerResult{err: nil}
	close(a.state.Reply)
	a.state.Finished = true
}

func (a *Actor) cancel(ctx context.Context, err error) {
	_ = a.emitSystem(ctx, CrawlCanceled{
		Err:       err.Error(),
		Timestamp: time.Now(),
	})
	a.state.Reply <- crawlerResult{err: err}
	close(a.state.Reply)
	a.state.Finished = true
}

func (a *Actor) failNow(errMsg string) {
	a.state.Reply <- crawlerResult{err: crawlerError(errMsg)}
	close(a.state.Reply)
	a.state.Finished = true
}

type crawlerError string

func (e crawlerError) Error() string { return string(e) }

func (a *Actor) emitSystem(ctx context.Context, evt SystemEvent) error {
	if a.cfg.EventSink != nil {
		return a.cfg.EventSink.AppendSystem(ctx, evt)
	}
	return nil
}

// emitDegraded reports a crt.sh search that returned zero certificates only after
// the backend was degraded (and a re-query was still empty). The domain still
// processes normally; the event flags the empty as a likely degraded artifact so
// the orchestrator can raise a data-quality issue rather than recording a silent
// authoritative zero from the sole certificate source.
func (a *Actor) emitDegraded(ctx context.Context, domain valueobjects.DnsDomainName, query string) {
	_ = a.emitSystem(ctx, DomainSearchDegraded{
		Domain:    string(domain),
		Query:     query,
		Timestamp: time.Now(),
	})
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func normalizeDomain(s valueobjects.DnsDomainName) valueobjects.DnsDomainName {
	str := strings.TrimSpace(strings.ToLower(string(s)))
	if str == "" {
		return ""
	}
	str = strings.TrimPrefix(str, "*.")
	str = strings.TrimSuffix(str, ".")
	if strings.ContainsAny(str, " \t\r\n/\\") {
		return ""
	}
	return valueobjects.DnsDomainName(str)
}

// isWildcardCovered reports whether a successful "%.ancestor" search has already
// returned every certificate for d. d is covered when d itself or any ancestor
// domain whose wildcard search succeeded is in WildcardCovered: crt.sh's % matches
// across dots, so that ancestor result is a superset of d's exact and wildcard
// searches, and re-querying d would only repeat load. The covered set is tiny (one
// entry per uncovered zone), so a linear scan is simpler than a label walk.
func (a *Actor) isWildcardCovered(d valueobjects.DnsDomainName) bool {
	for cov := range a.state.WildcardCovered {
		if withinRoot(d, cov) {
			return true
		}
	}
	return false
}

func withinRoot(domain, root valueobjects.DnsDomainName) bool {
	if domain == root {
		return true
	}
	return strings.HasSuffix(string(domain), "."+string(root))
}
