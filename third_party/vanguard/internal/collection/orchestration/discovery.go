package orchestration

import (
	"context"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"strings"
)

// runSubfinder enumerates subdomains for root via subfinder, feeds each into the
// pipeline as a DnsDomainNameDiscovered (Source = subfinder), and fans out the
// per-domain DNS and whois lookups. Names already discovered by the crawler are
// deduplicated by spawnDns/spawnWhois, but re-emitting their domain event still
// records subfinder provenance, so multi-tool coverage is captured. Enumeration
// failures surface as a subfinder tool event from the client and are otherwise
// non-fatal to the scan.
func (o *Orchestrator) runSubfinder(ctx context.Context, root string) {
	if ctx.Err() != nil {
		return
	}
	callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, root), newToolCorrID(o.scanID, sourceSubfinder, root))
	results, err := o.tools.subfinder.Enumerate(callCtx, root)
	if err != nil {
		return
	}
	for _, r := range results {
		evts := translate.Subfinder(r.Subdomain, root, o.scanID)
		o.publish(ctx, evts)
		causationID := firstEventID(evts)
		o.spawnDns(ctx, r.Subdomain, causationID)
		o.spawnWhois(ctx, r.Subdomain, causationID)
		o.spawnMailsec(ctx, r.Subdomain, causationID)
		o.fanOutPaid(ctx, r.Subdomain, causationID)
	}

	// A successful enumeration that found nothing with every source enabled almost
	// always means a provider key is missing, not a target without subdomains; flag
	// it as a coverage gap rather than letting the empty result pass as clean.
	o.flagSubfinderZeroResult(ctx, root, len(results))
}

// runCertspotter queries the certspotter second CT source for root, feeds each
// discovered name into the pipeline as a DnsDomainNameDiscovered (Source =
// certspotter), and fans out the per-domain lookups. It mirrors runSubfinder: the
// names enrich the asset graph, and the per-source count it records feeds the
// post-crawl CT coverage cross-check. A query failure surfaces as a certspotter
// tool event from the client and is otherwise non-fatal (the cross-check is simply
// skipped for that run).
func (o *Orchestrator) runCertspotter(ctx context.Context, root string) {
	if ctx.Err() != nil {
		return
	}
	callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, root), newToolCorrID(o.scanID, sourceCertspotter, root))
	// Fetch through the per-scan memo so a root the degraded-empty corroboration already
	// queried certspotter for is served from cache instead of re-fetched.
	subs, _, err := o.certspotterMemo.Certs(callCtx, root)
	if err != nil {
		return
	}
	for _, sub := range subs {
		evts := translate.CertspotterSubdomain(sub, root, o.scanID)
		o.publish(ctx, evts)
		causationID := firstEventID(evts)
		o.spawnDns(ctx, sub, causationID)
		o.spawnWhois(ctx, sub, causationID)
		o.spawnMailsec(ctx, sub, causationID)
		o.fanOutPaid(ctx, sub, causationID)
	}
}

// runVirustotalSubdomains enumerates subdomains for root via VirusTotal, feeds
// each into the pipeline as a DnsDomainNameDiscovered (Source = virustotal), and
// fans out the per-domain lookups. It mirrors runSubfinder: names already seen
// are deduplicated downstream, but re-emitting their domain event still records
// VirusTotal provenance for multi-source coverage. Enumeration failures surface
// as a virustotal tool event from the client and are otherwise non-fatal.
func (o *Orchestrator) runVirustotalSubdomains(ctx context.Context, root string) {
	if ctx.Err() != nil {
		return
	}
	callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, root), newToolCorrID(o.scanID, sourceVirustotal, root))
	subs, err := o.tools.virustotal.Subdomains(callCtx, root)
	if err != nil {
		return
	}
	for _, sub := range subs {
		evts := translate.VirustotalSubdomain(sub.Name, root, o.scanID, sub.LastSeen)
		o.publish(ctx, evts)
		causationID := firstEventID(evts)
		o.spawnDns(ctx, sub.Name, causationID)
		o.spawnWhois(ctx, sub.Name, causationID)
		o.spawnMailsec(ctx, sub.Name, causationID)
		o.fanOutPaid(ctx, sub.Name, causationID)
	}
}

// runWebsearch runs the Google dork pass for root via SerpAPI. It folds the dork
// hits onto the root domain as a WebAssetsDiscovered (the WebAssets facet) and,
// for each distinct in-scope result host, emits a DnsDomainNameDiscovered
// (Source = websearch) and fans out the per-domain lookups, mirroring
// runVirustotalSubdomains. Out-of-scope hosts (third-party sites in results) stay
// in the facet but are not added to the asset graph. It runs once on the root, so
// it never re-triggers itself. Search failures surface as a websearch tool event
// from the client and are otherwise non-fatal.
func (o *Orchestrator) runWebsearch(ctx context.Context, root string) {
	if ctx.Err() != nil {
		return
	}
	callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, root), newToolCorrID(o.scanID, sourceWebsearch, root))
	result, err := o.tools.websearch.Search(callCtx, root)
	if err != nil {
		return
	}

	o.publish(callCtx, translate.WebAssets(root, result, o.scanID, tooleventlog.CorrIDFrom(callCtx)))

	seenHost := make(map[string]bool)
	for _, a := range result.Assets {
		host := a.Host
		if seenHost[host] || !inScopeHost(host, root) {
			continue
		}
		seenHost[host] = true

		evts := translate.WebsearchHost(host, root, o.scanID)
		o.publish(ctx, evts)
		hostCausation := firstEventID(evts)
		o.spawnDns(ctx, host, hostCausation)
		o.spawnWhois(ctx, host, hostCausation)
		o.spawnMailsec(ctx, host, hostCausation)
		o.fanOutPaid(ctx, host, hostCausation)
	}
}

// inScopeHost reports whether host is the root domain or a subdomain of it, so
// third-party hosts that appear in search results are not added as discovered
// domains of the target. Matching is on label boundaries: a deceptive suffix
// such as example.com.attacker.test is out of scope for example.com.
//
// The websearch tool already rejects unowned result hosts before returning them;
// this check is the defensive second gate for the domain fan-out and must keep
// the same suffix semantics.
func inScopeHost(host, root string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	r := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), ".")
	if h == "" || r == "" {
		return false
	}
	return h == r || strings.HasSuffix(h, "."+r)
}
