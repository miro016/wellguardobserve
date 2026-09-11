package orchestration

import (
	"context"
	"errors"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/censys"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/netlas"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/shodan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/whois"
	"github.com/velgard-sk/vanguard/internal/collection/tools/toolerr"
)

// spawnDns resolves DNS records for domain. causationID is the event ID of the
// DnsDomainNameDiscovered event that triggered this lookup, threaded onto the
// emitted DnsRecordsDiscovered for provenance.
func (o *Orchestrator) spawnDns(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, domain)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceDnsinfo, domain))

	if !o.targets.claim(workDNS, domain) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()
		// Schedule the per-domain active probe on every exit path, so a name that
		// resolved to nothing (or that dnsinfo is disabled for) is still handled by
		// probeDomain's own reachability gates, matching the old phase sweep that
		// iterated every discovered domain. Registered after the sem-release defer so
		// it runs first on unwind: it counts its child on o.wg before this goroutine's
		// wg.Done, keeping the single end-of-run barrier correct.
		defer o.scheduleDomainProbe(ctx, domain, causationID)

		if o.tools.dns == nil {
			return
		}

		records, err := o.tools.dns.Lookup(ctx, domain)
		if err != nil {
			return
		}

		// Record which address families the name resolved to, so the active sweep
		// can recognise an IPv6-only host the scanner may not be able to reach, and
		// whether it has any MX, so the smtp probe can skip a name that handles no mail.
		o.targets.recordAddressFamilies(records.Domain, len(records.A) > 0, len(records.AAAA) > 0)
		if len(records.MX) > 0 {
			o.targets.recordMailRoute(records.Domain)
		}

		corrID := tooleventlog.CorrIDFrom(ctx)
		dnsEvents := translate.DnsRecords(records, o.scanID, causationID, corrID)
		o.publish(ctx, dnsEvents)
		dnsEventID := firstEventID(dnsEvents)

		o.scheduleZoneTransfer(ctx, records.Domain, records.NS, dnsEventID)

		ipEvents := translate.IPAddresses(records.Domain, records, o.scanID, dnsEventID, corrID)
		if len(ipEvents) > 0 {
			o.publish(ctx, translate.ToDomainEvents(ipEvents))
			o.spawnAsn(ctx, ipEvents)
		}
	}()
}

// spawnWhois resolves registration data for the registrable apex of domain.
// causationID is the event ID of the DnsDomainNameDiscovered event that triggered
// this lookup, threaded onto the emitted DomainRegistrationDiscovered for
// provenance. Registration is a property of the registrable apex, not the
// subdomain: a registry's RDAP/WHOIS server returns 404 for a non-registrable
// name, and every subdomain shares the apex's registration. So the lookup is
// reduced to the apex and deduplicated by apex, running whois once per estate
// apex rather than once per discovered name. It is gated and deduplicated
// independently of spawnDns so whois can run on its own.
func (o *Orchestrator) spawnWhois(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	apex := whois.RegistrableApex(domain)

	ctx = tooleventlog.WithTarget(ctx, apex)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceWhois, apex))

	if !o.targets.claim(workWhois, apex) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.whois == nil {
			return
		}

		registration, err := o.tools.whois.Lookup(ctx, apex)
		if err != nil {
			return
		}

		o.publish(ctx, translate.Registration(apex, registration, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx)))
	}()
}

// spawnMailsec gathers the email-security posture (SPF/DMARC/DKIM/BIMI) for
// domain. causationID is the event ID of the DnsDomainNameDiscovered that
// triggered the lookup, threaded onto the emitted MailSecurityDiscovered for
// provenance. It is gated and deduplicated independently of the other per-domain
// lookups so mail security can run on its own.
func (o *Orchestrator) spawnMailsec(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, domain)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceMailsec, domain))

	if !o.targets.claim(workMailsec, domain) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.mailsec == nil {
			return
		}

		records, err := o.tools.mailsec.Lookup(ctx, domain)
		if err != nil {
			return
		}

		o.publish(ctx, translate.MailSecurity(domain, records, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx)))
	}()
}

// spawnBreach gathers the data-breach exposure (breached email aliases) for
// domain from HIBP. causationID is the event ID of the DnsDomainNameDiscovered
// that triggered the lookup, threaded onto the emitted BreachDataDiscovered for
// provenance. It is gated and deduplicated independently of the other per-domain
// lookups so breach data can run on its own. A nil result (no breached aliases)
// produces no domain event.
func (o *Orchestrator) spawnBreach(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	if o.toolIsUnavailable(sourceBreach) {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, domain)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceBreach, domain))

	if !o.targets.claim(workBreach, domain) {
		return
	}

	if !o.takePaidBudget(ctx, sourceBreach) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.breach == nil {
			return
		}

		result, err := o.tools.breach.Lookup(ctx, domain)
		if err != nil {
			if errors.Is(err, toolerr.ErrProviderUnavailable) {
				o.markToolUnavailable(ctx, sourceBreach, err)
			}
			return
		}

		o.publish(ctx, translate.BreachData(domain, result, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx)))
	}()
}

// spawnCensys searches Censys for the hosts attributed to the scan estate. Censys
// is an estate-wide source, not a per-domain one: querying host.dns.names and
// host.services.cert.names on the registered root already matches every subdomain
// (Censys does registered-domain suffix matching, confirmed against the live API),
// so one query per type returns the whole estate and a per-subdomain query would
// only repeat it. It therefore runs exactly once - the first per-domain fan-out to
// reach it triggers the estate query at the root, and every later call
// short-circuits on the seen-set - attributing the result to the root with the
// root's discovery event as causation. The passed per-domain causationID is only a
// fallback. A nil or empty result produces no domain event; the single call also
// bounds spend to one paid lookup.
func (o *Orchestrator) spawnCensys(ctx context.Context, _, causationID string) {
	if ctx.Err() != nil {
		return
	}

	if o.toolIsUnavailable(sourceCensys) {
		return
	}

	root := o.gate.root()
	if root == "" {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, root)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceCensys, root))

	if !o.targets.claim(workCensys, root) {
		return
	}
	// Attribute the estate query to the root's own discovery when it has one; the
	// per-domain causation the fan-out passed in is only a fallback.
	if id := o.targets.domainEventID(root); id != "" {
		causationID = id
	}

	if !o.takeCensysPaidBudget(ctx) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.censys == nil {
			return
		}

		result, err := o.tools.censys.Search(ctx, root)
		if err != nil {
			if errors.Is(err, toolerr.ErrProviderUnavailable) {
				o.markToolUnavailable(ctx, sourceCensys, err)
			}
			return
		}
		if result == nil {
			// A cache-only client with no fixture entry for the root: no observation
			// was made, so there is nothing to translate or ingest. The tool log
			// carries the cache miss.
			return
		}

		facet := translate.CensysHosts(root, result, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx))
		o.publish(ctx, facet)
		o.ingestProviderHosts(ctx, root, censysHostIPs(result), sourceCensys, firstEventID(facet))
	}()
}

// spawnShodan searches Shodan for the hosts indexed for domain. causationID is
// the event ID of the DnsDomainNameDiscovered that triggered the lookup, threaded
// onto the emitted ShodanHostsDiscovered for provenance. It is gated and
// deduplicated independently of the other per-domain lookups so Shodan can run on
// its own. A nil or empty result produces no domain event. Shodan is a paid API
// queried once per discovered domain, so the per-domain dedup also bounds spend.
func (o *Orchestrator) spawnShodan(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	if o.toolIsUnavailable(sourceShodan) {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, domain)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceShodan, domain))

	if !o.targets.claim(workShodan, domain) {
		return
	}

	if !o.takePaidBudget(ctx, sourceShodan) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.shodan == nil {
			return
		}

		result, err := o.tools.shodan.Search(ctx, domain)
		if err != nil {
			if errors.Is(err, toolerr.ErrProviderUnavailable) {
				o.markToolUnavailable(ctx, sourceShodan, err)
			}
			return
		}

		facet := translate.ShodanHosts(domain, result, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx))
		o.publish(ctx, facet)
		o.ingestProviderHosts(ctx, domain, shodanHostIPs(result), sourceShodan, firstEventID(facet))
	}()
}

// spawnNetlas searches Netlas for the hosts indexed for domain. causationID is the
// event ID of the DnsDomainNameDiscovered that triggered the lookup, threaded onto
// the emitted NetlasHostsDiscovered for provenance. It is gated and deduplicated
// independently of the other per-domain lookups so Netlas can run on its own. A nil
// or empty result produces no domain event. Netlas is a paid API queried once per
// discovered domain, so the per-domain dedup also bounds spend.
func (o *Orchestrator) spawnNetlas(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	if o.toolIsUnavailable(sourceNetlas) {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, domain)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceNetlas, domain))

	if !o.targets.claim(workNetlas, domain) {
		return
	}

	if !o.takePaidBudget(ctx, sourceNetlas) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.netlas == nil {
			return
		}

		result, err := o.tools.netlas.Search(ctx, domain)
		if err != nil {
			if errors.Is(err, toolerr.ErrProviderUnavailable) {
				o.markToolUnavailable(ctx, sourceNetlas, err)
			}
			return
		}

		facet := translate.NetlasHosts(domain, result, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx))
		o.publish(ctx, facet)
		o.ingestProviderHosts(ctx, domain, netlasHostIPs(result), sourceNetlas, firstEventID(facet))
	}()
}

// spawnVirustotal fetches the VirusTotal reputation report for domain.
// causationID is the event ID of the DnsDomainNameDiscovered that triggered the
// lookup, threaded onto the emitted DomainReputationDiscovered for provenance. It
// is gated and deduplicated independently of the other per-domain lookups. Only
// the reputation lookup runs here; subdomain enumeration is a root-level pass (see
// runVirustotalSubdomains). VirusTotal's free tier allows 4 requests/min, so the
// per-domain dedup also bounds request volume.
func (o *Orchestrator) spawnVirustotal(ctx context.Context, domain, causationID string) {
	if ctx.Err() != nil {
		return
	}

	ctx = tooleventlog.WithTarget(ctx, domain)
	ctx = tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceVirustotal, domain))

	if !o.targets.claim(workVirustotal, domain) {
		return
	}

	if !o.takePaidBudget(ctx, sourceVirustotal) {
		return
	}

	select {
	case o.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { <-o.sem }()

		if o.tools.virustotal == nil {
			return
		}

		report, err := o.tools.virustotal.Lookup(ctx, domain)
		if err != nil {
			return
		}

		o.publish(ctx, translate.VirustotalReputation(domain, report, o.scanID, causationID, tooleventlog.CorrIDFrom(ctx)))
	}()
}

// ingestProviderHosts turns a provider result's host IPs into inferred
// IPAddressDiscovered events (rejoining them to the core IP asset graph), runs the
// ASN lookup on the newly-seen ones, and schedules the active scan for every result
// IP (providerOnly=true), gated by scheduleHostScan on the probe-provider-hosts
// knob and its own scannedIPs dedup. Runs inside the spawn goroutine, which already
// holds a sem slot.
func (o *Orchestrator) ingestProviderHosts(ctx context.Context, domain string, ips []string, source, facetEventID string) {
	if len(ips) == 0 {
		return
	}
	ipEvents := translate.ProviderIPAddresses(domain, ips, source, o.scanID, facetEventID, tooleventlog.CorrIDFrom(ctx))
	if len(ipEvents) == 0 {
		return
	}
	o.publish(ctx, translate.ToDomainEvents(ipEvents)) // asset graph + entity file
	newIPs := o.targets.registerIPs(ipEvents)
	newByIP := make(map[string]bool, len(newIPs))
	for i := range newIPs {
		newByIP[newIPs[i].IP] = true
	}
	// ASN cross-link (D4). The corroborated policy delegates the lookup to the
	// active corroboration collector, which needs the routed prefix synchronously
	// before it decides on the shared-netblock evidence. That collector only runs
	// when the active host tools are enabled, so a passive-only execution enriches
	// here instead: passive ASN attribution must not depend on active tooling.
	if o.cfg.ProviderHostProbePolicy != ProviderHostProbeCorroborated || !o.corroborationCollectorRuns() {
		o.lookupASNs(ctx, newIPs)
	}

	// Iterate every result IP, not only the newly-registered ones: an IP another
	// domain's provider result already registered in seenIPs may still be
	// unscanned. scheduleHostScan's scannedIPs dedup (and the knob) make this
	// idempotent and gated either way.
	for i := range ipEvents {
		o.handleProviderHost(ctx, providerHostCandidate{
			ip: ipEvents[i].IP, domain: domain, causationID: ipEvents[i].EventID,
		}, newByIP[ipEvents[i].IP])
	}
}

// censysHostIPs extracts the per-host IPs from a Censys search result.
func censysHostIPs(result *censys.DomainHosts) []string {
	ips := make([]string, 0, len(result.Hosts))
	for i := range result.Hosts {
		ips = append(ips, result.Hosts[i].IP)
	}
	return ips
}

// shodanHostIPs extracts the per-host IPs from a Shodan search result.
func shodanHostIPs(result *shodan.DomainHosts) []string {
	ips := make([]string, 0, len(result.Hosts))
	for i := range result.Hosts {
		ips = append(ips, result.Hosts[i].IP)
	}
	return ips
}

// netlasHostIPs extracts the per-host IPs from a Netlas search result.
func netlasHostIPs(result *netlas.DomainHosts) []string {
	ips := make([]string, 0, len(result.Hosts))
	for i := range result.Hosts {
		ips = append(ips, result.Hosts[i].IP)
	}
	return ips
}
