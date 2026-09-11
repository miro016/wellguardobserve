package orchestration

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// scheduleZoneTransfer runs the direct authoritative-server AXFR check as active
// reconnaissance. Passive DNS supplies the nameservers, but no transfer is sent
// unless both the active phase and the explicit dnsinfo flag are enabled.
func (o *Orchestrator) scheduleZoneTransfer(ctx context.Context, domain string, nameservers []string, causationID string) {
	if !o.cfg.EnableActive || !o.cfg.EnableZoneTransfer || o.tools.dns == nil || len(nameservers) == 0 || ctx.Err() != nil {
		return
	}
	// A hard-excluded zone is refused before the work claim and the goroutine, so no
	// transfer is attempted, no claim is set, and the denial is audited as an
	// exclusion rather than a transfer failure. The nameserver name and resolved
	// address boundaries are enforced inside the tool's ZoneTransfer.
	if excluded, reason := o.gate.excludedHost(domain); excluded {
		normalized, err := scopecheck.NormalizeHost(domain)
		if err != nil {
			normalized = domain
		}
		o.emitActiveExclusion(ctx, events.ActiveTargetDomain, normalized, reason)
		return
	}
	if !o.targets.claim(workZoneTransfer, domain) {
		return
	}

	ctx = tooleventlog.WithScan(ctx, o.scanID, string(events.PhaseActive))
	o.wg.Add(1)
	go func(ns []string) {
		defer o.wg.Done()
		select {
		case o.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-o.sem }()
		callCtx := o.withActiveExclusionAudit(ctx)
		callCtx = tooleventlog.WithCorrID(tooleventlog.WithTarget(callCtx, domain), newToolCorrID(o.scanID, sourceDnsinfo, domain+"|axfr"))
		if server, records := o.tools.dns.ZoneTransfer(callCtx, domain, ns, o.gate.exclusionsSnapshot()); len(records) > 0 {
			o.publish(callCtx, translate.ZoneTransfer(domain, server, records, o.scanID, causationID, tooleventlog.CorrIDFrom(callCtx)))
		}
	}(slices.Clone(nameservers))
}

// spawnAsn registers each newly seen IP in ipEvents (emit/ASN dedup), schedules the
// active host scan for every one of them (new or already seen - scheduleHostScan's
// own scannedIPs dedup decides whether a scan is actually needed, so a provider
// result that registered an IP first cannot suppress a later DNS-confirmed scan of
// the same address), and runs the ASN lookup for the newly seen IPs.
//
// An address whose only association here is an excluded domain is registered and ASN-
// enriched (both passive) but is neither DNS-confirmed nor scheduled for a scan: a
// name the engagement excluded must not admit the address it resolved to. A later
// allowed association of the same address still confirms and scans it (unless the
// address itself is excluded), so a shared address stays reachable through its
// non-excluded name. The excluded association is audited here as well as by the
// domain scheduler because a portscan-only profile never calls the latter; the gate
// deduplicates the two paths when both are enabled.
func (o *Orchestrator) spawnAsn(ctx context.Context, ipEvents []events.IPAddressDiscovered) {
	newIPs := o.targets.registerIPs(ipEvents)

	for _, ipe := range ipEvents {
		if o.domainHardExcluded(ipe.Domain) {
			// This association only denies active work when a per-IP tool could
			// consume it. Passive-only runs retain evidence without active audit.
			if o.cfg.EnableActive && o.hostToolsEnabled() {
				o.rejectExcludedDomain(ctx, ipe.Domain)
			}
			continue
		}
		o.providers.confirmDNS(ipe.IP)
		o.scheduleHostScan(ctx, ipe.IP, ipe.EventID)
	}

	o.lookupASNs(ctx, newIPs)
}

// ipHardExcluded reports whether ip matches a hard IP/CIDR exclusion, emitting the
// active-phase exclusion audit once when it does. It is the single per-address
// boundary every scan path (DNS-confirmed, provider) consults before opening
// a target socket, so the deny wins over approval, corroboration, and budget. A
// malformed address is not excluded here; the normalizing scan path rejects it on its
// own terms.
func (o *Orchestrator) ipHardExcluded(ctx context.Context, ip string) bool {
	normalized, err := scopecheck.NormalizeHost(ip)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(normalized)
	if err != nil {
		return false
	}
	if excluded, reason := o.gate.excludedAddr(addr); excluded {
		o.emitActiveExclusion(ctx, events.ActiveTargetIP, addr.Unmap().String(), reason)
		return true
	}
	return false
}

// domainHardExcluded reports whether name matches a hard domain exclusion without
// emitting an audit. An empty or malformed name is not excluded.
func (o *Orchestrator) domainHardExcluded(name string) bool {
	if name == "" {
		return false
	}
	excluded, _ := o.gate.excludedHost(name)
	return excluded
}

// rejectExcludedDomain reports and audits a hard domain exclusion. Admission paths
// that can suppress active work without reaching scheduleDomainProbe use this helper;
// recordActiveExclusion keeps the audit at one event when both paths see the denial.
func (o *Orchestrator) rejectExcludedDomain(ctx context.Context, name string) bool {
	if name == "" {
		return false
	}
	normalized, err := scopecheck.NormalizeHost(name)
	if err != nil {
		return false
	}
	if excluded, reason := o.gate.excludedHost(normalized); excluded {
		o.emitActiveExclusion(ctx, events.ActiveTargetDomain, normalized, reason)
		return true
	}
	return false
}

// lookupASNs runs the ASN lookup for each IP in newIPs in a child goroutine that
// acquires its own sem slot (never a second synchronous slot). wg.Add is done here
// in the parent, before its own wg.Done, so the child is counted against the single
// end-of-run barrier. It is a no-op when there is nothing new to look up or no ASN
// client is configured.
func (o *Orchestrator) lookupASNs(ctx context.Context, newIPs []events.IPAddressDiscovered) {
	if len(newIPs) == 0 || o.tools.asn == nil {
		return
	}

	// The caller runs inside a goroutine that already holds an o.sem slot (spawnDns
	// for the DNS path, the provider spawn goroutines for the provider path). The
	// ASN lookup therefore acquires its own slot inside this child goroutine (not
	// synchronously here) so the chain never holds two slots at once - that would
	// deadlock at a low MaxConcurrency.
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		select {
		case o.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-o.sem }()

		for _, ipe := range newIPs {
			if ctx.Err() != nil {
				return
			}
			// Each IP's ASN lookup is its own tool call, so it gets its own corrID
			// rather than inheriting the parent call's corrID from the parent context.
			callCtx := tooleventlog.WithCorrID(tooleventlog.WithTarget(ctx, ipe.IP), newToolCorrID(o.scanID, sourceAsn, ipe.IP))
			record, err := o.tools.asn.Lookup(callCtx, ipe.IP)
			if err != nil {
				continue
			}
			o.recordIPNetblock(ipe.IP, ipe.Confidence != events.ConfidenceInferred, record.Prefix)
			o.publish(callCtx, translate.Netblock(record, o.scanID, ipe.EventID, tooleventlog.CorrIDFrom(callCtx)))
		}
	}()
}

// scheduleHostScan approves a newly discovered IP for the active per-IP work and
// starts the part of it that streams (port scan plus per-port HTTP probe). It is the
// parallel-model replacement for the old active-phase IP sweep: the scan starts as
// soon as the IP lands instead of after all discovery finishes. It does nothing when
// the active phase is disabled or no per-IP tool is configured. Provider-only IPs
// reach this method only after handleProviderHost has approved their policy and
// evidence; DNS-confirmed IPs call it directly.
//
// Approval and execution are deliberately separate. Every gate below (provider-only,
// per-IP dedup, active-host budget) decides whether the target may be probed at all;
// each enabled per-IP tool then acts on that one decision. The terminal GoScans
// substage only records the approved address here and assesses it once the streaming
// workers drain, which is why an approved IP is captured even when the port scanner
// is disabled, and why sending it to both tools costs one budget unit rather than
// two: the budget guards targets, not implementations.
//
// Concurrency: the caller (spawnAsn, running inside spawnDns's goroutine, or
// ingestProviderHosts's spawn goroutine) already holds an o.sem slot, so the child
// acquires its own slot rather than this taking one synchronously - holding two
// would deadlock at a low MaxConcurrency. wg.Add runs in the caller so the child is
// counted before the caller's wg.Done.
func (o *Orchestrator) scheduleHostScan(ctx context.Context, ip, causationID string) {
	if !o.cfg.EnableActive || !o.hostToolsEnabled() {
		return
	}
	if ctx.Err() != nil {
		return
	}
	normalizedIP, err := scopecheck.NormalizeHost(ip)
	if err != nil {
		return
	}
	ip = normalizedIP
	// A hard IP/CIDR exclusion wins over every downstream gate: it is checked before
	// the scan claim and the active-host budget, so an excluded address sets no claim,
	// reserves no budget, receives no approval, and enters no GoScans target list.
	if o.ipHardExcluded(ctx, ip) {
		return
	}
	// scannedIPs is the scan dedup, deliberately separate from seenIPs (the emit/ASN
	// dedup): an IP can be registered by one source and scanned via a call from
	// another, so the scan itself must dedup on "already scanned", not "already
	// seen". Checked (and set) before the budget so a duplicate call never consumes
	// active-host budget.
	if !o.targets.claim(workHostScan, ip) {
		return
	}
	// The active-host budget caps the combined active sweep, per-domain probes and
	// per-IP scans alike. A large estate can resolve to many addresses, so the per-IP
	// scan is gated here too, not just the per-domain probe, and both spend from one
	// counter for consistent accounting.
	if !o.takeActiveBudget(ctx) {
		return
	}
	approvalSource := "provider host policy"
	if o.providers.isDNSConfirmed(ip) {
		approvalSource = "DNS-confirmed address"
	}
	o.gate.approveIP(ip, approvalSource)
	o.emitActiveTargetApproval(ctx, events.ActiveTargetIP, ip, -1, approvalSource, causationID)
	ctx, err = scopecheck.WithOrigin(ctx, ip, -1)
	if err != nil {
		return
	}
	// Re-stamp the active phase so the scan's tool events are tagged active, not the
	// passive phase the discovery context carries.
	ctx = tooleventlog.WithScan(ctx, o.scanID, string(events.PhaseActive))

	// One approval, every enabled per-IP tool. The terminal substage records the
	// address now and assesses it after the streaming work drains.
	o.captureGoScansTarget(ctx, ip, causationID)

	if o.tools.portscan == nil {
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
		select {
		case o.portScanSem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-o.portScanSem }()
		o.scanHost(ctx, ip, causationID)
	}()
}

// hostToolsEnabled reports whether any per-IP tool is configured, so an approved
// address is only recorded and only charged to the budget when something will
// actually probe it. The port scanner and the terminal GoScans substage are
// independent: either one alone is reason enough to approve a host.
func (o *Orchestrator) hostToolsEnabled() bool {
	return o.tools.portscan != nil || o.cfg.EnableGoScans
}

// scheduleDomainProbe schedules the active per-domain probes (https TLS posture,
// smtp STARTTLS, web-info, wappalyzer) for a domain whose passive DNS lookup just
// completed. It
// is the parallel-model replacement for the old active-phase domain sweep: the
// probe starts as soon as the domain's reachability signals are recorded rather
// than after all discovery finishes. The scope and budget gates are evaluated here,
// synchronously, so the active-host budget is consumed in arrival (DNS-completion)
// order - roughly shallowest-first, since the crawler discovers breadth-first. It
// does nothing when the active phase is disabled or no per-domain probe tool is
// configured.
//
// Concurrency: see scheduleHostScan. The caller (spawnDns's goroutine) holds an
// o.sem slot; the child acquires its own, so this never blocks holding one.
func (o *Orchestrator) scheduleDomainProbe(ctx context.Context, domain, causationID string) {
	if !o.cfg.EnableActive {
		return
	}
	// Each per-domain tool is independent: any one of them being configured is reason
	// enough to schedule, and none of them reads another's state.
	if o.tools.https == nil && o.tools.smtp == nil && o.tools.webinfo == nil && o.tools.wappalyzer == nil {
		return
	}
	if ctx.Err() != nil {
		return
	}
	normalizedDomain, err := scopecheck.NormalizeHost(domain)
	if err != nil {
		return
	}
	// A hard domain exclusion is checked before the in-scope and depth gates so the
	// denial is audited as an exclusion (with the matched rule), not as an ordinary
	// out-of-scope schedule skip, and so it wins over any include membership.
	if excluded, reason := o.gate.excludedHost(normalizedDomain); excluded {
		o.emitActiveExclusion(ctx, events.ActiveTargetDomain, normalizedDomain, reason)
		return
	}
	if !o.inScopeForActive(ctx, domain) {
		return
	}
	if !o.takeActiveBudget(ctx) {
		return
	}
	depth, _ := o.targets.depth(domain)
	o.gate.approveDomain(normalizedDomain, depth)
	o.emitActiveTargetApproval(ctx, events.ActiveTargetDomain, normalizedDomain, depth, "active domain scheduler", causationID)
	ctx, err = scopecheck.WithOrigin(ctx, normalizedDomain, depth)
	if err != nil {
		return
	}
	// Re-stamp the active phase so the probe's tool events are tagged active.
	ctx = tooleventlog.WithScan(ctx, o.scanID, string(events.PhaseActive))
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		select {
		case o.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-o.sem }()
		o.probeDomain(ctx, domain, causationID)
	}()
}

// emitActiveTargetApproval persists the positive authorization decision before any
// target-facing tool starts, so the stream records what was allowed to receive
// traffic and why, separately from what was merely discovered.
func (o *Orchestrator) emitActiveTargetApproval(ctx context.Context, kind events.ActiveTargetKind, target string, depth int, source, causationID string) {
	at := time.Now()
	e := events.ActiveTargetApproved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			CausationID:     causationID,
			Source:          "active-scheduler",
			Phase:           events.PhaseActive,
			Category:        events.CategoryLifecycle,
			ObservationKind: events.ObservationKindLifecycle,
			CapturedAt:      at,
		},
		Target: target, Kind: kind, Depth: depth, AdmissionSource: source,
	}
	e.EventID = events.NewEventID(at, e)
	o.publish(ctx, []events.DomainEvent{e})
}
