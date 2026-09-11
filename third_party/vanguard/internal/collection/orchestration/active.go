package orchestration

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/translate"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/httpprobe"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/portscan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/smtp"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/wappalyzer"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// portScanner is the port-scanning capability scanHost needs: a full scan plus a
// reachability tiebreaker for the zero-open case. The concrete implementation is
// *portscan.Client; the interface is a seam so the active-phase reachability logic
// can be exercised with a fake.
type portScanner interface {
	Scan(ctx context.Context, ip string, ports []int) ([]portscan.OpenPort, error)
	Reachable(ctx context.Context, ip string, ports []int) bool
	// ScanUDP is the sibling UDP pass. It is part of the same capability rather
	// than a second tool: it reuses the port scanner's source, tool log, target
	// admission, host slot, and budget. It is only called when the profile enabled
	// it, so a scanner whose UDP block is off is never asked for one.
	ScanUDP(ctx context.Context, ip string, ports []int) (*portscan.UDPResult, error)
}

// smtpProber is the SMTP STARTTLS probing capability probeDomain needs. The
// concrete implementation is *smtp.Client; the interface is a seam so the
// active-phase egress-gap logic can be exercised with a fake.
type smtpProber interface {
	Probe(ctx context.Context, domain string) (*smtp.Result, error)
}

// wappalyzerProber is the web-technology fingerprinting capability probeDomain
// needs. The concrete implementation is *wappalyzer.Client; the interface is a seam
// so the scheduling and translation paths can be exercised without network.
type wappalyzerProber interface {
	Probe(ctx context.Context, domain string) (*wappalyzer.Result, error)
}

// scanHost port-scans a single IP, emits a ServiceDiscovered per open port, and
// for HTTP-ish ports probes the endpoint and emits the HTTP and technology
// events. CausationID links a service back to its IP and an endpoint back to its
// service.
func (o *Orchestrator) scanHost(ctx context.Context, ip, causationID string) {
	if o.tools.portscan == nil {
		return
	}
	if _, ok := scopecheck.OriginFrom(ctx); !ok {
		originCtx, err := scopecheck.WithOrigin(ctx, ip, -1)
		if err != nil {
			return
		}
		ctx = originCtx
	}
	ctx = o.withActiveExclusionAudit(ctx)
	// An IPv6 host is unreachable from an IPv4-only scanner: naabu cannot tell a
	// closed port from an unreachable one, so "0 open" would masquerade as a clean
	// scan. Skip it and record the coverage gap explicitly instead.
	if isIPv6(ip) && !o.ipv6Usable {
		o.emitIPReachability(ctx, ip, events.ReachabilityUnreachableIPv6, "IPv6-only and the scanner has no IPv6 route")
		o.emitCoverageIssue(ctx, sourcePortscan, ip,
			fmt.Sprintf("%s is IPv6-only and the scanner has no IPv6 route; port scan skipped (coverage gap, not a clean result)", ip))
		return
	}
	ctx = tooleventlog.WithTarget(ctx, ip)

	// The two transports are sibling passes over one admitted host, run
	// sequentially inside the host's single concurrency slot and under the host's
	// deadline. The UDP pass is not a follow-up to the TCP one: it runs whether or
	// not a TCP port answered and whether or not the TCP pass failed, because a
	// host that ignores every TCP probe can still answer a UDP one. Only a
	// cancelled context or a scope refusal stops it, and both are decided inside
	// the pass itself. Each pass takes its own correlation id, so their tool
	// accounting cannot collide.
	tcp := o.scanHostTCP(ctx, ip)
	udp := o.scanHostUDP(ctx, ip)

	// The UDP pass's own evidence is published before any reachability decision.
	// A confirmed service and an ambiguous port are results of that pass, so they
	// must not depend on what the other transport concluded: a host whose TCP pass
	// failed still owes its UDP coverage to the stream.
	o.publishUDPPass(ctx, ip, causationID, udp)

	// Reachability is decided only after every enabled pass has finished. A
	// positive answer on either transport proves the host is there; UDP silence
	// proves nothing and must never erase a positive from the other transport.
	if !tcp.conclusive && !udp.conclusive {
		// A pass that failed produced no verdict about the target, only about the
		// scanner, and that is already reported as a health event. Claiming the host
		// is unreachable on the strength of a broken pass would turn a local failure
		// into a statement about the customer's estate.
		if !tcp.failed && !udp.failed {
			o.emitIPReachability(ctx, ip, events.ReachabilityUnreachableNoResponse, unreachableReason(udp))
			o.emitCoverageIssue(ctx, sourcePortscan, ip,
				fmt.Sprintf("%s answered no probe on any enabled transport (%s); the active scan is a coverage gap, not a clean result",
					ip, coverageDetail(tcp, udp)))
		}
		return
	}
	// A pass reached the host (whether or not any port was open), so stamp the IP
	// asset reachable - a definite signal, distinct from the unknown default a
	// passive-only IP carries.
	o.emitIPReachability(ctx, ip, events.ReachabilityReachable, "")

	// Everything below is the TCP follow-up chain and stays TCP-only: a UDP result
	// never seeds an HTTP probe, never enters the GoScans input set, and never
	// contributes to the host OS guess. It is gated on the TCP pass's own verdict
	// rather than the combined one, so a host proven reachable by UDP alone does
	// not turn an inconclusive TCP sweep into a definitive one.
	if !tcp.conclusive {
		return
	}
	scanCtx := tooleventlog.WithCorrID(ctx, tcp.corrID)
	// Recorded only here, past every early return, so the set is a definitive sweep
	// result rather than a partial one: a scan that errored or a host that answered
	// no TCP probe has already returned above, and must stay absent from the map.
	o.recordGoScansPorts(ip, tcp.openPorts)
	o.emitHostOSGuess(ctx, ip, causationID, tcp.openPorts)
	for i := range tcp.openPorts {
		op := &tcp.openPorts[i]
		svc := translate.Service(ip, op, o.scanID, causationID, tcp.corrID)
		o.publish(scanCtx, []events.DomainEvent{svc})

		if o.tools.httpprobe == nil {
			continue
		}
		// Only probe ports that plausibly speak HTTP. Ports like 21, 22, 25, 110,
		// 143, 3306, 6379 are dialled by the port scan but are not HTTP services, so
		// an HTTP GET against them is a guaranteed failure (and wasted time). The
		// ServiceDiscovered above is still emitted for every open port; only the HTTP
		// probe is gated.
		if !o.isHTTPProbePort(op.Port) {
			continue
		}
		// The probe is a distinct tool call from the port scan, so it gets its own
		// corrID. The scheme is derived from the port. The target is always a bare IP
		// literal here, so HTTPS uses an insecure dial: a valid public certificate
		// has no IP SAN and standard verification would always fail.
		url := buildURL(ip, op.Port)
		probeCtx := tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceHTTP, url))
		resp, err := o.probeEndpoint(probeCtx, url, op.Port)
		if resp != nil {
			o.publishHTTPRedirects(probeCtx, resp.RedirectTrail, svc.EventID, sourceHTTP, tooleventlog.CorrIDFrom(probeCtx))
		}
		if err != nil {
			continue
		}
		o.publish(probeCtx, translate.HTTP(resp, o.scanID, svc.EventID, tooleventlog.CorrIDFrom(probeCtx)))
	}
}

// hostPass is what one transport's pass concluded about one host. The two
// transports produce the same shape so the reachability decision can be made from
// both without knowing which is which.
type hostPass struct {
	// ran reports that the pass was enabled and executed. A pass that did not run
	// is not evidence of anything, which is what lets a consumer tell "no
	// conclusive reply" from "that transport was never attempted".
	ran bool
	// failed reports that the pass lost work it was asked to do. It is a statement
	// about the scanner, not about the target, and the health event that
	// accompanies it is the authority on the loss.
	failed bool
	// conclusive reports that the host demonstrably answered this transport. Only a
	// positive answer sets it: silence never does, on either transport.
	conclusive bool
	// corrID is the pass's own correlation id, so its tool events and the domain
	// events derived from them join, and so the two passes never share a span.
	corrID string
	// openPorts are the TCP pass's open ports, empty for a UDP pass.
	openPorts []portscan.OpenPort
	// udp is the UDP pass's full transport result, nil for a TCP pass and for a UDP
	// pass that produced no output at all.
	udp *portscan.UDPResult
}

// scanHostTCP runs the host's TCP pass and reports what it concluded.
//
// The connect scan cannot tell a closed port (the host answered with a RST) from
// a filtered one (no answer), so "zero open ports" is ambiguous: a clean result
// for a reachable host, a coverage gap for one that never answered (down, or
// ingress/egress filtered - common when scanning from a cloud VM). When nothing is
// open it asks the reachability tiebreaker, so the ambiguity is resolved rather
// than stamped as "reachable, nothing found".
func (o *Orchestrator) scanHostTCP(ctx context.Context, ip string) hostPass {
	corrID := newToolCorrID(o.scanID, sourcePortscan, ip)
	scanCtx := tooleventlog.WithCorrID(ctx, corrID)
	openPorts, err := o.tools.portscan.Scan(scanCtx, ip, o.cfg.ActivePorts)
	if err != nil {
		return hostPass{ran: true, failed: true, corrID: corrID}
	}
	return hostPass{
		ran:        true,
		corrID:     corrID,
		openPorts:  openPorts,
		conclusive: len(openPorts) > 0 || o.tools.portscan.Reachable(scanCtx, ip, o.cfg.ActivePorts),
	}
}

// scanHostUDP runs the host's UDP pass and reports what it concluded. A profile
// that did not enable UDP runs nothing here and returns a pass that never ran, so
// the TCP flow is exactly what it was before UDP existed.
//
// Only a confirmed response or an ICMP port-unreachable makes the pass
// conclusive: an answering service proves the host is there, and so does a host
// that actively refused a port. Silence (open|filtered) proves nothing, and a
// filtered verdict describes something in the path rather than the host.
//
// A pass that returned evidence and then failed keeps both facts: its result is
// still published, and its failure is still reported by the health event the tool
// emitted.
func (o *Orchestrator) scanHostUDP(ctx context.Context, ip string) hostPass {
	if !o.cfg.EnablePortScanUDP || len(o.cfg.ActiveUDPPorts) == 0 {
		return hostPass{}
	}
	corrID := newToolCorrID(o.scanID, sourcePortscan, udpCorrTarget(ip))
	scanCtx := tooleventlog.WithCorrID(ctx, corrID)
	result, err := o.tools.portscan.ScanUDP(scanCtx, ip, o.cfg.ActiveUDPPorts)
	pass := hostPass{ran: true, failed: err != nil, corrID: corrID, udp: result}
	if result != nil {
		// StateCounts, not the individual slices: nmap folds a run of same-state
		// ports into an aggregate group, so a host that refused every probe can
		// arrive as one collapsed "closed" count with an empty Closed slice. Reading
		// only the slices would call that host unreachable while the result holds an
		// ICMP port-unreachable.
		counts := result.StateCounts()
		pass.conclusive = counts[portscan.UDPOpen] > 0 || counts[portscan.UDPClosed] > 0
	}
	return pass
}

// udpCorrTarget distinguishes the UDP pass's correlation id from the TCP pass's
// on the same host, so a replay that counts calls per host sees two sequential
// passes rather than one call reported twice.
func udpCorrTarget(ip string) string { return "udp|" + ip }

// publishUDPPass turns a UDP pass into collection events: one ServiceDiscovered
// per confirmed service, and one coverage issue per host for the ports whose
// state stayed ambiguous.
//
// Only a confirmed response becomes a service. open|filtered is silence and
// carries no evidence that anything is listening, so publishing it would invent a
// service; closed and filtered are the opposite claim and are not services either.
// Their reasons stay in the tool stream, and the count of ambiguous ports becomes
// coverage so a reader can see what the pass could not settle.
//
// Nothing here starts a follow-up. A UDP port never becomes an HTTP probe, never
// joins the GoScans input set, and never merges into the TCP service of the same
// number: TCP/53 and UDP/53 are two services, and every consumer opts into UDP
// explicitly.
func (o *Orchestrator) publishUDPPass(ctx context.Context, ip, causationID string, pass hostPass) {
	if pass.udp == nil {
		return
	}
	scanCtx := tooleventlog.WithCorrID(ctx, pass.corrID)
	for i := range pass.udp.Open {
		op := &pass.udp.Open[i]
		svc := translate.Service(ip, op, o.scanID, causationID, pass.corrID)
		o.publish(scanCtx, []events.DomainEvent{svc})
	}
	counts := pass.udp.StateCounts()
	if ambiguous := counts[portscan.UDPOpenFiltered]; ambiguous > 0 {
		o.emitCoverageIssueFor(scanCtx, sourcePortscan, udpCorrTarget(ip), ip,
			fmt.Sprintf("%s left %d of %d UDP port(s) open|filtered (probe sent, nothing came back); "+
				"a silent UDP port is neither a service nor a clean negative",
				ip, ambiguous, pass.udp.RequestedPorts))
	}
}

// unreachableReason renders the verdict's reason text. With UDP disabled it is
// exactly the TCP-only sentence, because nothing about that case changed; with
// UDP enabled it names both transports, because "no conclusive reply on either"
// and "UDP was never attempted" are different facts and a consumer must be able
// to tell them apart.
func unreachableReason(udp hostPass) string {
	if !udp.ran {
		return "no TCP port answered (every probe timed out); host is down or filtered"
	}
	return "no TCP port answered and no UDP port replied; host is down or filtered (UDP silence alone proves nothing)"
}

// coverageDetail names what each enabled transport actually observed, so the
// coverage issue records which passes were attempted rather than implying one.
func coverageDetail(tcp, udp hostPass) string {
	parts := make([]string, 0, 2)
	if tcp.ran {
		parts = append(parts, "tcp: every port timed out")
	}
	switch {
	case !udp.ran:
		parts = append(parts, "udp: not attempted")
	case udp.udp != nil:
		parts = append(parts, fmt.Sprintf("udp: %d port(s) silent, none confirmed",
			udp.udp.StateCounts()[portscan.UDPOpenFiltered]))
	default:
		parts = append(parts, "udp: no result")
	}
	return strings.Join(parts, "; ")
}

// probeDomain runs the enabled per-domain active tools against one domain and
// publishes the translated events.
func (o *Orchestrator) probeDomain(ctx context.Context, domain, causationID string) {
	if _, ok := scopecheck.OriginFrom(ctx); !ok {
		depth, _ := o.targets.depth(domain)
		originCtx, err := scopecheck.WithOrigin(ctx, domain, depth)
		if err != nil {
			return
		}
		ctx = originCtx
	}
	o.probeDomainWithOrigin(ctx, domain, causationID)
}

// probeDomainWithOrigin runs domain tools after the approved request origin has
// been attached by the scheduler or the direct-call guard above.
func (o *Orchestrator) probeDomainWithOrigin(ctx context.Context, domain, causationID string) {
	ctx = o.withActiveExclusionAudit(ctx)
	ctx = tooleventlog.WithTarget(ctx, domain)

	// The web probes target the domain's own address. If it resolved only to IPv6 and
	// the scanner has no IPv6 route, they cannot connect and would record an empty
	// posture indistinguishable from a clean one. Skip them with a coverage Issue per
	// enabled tool, under that tool's own source: a gap is only honest if it names
	// the tool that did not run, and an operator filtering the stream by source must
	// see the skip for the tool they enabled. The smtp probe is not skipped: it
	// targets the MX hosts, which resolve to their own (often IPv4) addresses.
	reachByOwnAddr := !o.isUnreachableIPv6Only(domain)
	if !reachByOwnAddr {
		o.emitWebProbeIPv6Skips(ctx, domain)
	}

	// A discovered name that resolved to no address at all (NXDOMAIN - common for
	// cert-SAN and subfinder guesses) cannot be dialled; the https/webinfo probes
	// fail "no such host". Skip them. Unlike the IPv6 skip this is a definite
	// negative (the name does not resolve), not a coverage gap, so no Issue is
	// emitted. smtp is unaffected (gated on MX below), so an MX-only mail domain
	// with no A/AAAA is still probed.
	runWebProbes := reachByOwnAddr && o.domainResolvable(domain)

	if runWebProbes && o.tools.https != nil {
		callCtx := tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceHTTPS, domain))
		result, err := o.tools.https.Probe(callCtx, domain)
		if result != nil {
			o.publishHTTPRedirects(callCtx, result.RedirectTrail, causationID, sourceHTTPS, tooleventlog.CorrIDFrom(callCtx))
		}
		if err == nil {
			o.publish(callCtx, translate.TLSPosture(domain, result, o.scanID, causationID, tooleventlog.CorrIDFrom(callCtx)))
			o.publish(callCtx, translate.HTTPSCert(domain, result, o.scanID, causationID))
		}
	}
	// The smtp STARTTLS probe targets the domain's MX hosts. A domain with no MX
	// handles no mail, so the probe would fail immediately ("no MX records") - pure
	// waste that also buries the real mail domains' results. Skip it. Unlike the
	// IPv6 skip this is a definite negative (the name is not a mail host), not a
	// coverage gap, so no Issue is emitted.
	if o.tools.smtp != nil && o.domainHasMailRoute(domain) {
		o.probeMailPosture(ctx, domain, causationID)
	}
	if runWebProbes && o.tools.webinfo != nil {
		callCtx := tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceWebinfo, domain))
		result, err := o.tools.webinfo.Probe(callCtx, domain)
		if result != nil {
			o.publishHTTPRedirects(callCtx, result.RedirectTrail, causationID, sourceWebinfo, tooleventlog.CorrIDFrom(callCtx))
		}
		if err == nil {
			o.publish(callCtx, translate.Webinfo(result, o.scanID, causationID, tooleventlog.CorrIDFrom(callCtx)))
		}
	}
	// Wappalyzer runs on its own client alone, once per domain, under the same gates
	// as its peers. It reads no other tool's result and no other tool's flag, so it
	// works with every other HTTP tool disabled and duplicates nothing when they are
	// enabled. A failed probe publishes nothing - no endpoint event may exist for a
	// response this tool never read - and does not affect the tools above or below.
	if runWebProbes && o.tools.wappalyzer != nil {
		callCtx := tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceWappalyzer, domain))
		result, err := o.tools.wappalyzer.Probe(callCtx, domain)
		if result != nil {
			o.publishHTTPRedirects(callCtx, result.RedirectTrail, causationID, sourceWappalyzer, tooleventlog.CorrIDFrom(callCtx))
		}
		if err == nil {
			o.publish(callCtx, translate.Wappalyzer(result, o.scanID, causationID, tooleventlog.CorrIDFrom(callCtx)))
		}
	}
}

// probeMailPosture runs the SMTP STARTTLS probe against a domain's MX hosts and
// publishes the translated posture. It also surfaces two orthogonal decisions the
// bare result cannot: an all-MX-excluded probe as an active-phase scope exclusion
// (the mail posture was withheld by policy, not by the network), and an all-MX-
// timed-out probe as a coverage gap (outbound port 25 is likely blocked from this
// runner). Policy-rejected MX hosts are already filtered out of the translated
// posture and never feed the egress signal.
func (o *Orchestrator) probeMailPosture(ctx context.Context, domain, causationID string) {
	callCtx := tooleventlog.WithCorrID(ctx, newToolCorrID(o.scanID, sourceSMTP, domain))
	result, err := o.tools.smtp.Probe(callCtx, domain)
	if err != nil {
		return
	}
	if result.PolicyLimited() {
		o.emitActiveExclusion(ctx, events.ActiveTargetDomain, domain,
			fmt.Sprintf("every MX host of %s is excluded; SMTP posture withheld", domain))
	}
	if result.EgressLikelyBlocked() {
		o.emitCoverageIssue(ctx, sourceSMTP, domain,
			fmt.Sprintf("%s: every MX host timed out on TCP/25, so outbound port 25 is likely blocked from this runner; MX STARTTLS/TLS posture not collected (coverage gap, not a clean result)", domain))
	}
	mxEvents := translate.MxTls(domain, result, o.scanID, causationID, tooleventlog.CorrIDFrom(callCtx))
	o.publish(callCtx, mxEvents)
	o.publish(callCtx, translate.SmtpCerts(result, o.scanID, firstEventID(mxEvents)))
}

// emitWebProbeIPv6Skips records one coverage Issue per enabled web probe that cannot
// run because the domain resolved only to IPv6 and the scanner has no route. Each
// issue is emitted under its own tool's source, so "which tool was enabled but did
// not run" is answerable from the stream instead of being buried under one tool's
// label.
func (o *Orchestrator) emitWebProbeIPv6Skips(ctx context.Context, domain string) {
	skips := []struct {
		source  string
		enabled bool
	}{
		{sourceHTTPS, o.tools.https != nil},
		{sourceWebinfo, o.tools.webinfo != nil},
		{sourceWappalyzer, o.tools.wappalyzer != nil},
	}
	for _, s := range skips {
		if !s.enabled {
			continue
		}
		o.emitCoverageIssue(ctx, s.source, domain,
			fmt.Sprintf("%s resolved only to IPv6 and the scanner has no IPv6 route; %s probe skipped (coverage gap, not a clean result)",
				domain, s.source))
	}
}

// domainHasMailRoute reports whether the smtp probe should run for domain. The
// gate is the MX signal dnsinfo recorded during the passive phase: a domain with
// no MX handles no mail and the STARTTLS probe cannot succeed. When dnsinfo is
// disabled the signal is unavailable, so the probe is not gated and falls back to
// its own MX lookup (preserving prior behaviour).
func (o *Orchestrator) domainHasMailRoute(domain string) bool {
	if o.tools.dns == nil {
		return true
	}
	return o.targets.signalsFor(domain).hasMX
}

// domainResolvable reports whether the https/webinfo probes should run for domain.
// The gate is whether dnsinfo recorded any address (A or AAAA) for it: a name that
// resolved to nothing (NXDOMAIN) cannot be dialled and the probe fails "no such
// host". When dnsinfo is disabled the signal is unavailable, so the probe is not
// gated (it falls back to resolving and dialling itself), preserving prior
// behaviour. Mirrors domainHasMailRoute.
func (o *Orchestrator) domainResolvable(domain string) bool {
	if o.tools.dns == nil {
		return true
	}
	signals := o.targets.signalsFor(domain)
	return signals.hasIPv4 || signals.hasIPv6
}

// isUnreachableIPv6Only reports whether domain resolved only to IPv6 while the
// scanner has no IPv6 route, so a probe against the domain's own address cannot
// connect. A domain with any IPv4 address is not treated as unreachable here; a
// domain with no recorded address at all is handled separately by domainResolvable
// (a definite NXDOMAIN negative, not an IPv6 coverage gap).
func (o *Orchestrator) isUnreachableIPv6Only(domain string) bool {
	if o.ipv6Usable {
		return false
	}
	signals := o.targets.signalsFor(domain)
	return signals.hasIPv6 && !signals.hasIPv4
}

// emitCoverageIssue publishes a low-severity, active-phase IssueObserved recording
// that a target could not be probed, so an unreachable host is an explicit gap in
// the stream rather than a silent absence. It dedups per target.
func (o *Orchestrator) emitCoverageIssue(ctx context.Context, source, target, msg string) {
	o.emitCoverageIssueFor(ctx, source, target, target, msg)
}

// emitCoverageIssueFor is emitCoverageIssue with the dedup key separated from the
// recorded target. One tool can observe more than one kind of gap on one host -
// the TCP sweep and the UDP pass both report their own - and folding them onto a
// single key would silently drop whichever arrived second.
func (o *Orchestrator) emitCoverageIssueFor(ctx context.Context, source, key, target, msg string) {
	if !o.targets.claim(workCoverageIssue, source+"|"+key) {
		return
	}

	at := time.Now()
	issue := events.IssueObserved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			Source:          source,
			Phase:           events.PhaseActive,
			Category:        events.CategoryIssue,
			Severity:        events.SeverityLow,
			ObservationKind: events.ObservationKindOperational,
			CapturedAt:      at,
		},
		Query: target,
		Error: msg,
	}
	issue.EventID = events.NewEventID(at, issue)
	o.publish(ctx, []events.DomainEvent{issue})
}

// emitIPReachability publishes an IPReachabilityObserved stamping the active
// phase's reachability verdict for ip, so the IP asset carries an explicit signal
// (reachable / unreachable IPv6 / unreachable no-response) rather than leaving the
// report to infer it from a coverage issue. The typed state is carried on the event
// so the projection records the exact case without guessing from the reason text.
// scanHost runs once per unique IP, so no dedup is needed.
func (o *Orchestrator) emitIPReachability(ctx context.Context, ip, state, reason string) {
	at := time.Now()
	evt := events.IPReachabilityObserved{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			Source:          sourcePortscan,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			Severity:        events.SeverityInfo,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      at,
		},
		IP:        ip,
		Reachable: state == events.ReachabilityReachable,
		State:     state,
		Reason:    reason,
	}
	evt.EventID = events.NewEventID(at, evt)
	o.publish(ctx, []events.DomainEvent{evt})
}

// emitHostOSGuess derives a host OS family from the open ports' nmap service
// ostype hints and, when one is found, publishes a HostOSGuessed stamping the IP
// asset. The guess is the OS the most open ports agree on (see hostOSGuess); it is
// deliberately coarse and inferred - nmap service-detection ostype is a weak
// signal, not a privileged -O fingerprint. causationID links it back to the IP
// that caused the scan. No event is emitted when no service exposed an OS hint.
func (o *Orchestrator) emitHostOSGuess(ctx context.Context, ip, causationID string, openPorts []portscan.OpenPort) {
	os := hostOSGuess(openPorts)
	if os == "" {
		return
	}
	at := time.Now()
	evt := events.HostOSGuessed{
		EventMeta: events.EventMeta{
			ScanID:          o.scanID,
			CausationID:     causationID,
			Source:          sourcePortscan,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			Severity:        events.SeverityInfo,
			ObservationKind: events.ObservationKindDerived,
			CapturedAt:      at,
		},
		IP:     ip,
		OS:     os,
		Method: "nmap service ostype",
	}
	evt.EventID = events.NewEventID(at, evt)
	o.publish(ctx, []events.DomainEvent{evt})
}

// hostOSGuess returns the OS family the most open ports' service ostype agree on,
// or "" when none reported one. openPorts is sorted ascending by port, so the
// first OS to reach the top count (the lowest port) breaks ties deterministically,
// keeping the guess replay-stable.
func hostOSGuess(openPorts []portscan.OpenPort) string {
	counts := make(map[string]int)
	var best string
	var bestCount int
	for i := range openPorts {
		os := strings.TrimSpace(openPorts[i].OSType)
		if os == "" {
			continue
		}
		counts[os]++
		if counts[os] > bestCount {
			best, bestCount = os, counts[os]
		}
	}
	return best
}

// hasIPv6Connectivity reports whether the scanner has a routable (global unicast,
// non-private) IPv6 address on any interface. It is a cheap, offline heuristic for
// IPv6 capability: a host with no global IPv6 address cannot reach an IPv6-only
// target. The rare false positive (an address exists but the route is dead) is
// harmless - the probe then fails and is marked unreachable by the tool result.
func hasIPv6Connectivity() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

// isIPv6 reports whether ip is a valid IPv6 (non-IPv4) address.
func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// defaultHTTPProbePorts is the allowlist of ports that plausibly speak HTTP(S).
// The active port list also includes non-HTTP services (ssh, smtp, mysql, redis,
// ...) that the port scan dials; probing those as HTTP always fails, so the HTTP
// probe is restricted to these ports. The orchestrator copies this into
// httpProbePorts at construction.
var defaultHTTPProbePorts = map[int]bool{
	80:   true, // http
	443:  true, // https
	8080: true, // http-alt
	8443: true, // https-alt
	8000: true, // http-alt
	8888: true, // http-alt
	3000: true, // common dev/app http
}

// isHTTPProbePort reports whether port should be probed over HTTP.
func (o *Orchestrator) isHTTPProbePort(port int) bool {
	return o.httpProbePorts[port]
}

// isHTTPSPort reports whether the HTTP probe should use the https scheme for port.
func isHTTPSPort(port int) bool {
	return port == 443 || port == 8443
}

// probeEndpoint runs the HTTP probe for url. For an HTTPS port the target here is
// always a bare IP literal, so it dials without certificate verification (the cert
// has no IP SAN); plaintext ports use the verifying probe.
func (o *Orchestrator) probeEndpoint(ctx context.Context, url string, port int) (*httpprobe.Response, error) {
	if isHTTPSPort(port) {
		return o.tools.httpprobe.ProbeInsecure(ctx, url)
	}
	return o.tools.httpprobe.Probe(ctx, url)
}

func buildURL(ip string, port int) string {
	scheme := schemeHTTP
	if isHTTPSPort(port) {
		scheme = schemeHTTPS
	}
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	if (scheme == schemeHTTP && port == 80) || (scheme == schemeHTTPS && port == 443) {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}
