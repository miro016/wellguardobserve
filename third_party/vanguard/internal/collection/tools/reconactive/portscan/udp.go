package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// UDPState is a port's transport-layer verdict, kept exactly as nmap reported it.
// The four states are not collapsed into open/closed anywhere in this package: a
// UDP probe that got no answer proves nothing, and a reader that cannot tell that
// from a refusal would read silence as a clean result.
type UDPState string

// The four states a UDP port can be in. Anything else is a change in nmap's output
// this code has not been reviewed against, and is an error rather than a default.
const (
	// UDPOpen is a confirmed positive response from the service. It is the only
	// state that becomes a discovered service.
	UDPOpen UDPState = "open"
	// UDPOpenFiltered is silence: the probe was sent and nothing came back. It may
	// be a service that only answers a protocol-correct payload, or a filter. It is
	// coverage, never a service and never a clean negative.
	UDPOpenFiltered UDPState = "open|filtered"
	// UDPClosed is an ICMP port-unreachable: the host answered, and nothing is
	// listening on that port. It proves the host is reachable.
	UDPClosed UDPState = "closed"
	// UDPFiltered is an explicit administrative rejection, typically an ICMP
	// prohibited message from a filter in the path.
	UDPFiltered UDPState = "filtered"
)

// UDPConfig is the UDP pass's own tuning. It is separate from the TCP fields on
// [Config] because the two are independent passes that share only a target: a UDP
// value never reinterprets a TCP one, and a client with Enabled false behaves
// exactly as it did before UDP existed.
type UDPConfig struct {
	// Enabled turns the pass on. [Client.ScanUDP] refuses to run without it, so a
	// profile that did not ask for UDP cannot get UDP traffic through a
	// programmatic call.
	Enabled bool
	// NmapPath is the absolute nmap executable collection preflight resolved and
	// proved capable of opening a raw socket. It is required when Enabled: this
	// pass never searches PATH at scan time, so the binary that was checked is the
	// binary that runs.
	NmapPath string
	// Privileged passes --privileged, as decided by the same preflight. nmap judges
	// its own privilege from its effective UID rather than from the capabilities it
	// holds, so on a host where the capability is a file capability it must be told
	// to stop asking.
	Privileged bool
	// ProbeTimeout is the per-port response wait.
	ProbeTimeout time.Duration
	// RatePerSecond caps the packet rate against one host. Host concurrency is the
	// caller's: this client paces one host.
	RatePerSecond int
	// Retries is the number of extra attempts after the first for a silent port.
	// Zero is valid and means exactly one attempt.
	Retries int
	// ServiceDetection runs nmap's version detection against answering ports.
	ServiceDetection bool
	// VersionIntensity is the version-detection intensity, 0-9.
	VersionIntensity int
	// TimingTemplate is nmap's timing template, 0-5.
	TimingTemplate int
	// HostTimeout bounds the whole pass against one host.
	HostTimeout time.Duration
	// MaxPorts caps the port list one call may probe, refused before any traffic.
	// It is the last boundary between a reviewed discovery pass and a UDP sweep.
	MaxPorts int
}

// udpEngineFunc runs one UDP pass and returns the parsed nmap run. It is the
// package's only seam onto the outside world for this transport, which is what
// lets every behaviour below be tested from recorded output.
type udpEngineFunc func(ctx context.Context, opts udpRunOptions) (*nmap.Run, error)

// validateUDPConfig fails a misconfigured UDP pass at construction rather than at
// the first target. Nothing here is defaulted: a value the profile was required to
// state must not be silently invented by the tool that consumes it.
func validateUDPConfig(cfg UDPConfig) error {
	if !cfg.Enabled {
		return nil
	}
	switch {
	case cfg.NmapPath == "":
		return errors.New("portscan: Config.UDP.NmapPath is required when UDP is enabled (preflight resolves it)")
	case cfg.ProbeTimeout <= 0:
		return errors.New("portscan: Config.UDP.ProbeTimeout must be positive")
	case cfg.RatePerSecond <= 0:
		return errors.New("portscan: Config.UDP.RatePerSecond must be positive")
	case cfg.Retries < 0:
		return errors.New("portscan: Config.UDP.Retries must be >= 0 (0 means one attempt)")
	case cfg.HostTimeout <= 0:
		return errors.New("portscan: Config.UDP.HostTimeout must be positive")
	case cfg.VersionIntensity < 0 || cfg.VersionIntensity > 9:
		return errors.New("portscan: Config.UDP.VersionIntensity must be 0-9")
	case cfg.TimingTemplate < 0 || cfg.TimingTemplate > 5:
		return errors.New("portscan: Config.UDP.TimingTemplate must be 0-5")
	case cfg.MaxPorts < 0:
		return errors.New("portscan: Config.UDP.MaxPorts must be >= 0 (0 means no tool-side cap)")
	}
	return nil
}

// UDPPortState is one non-open port and why nmap said so. The reason is kept
// because the state alone is not the evidence: "no-response" and "port-unreach"
// are different facts about a port that is not open, and only one of them proves
// the host answered at all.
type UDPPortState struct {
	// Port is the probed UDP port.
	Port int
	// State is the transport verdict.
	State UDPState
	// Reason is nmap's reason string, for example "no-response" or "port-unreach".
	Reason string
}

// UDPCollapsedPorts is a group of ports nmap reported only in aggregate. nmap
// folds a large run of same-state ports into a count rather than listing each one,
// so without this a pass could report one open port out of eight and silently lose
// the other seven. The ports are not named because nmap did not name them.
type UDPCollapsedPorts struct {
	// State is the shared transport verdict.
	State UDPState
	// Count is how many ports nmap folded into this group.
	Count int
	// Reasons are nmap's reason strings for the group, joined for display.
	Reasons string
}

// UDPResult is one host's UDP pass. Every requested port is accounted for in
// exactly one place, and the four states stay separate all the way out of the
// package: only Open is evidence of a service, and the rest is coverage.
type UDPResult struct {
	// IP is the scanned address.
	IP string
	// RequestedPorts is how many ports the caller asked for, so a reader can tell
	// a complete pass from one that ended early.
	RequestedPorts int
	// Open holds the confirmed services, sorted by port, with Protocol "udp".
	Open []OpenPort
	// OpenFiltered holds the silent ports, sorted by port.
	OpenFiltered []UDPPortState
	// Closed holds the ports the host actively said nothing listens on.
	Closed []UDPPortState
	// Filtered holds the ports something in the path rejected.
	Filtered []UDPPortState
	// Collapsed holds the groups nmap reported only as counts.
	Collapsed []UDPCollapsedPorts
	// Duration is how long the pass took.
	Duration time.Duration
}

// StateCounts returns the number of ports in each state, including the groups
// nmap collapsed. It is what an accounting event and a coverage record are built
// from, so neither has to know how nmap chose to format its output.
func (r UDPResult) StateCounts() map[UDPState]int {
	counts := map[UDPState]int{
		UDPOpen:         len(r.Open),
		UDPOpenFiltered: len(r.OpenFiltered),
		UDPClosed:       len(r.Closed),
		UDPFiltered:     len(r.Filtered),
	}
	for _, group := range r.Collapsed {
		counts[group.State] += group.Count
	}
	return counts
}

// Accounted reports how many of the requested ports the pass returned a verdict
// for. A pass that returns fewer than it requested is incomplete, whatever nmap's
// exit status was.
func (r UDPResult) Accounted() int {
	total := 0
	for _, n := range r.StateCounts() {
		total += n
	}
	return total
}

// UDPPartialError reports that a UDP pass produced evidence and then failed. It
// exists so a caller can do both honest things at once: publish the services that
// were actually confirmed, and record that the rest of the requested work was
// lost. Collapsing that into a plain error would throw away findings; collapsing
// it into success would claim coverage the pass never had.
type UDPPartialError struct {
	// IP is the host whose pass was cut short.
	IP string
	// Requested is how many ports were asked for.
	Requested int
	// Accounted is how many came back with a verdict.
	Accounted int
	// Cause is what ended the pass.
	Cause error
}

// Error describes the loss in the terms an operator needs: which host, and how
// much of the requested work survived.
func (e *UDPPartialError) Error() string {
	return fmt.Sprintf("portscan: udp scan of %s returned %d of %d ports before failing: %v",
		e.IP, e.Accounted, e.Requested, e.Cause)
}

// Unwrap exposes the underlying failure so errors.Is and errors.As still see it,
// which is what lets a caller tell a cancellation from a broken runtime.
func (e *UDPPartialError) Unwrap() error { return e.Cause }

// UDPAccountingError reports that nmap exited successfully while its parsed
// result assigns states to a different number of ports than were requested. It is
// its own failure because the run did not fail: nothing else in the pass would
// notice that a truncated or malformed document covered six of eight ports, and
// recording that as full coverage would present two unscanned ports as two ports
// that answered nothing.
type UDPAccountingError struct {
	// IP is the host whose pass does not add up.
	IP string
	// Requested is how many ports were asked for.
	Requested int
	// Accounted is how many came back with a verdict.
	Accounted int
}

// Error names the host and the shortfall (or surplus) in requested-port terms.
func (e *UDPAccountingError) Error() string {
	return fmt.Sprintf("portscan: udp scan of %s reported success but accounted for %d of %d requested ports",
		e.IP, e.Accounted, e.Requested)
}

// UDPStateError reports a port state string this code has not been reviewed
// against. It is deliberately fatal to the pass: defaulting an unknown state to
// closed would turn an nmap output change into a silent, confident lie about a
// customer's attack surface.
type UDPStateError struct {
	// IP is the host being scanned.
	IP string
	// Port is the port carrying the unrecognised state.
	Port int
	// State is the raw state string, bounded for display.
	State string
}

// Error names the unrecognised state and where it came from.
func (e *UDPStateError) Error() string {
	return fmt.Sprintf("portscan: udp scan of %s port %d returned unrecognised state %q", e.IP, e.Port, e.State)
}

// ScanUDP probes ports on ip with one direct nmap UDP pass and returns every
// port's transport state.
//
// It is a second, independent pass beside [Client.Scan], not a mode of it: it is
// never skipped because no TCP port answered, and its result never seeds a TCP
// follow-up. The caller owns host concurrency and runs the two passes
// sequentially within one host's slot; this client owns the per-host rate,
// timeouts, retries, and limits.
//
// Order of operations matters and is deliberate. The address is parsed, the scope
// authorizer is asked, and the port list is validated, all before any process
// exists: an excluded or unapproved address never reaches a socket, an argument
// list, or a child process, and is not recorded as a started scan.
//
// A pass that produced evidence and then failed returns that evidence with a
// *[UDPPartialError]. A pass that exited successfully while accounting for a
// different number of ports than were requested returns its evidence with a
// *[UDPAccountingError], because a successful exit status is not proof of
// coverage. A pass that failed outright returns a nil result and the typed error;
// nothing is fabricated. Cancellation returns the context error.
func (c *Client) ScanUDP(ctx context.Context, ip string, ports []int) (*UDPResult, error) {
	if !c.cfg.UDP.Enabled {
		err := errors.New("portscan: udp scanning is not enabled on this client")
		c.emit(ctx, UDPScanError{IP: ip, Err: err})
		return nil, err
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		err := fmt.Errorf("portscan: invalid IP address %q", ip)
		c.emit(ctx, UDPScanError{IP: ip, Err: err})
		return nil, err
	}
	// The same authorizer the TCP path consults, asked before any process exists:
	// an excluded or unapproved address never reaches a socket, an argument list,
	// or a child process, and is not recorded as a started scan.
	if err := c.checkTarget(ctx, ip); err != nil {
		return nil, err
	}
	if err := c.validateUDPPorts(ports); err != nil {
		c.emit(ctx, UDPScanError{IP: ip, Err: err})
		return nil, err
	}
	if len(ports) == 0 {
		return &UDPResult{IP: ip}, nil
	}

	c.emit(ctx, UDPScanStarted{IP: ip, Ports: len(ports)})
	started := time.Now()

	run, runErr := c.udpRun(ctx, udpRunOptions{
		NmapPath:         c.cfg.UDP.NmapPath,
		IP:               ip,
		IPv6:             parsed.To4() == nil,
		Ports:            ports,
		Privileged:       c.cfg.UDP.Privileged,
		ServiceDetection: c.cfg.UDP.ServiceDetection,
		VersionIntensity: c.cfg.UDP.VersionIntensity,
		TimingTemplate:   c.cfg.UDP.TimingTemplate,
		HostTimeout:      c.cfg.UDP.HostTimeout,
		ProbeTimeout:     c.cfg.UDP.ProbeTimeout,
		RatePerSecond:    c.cfg.UDP.RatePerSecond,
		Retries:          c.cfg.UDP.Retries,
	})

	// An interrupted pass is an interruption, not a scanner failure: the capture
	// manifest is the authority on what an interrupted run collected, so this
	// emits its terminal event and reports no health problem.
	if ctxErr := ctx.Err(); ctxErr != nil {
		c.emit(ctx, UDPScanCancelled{IP: ip, Err: ctxErr})
		return nil, ctxErr
	}

	// A pass that failed before producing any output maps to no result rather than
	// to an empty one: "nothing came back" and "every port was silent" are
	// different claims, and only the second one is coverage.
	var result *UDPResult
	if run != nil {
		mapped, mapErr := c.mapUDPRun(ctx, ip, len(ports), run)
		if mapErr != nil {
			c.emitUDPError(ctx, ip, mapErr)
			return nil, mapErr
		}
		mapped.Duration = time.Since(started)
		result = mapped
	}

	if runErr != nil {
		// Evidence first: a pass that confirmed a service and then died still found
		// that service, and dropping it would lose a finding to an exit status.
		if result != nil && result.Accounted() > 0 {
			partial := &UDPPartialError{IP: ip, Requested: len(ports), Accounted: result.Accounted(), Cause: runErr}
			c.emitUDPError(ctx, ip, partial)
			c.emitUDPCompleted(ctx, *result, true)
			return result, partial
		}
		c.emitUDPError(ctx, ip, runErr)
		return nil, fmt.Errorf("portscan: udp scan of %s failed: %w", ip, runErr)
	}

	if result == nil {
		// nmap reported success and produced no document. That is a broken runtime,
		// not an empty host, and calling it a clean pass would claim coverage that
		// never happened.
		err := fmt.Errorf("portscan: udp scan of %s reported success but returned no output", ip)
		c.emitUDPError(ctx, ip, err)
		return nil, err
	}
	// A successful exit status is not proof of coverage. nmap can return a document
	// that assigns states to fewer ports than were asked for (truncated or
	// malformed output) or to more (a document that is not the pass this code
	// built), and either way the requested work is not what came back. The evidence
	// is kept, the completion is marked partial, and the error degrades collection
	// so the phase stays retryable instead of checkpointing false coverage.
	if accounted := result.Accounted(); accounted != len(ports) {
		err := &UDPAccountingError{IP: ip, Requested: len(ports), Accounted: accounted}
		c.emitUDPError(ctx, ip, err)
		c.emitUDPCompleted(ctx, *result, true)
		return result, err
	}
	c.emitUDPCompleted(ctx, *result, false)
	return result, nil
}

// udpRun executes the pass through the injectable engine, so every test in this
// package drives recorded nmap XML instead of a binary, a socket, or a privilege.
func (c *Client) udpRun(ctx context.Context, opts udpRunOptions) (*nmap.Run, error) {
	if c.udpEngine != nil {
		return c.udpEngine(ctx, opts)
	}
	return runNmapUDP(ctx, opts)
}

// validateUDPPorts refuses a port list before any traffic. The cap is what keeps
// a programmatic caller from turning a reviewed eight-port discovery pass into a
// sweep.
func (c *Client) validateUDPPorts(ports []int) error {
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("portscan: udp port %d is out of range", p)
		}
	}
	if c.cfg.UDP.MaxPorts > 0 && len(ports) > c.cfg.UDP.MaxPorts {
		return fmt.Errorf("portscan: udp scan requested %d ports, limit is %d", len(ports), c.cfg.UDP.MaxPorts)
	}
	return nil
}

// mapUDPRun turns one nmap run into a Vanguard result without collapsing any
// state. The run is never nil: the caller decides what an absent document means,
// because that judgement belongs with the pass and not with the mapping.
func (c *Client) mapUDPRun(ctx context.Context, ip string, requested int, run *nmap.Run) (*UDPResult, error) {
	result := &UDPResult{IP: ip, RequestedPorts: requested}
	for _, host := range run.Hosts {
		for _, p := range host.Ports {
			// nmap reports every technique's ports in one document. A TCP entry here
			// would mean the invocation was not the one this code builds, so it is
			// skipped rather than recorded as a UDP service.
			if !strings.EqualFold(p.Protocol, "udp") {
				continue
			}
			port := int(p.ID)
			state, ok := udpStateFor(p.State.State)
			if !ok {
				err := &UDPStateError{IP: ip, Port: port, State: boundedState(p.State.State)}
				c.emit(ctx, UDPParsingError{IP: ip, Port: port, State: err.State, Raw: boundedState(p.State.Reason)})
				return nil, err
			}
			if state == UDPOpen {
				open := udpOpenPort(port, p)
				result.Open = append(result.Open, open)
				c.emit(ctx, UDPPortOpen{IP: ip, Port: port, Service: open.Service, Product: open.Product, Version: open.Version})
				if open.Banner != "" {
					c.emit(ctx, ServiceBannerDiscovered{IP: ip, Port: port, Protocol: "udp", BannerSnippet: bannerSnippet(open.Banner)})
				}
				continue
			}
			entry := UDPPortState{Port: port, State: state, Reason: p.State.Reason}
			switch state {
			case UDPOpenFiltered:
				result.OpenFiltered = append(result.OpenFiltered, entry)
			case UDPClosed:
				result.Closed = append(result.Closed, entry)
			case UDPFiltered:
				result.Filtered = append(result.Filtered, entry)
			case UDPOpen:
				// handled above; listed so a future state addition fails to compile
			}
			c.emit(ctx, UDPPortNotOpen{IP: ip, Port: port, State: string(state), Reason: entry.Reason})
		}
		for _, extra := range host.ExtraPorts {
			state, ok := udpStateFor(extra.State)
			if !ok {
				err := &UDPStateError{IP: ip, State: boundedState(extra.State)}
				c.emit(ctx, UDPParsingError{IP: ip, State: err.State, Raw: boundedState(extra.State)})
				return nil, err
			}
			result.Collapsed = append(result.Collapsed, UDPCollapsedPorts{
				State: state, Count: extra.Count, Reasons: joinReasons(extra.Reasons),
			})
		}
	}
	sortUDPResult(result)
	return result, nil
}

// udpStateFor maps nmap's state string onto the reviewed set. The false return is
// the whole point: an unrecognised string is never quietly folded into a state
// this code does understand.
func udpStateFor(state string) (UDPState, bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "open":
		return UDPOpen, true
	case "open|filtered":
		return UDPOpenFiltered, true
	case "closed":
		return UDPClosed, true
	case "filtered":
		return UDPFiltered, true
	default:
		return "", false
	}
}

// udpOpenPort builds the confirmed-service shape from an nmap port. It reuses
// OpenPort so a UDP service and a TCP service are the same kind of thing
// everywhere downstream, distinguished only by Protocol.
func udpOpenPort(port int, p nmap.Port) OpenPort {
	open := OpenPort{Port: port, Protocol: "udp"}
	svc := p.Service
	open.Service = svc.Name
	open.Product = svc.Product
	open.Version = svc.Version
	open.ExtraInfo = svc.ExtraInfo
	open.OSType = svc.OSType
	for _, cpe := range svc.CPEs {
		open.CPEs = append(open.CPEs, string(cpe))
	}
	open.Banner = udpBanner(svc)
	return open
}

// udpBanner derives the same best-effort banner the TCP path derives, from the
// same fields, so a consumer does not have to know which transport produced it.
func udpBanner(svc nmap.Service) string {
	banner := strings.TrimSpace(svc.ServiceFP)
	if banner == "" {
		parts := make([]string, 0, 3)
		for _, f := range []string{svc.Product, svc.Version, svc.ExtraInfo} {
			if f = strings.TrimSpace(f); f != "" {
				parts = append(parts, f)
			}
		}
		banner = strings.Join(parts, " ")
	}
	if len(banner) > maxBannerLen {
		banner = strings.ToValidUTF8(banner[:maxBannerLen], "")
	}
	return banner
}

// bannerSnippet bounds a banner for the event stream, matching the TCP path.
func bannerSnippet(banner string) string {
	if len(banner) > 256 {
		return strings.ToValidUTF8(banner[:256], "")
	}
	return banner
}

// boundedState caps a raw string taken from nmap output before it enters an error
// or an event, so an unexpected document cannot paste itself into the tool log.
func boundedState(raw string) string {
	const maxLen = 64
	raw = strings.TrimSpace(raw)
	if len(raw) > maxLen {
		return strings.ToValidUTF8(raw[:maxLen], "") + "..."
	}
	return raw
}

// joinReasons renders nmap's aggregate reasons for a collapsed group.
func joinReasons(reasons []nmap.Reason) string {
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		parts = append(parts, fmt.Sprintf("%s=%d", r.Reason, r.Count))
	}
	return strings.Join(parts, ",")
}

// sortUDPResult makes the result deterministic. Two runs over the same host must
// produce the same bytes, or a capture diff reports churn that never happened.
func sortUDPResult(r *UDPResult) {
	slices.SortFunc(r.Open, func(a, b OpenPort) int { return a.Port - b.Port })
	byPort := func(a, b UDPPortState) int { return a.Port - b.Port }
	slices.SortFunc(r.OpenFiltered, byPort)
	slices.SortFunc(r.Closed, byPort)
	slices.SortFunc(r.Filtered, byPort)
	slices.SortFunc(r.Collapsed, func(a, b UDPCollapsedPorts) int { return strings.Compare(string(a.State), string(b.State)) })
}

// emitUDPCompleted reports the pass's terminal accounting: what was asked for,
// what each state accounted for, and whether the result is complete. A pass that
// finished with zero open ports is a healthy pass, so this event carries no health
// problem of its own.
func (c *Client) emitUDPCompleted(ctx context.Context, r UDPResult, partial bool) {
	counts := r.StateCounts()
	c.emit(ctx, UDPScanCompleted{
		IP:           r.IP,
		TotalPorts:   r.RequestedPorts,
		Open:         counts[UDPOpen],
		OpenFiltered: counts[UDPOpenFiltered],
		Closed:       counts[UDPClosed],
		Filtered:     counts[UDPFiltered],
		Accounted:    r.Accounted(),
		DurationMS:   r.Duration.Milliseconds(),
		Partial:      partial,
	})
}

// isPermissionError reports whether a failure is the local privilege failure an
// operator fixes at deployment. The UDP pass runs nmap as a child process, so the
// refusal arrives as an exit status and a message rather than as a socket errno,
// which is why the text is matched as well as the errno.
func isPermissionError(err error) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, phrase := range []string{
		"permission denied",
		"operation not permitted",
		"access denied",
		"requires root privileges",
		"requires raw socket access",
	} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

// emitUDPError routes a failure to the most specific event that describes it. A
// missing raw-socket privilege keeps its own event because it is the one failure
// an operator fixes at deployment rather than by retrying.
func (c *Client) emitUDPError(ctx context.Context, ip string, err error) {
	if err == nil {
		return
	}
	if isPermissionError(err) {
		c.emit(ctx, UDPPermissionDenied{IP: ip, Err: err})
		return
	}
	c.emit(ctx, UDPScanError{IP: ip, Err: err})
}
