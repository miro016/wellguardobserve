package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

// Config holds configuration for the Client.
type Config struct {
	// Timeout is the per-port connect timeout naabu waits for a response.
	Timeout time.Duration
	// RatePerSecond caps naabu's packet rate for this host scan.
	RatePerSecond int
	// NmapCommand is the nmap command line naabu runs against the open ports to
	// fingerprint services (for example "nmap -sV -Pn -T4"). When empty, naabu
	// reports open ports without service detection. The tool requires nmap on the
	// host: callers must verify it is installed before enabling the scanner. New
	// rejects unsupported flags so typos fail before scanning starts.
	NmapCommand string
	// Allow authorizes every scan target IP before any engine runs. It is the shared
	// request authorizer the orchestrator injects, so a hard-excluded or unapproved
	// address is refused at the tool boundary as defense in depth behind the outer
	// scheduler. A nil Allow permits every valid target, for standalone and test use.
	Allow scopecheck.Allow
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
	// UDP configures the optional, independent UDP pass (see [Client.ScanUDP]).
	// Its zero value disables it, and a disabled pass changes nothing about the
	// TCP path: no UDP socket is opened, no -sU process is started, and the naabu
	// invocation and its results are untouched.
	UDP UDPConfig
}

// OpenPort describes a port naabu found open, enriched with nmap service
// detection when NmapCommand is set.
type OpenPort struct {
	// Port is the open TCP port.
	Port int
	// Protocol is the transport, normally "tcp".
	Protocol string
	// Service is the service name (for example "http"), best-effort.
	Service string
	// Product is the fingerprinted product (for example "nginx").
	Product string
	// Version is the fingerprinted product version (for example "1.25.3").
	Version string
	// ExtraInfo is extra service detail from nmap (for example "Ubuntu").
	ExtraInfo string
	// CPEs holds the Common Platform Enumeration identifiers from nmap.
	CPEs []string
	// OSType is the coarse OS family nmap's service detection attached to the
	// match (for example "Linux" or "Windows"), best-effort and often empty. It
	// is a weak, per-service hint - not a privileged -O OS fingerprint - that the
	// orchestrator aggregates into a host OS guess.
	OSType string
	// Banner is a best-effort, truncated service banner derived from the nmap
	// fingerprint. It carries the raw probe response (nmap ServiceFP) when nmap
	// could not match the service, and the assembled product/version/extra-info
	// otherwise. The plain naabu connect scan captures none; it is empty without
	// nmap service detection.
	Banner string
}

// maxBannerLen bounds the stored Banner. nmap service fingerprints (ServiceFP)
// can run to a few kilobytes; the field is documented as a truncated banner and
// downstream consumers only need the leading bytes to corroborate a build.
const maxBannerLen = 512

// Client performs port scans via the projectdiscovery naabu library and, when
// configured, fingerprints the open ports with nmap.
type Client struct {
	cfg         Config
	dialContext func(context.Context, string, string) (net.Conn, error)
	// udpEngine runs one nmap UDP pass. It is nil in production, where the real
	// nmap invocation is used; tests replace it so every mapping, accounting, and
	// failure path is proven from recorded nmap XML, with no binary and no
	// privilege on the machine running them.
	udpEngine udpEngineFunc
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("portscan: Config.Timeout must be positive")
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = runner.DefaultRateConnectScan
	}
	if err := validateNmapCommand(cfg.NmapCommand); err != nil {
		return nil, err
	}
	if err := validateUDPConfig(cfg.UDP); err != nil {
		return nil, err
	}
	// naabu and its nmap integration log through gologger; clamp it to fatal so
	// the scanner stays silent and does not corrupt the CLI output.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	return &Client{cfg: cfg, dialContext: dialer.DialContext}, nil
}

// Scan port-scans ports on ip with naabu, optionally fingerprinting open ports
// with nmap, and returns the open ports in ascending order. It honours ctx.
func (c *Client) Scan(ctx context.Context, ip string, ports []int) ([]OpenPort, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		err := fmt.Errorf("portscan: invalid IP address %q", ip)
		c.emit(ctx, ScanError{IP: ip, Err: err})
		return nil, err
	}
	// Enforce the injected policy before naabu runner construction, nmap argument
	// creation, or the ScanStarted event, so an excluded or unapproved target sends
	// no traffic and is not recorded as a started scan.
	if err := c.checkTarget(ctx, ip); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, nil
	}
	c.emit(ctx, ScanStarted{IP: ip, Ports: len(ports)})

	var (
		mu   sync.Mutex
		open []OpenPort
	)
	opts := &runner.Options{
		Host:               goflags.StringSlice{ip},
		Ports:              joinPorts(ports),
		ScanType:           runner.ConnectScan,
		Rate:               c.cfg.RatePerSecond,
		Timeout:            c.cfg.Timeout,
		NmapCLI:            nmapCommandFor(c.cfg.NmapCommand, parsed),
		Silent:             true,
		DisableStdout:      true,
		DisableUpdateCheck: true,
		OnResult: func(hr *result.HostResult) {
			mu.Lock()
			defer mu.Unlock()
			for _, p := range hr.Ports {
				op := toOpenPort(p)
				open = append(open, op)
				c.emit(ctx, PortOpen{IP: ip, Port: op.Port, Service: op.Service, Product: op.Product, Version: op.Version})
				if op.Banner != "" {
					snippet := op.Banner
					if len(snippet) > 256 {
						snippet = strings.ToValidUTF8(snippet[:256], "")
					}
					c.emit(ctx, ServiceBannerDiscovered{IP: ip, Port: op.Port, Protocol: op.Protocol, BannerSnippet: snippet})
				}
			}
		},
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		c.emitScanError(ctx, ip, err)
		return nil, fmt.Errorf("portscan: failed to create naabu runner: %w", err)
	}
	defer func() { _ = r.Close() }()

	if err := r.RunEnumeration(ctx); err != nil {
		c.emitScanError(ctx, ip, err)
		return nil, fmt.Errorf("portscan: scan of %s failed: %w", ip, err)
	}

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	closed := len(ports) - len(open)
	c.emit(ctx, ScanCompleted{
		IP:         ip,
		TotalPorts: len(ports),
		Open:       len(open),
		Closed:     closed,
		Filtered:   0,
		Timeouts:   0,
		Degraded:   false,
	})
	return open, nil
}

// Reachable reports whether ip answers at the TCP layer at all. It is a tiebreaker
// for the ambiguous "zero open ports" outcome: naabu's connect scan cannot tell a
// closed port (the host answered with a RST) from a filtered one (no answer), so a
// host that is down or fully firewalled looks identical to one with every port
// closed. Reachable dials the given ports concurrently with the configured timeout
// and returns true as soon as one connect either succeeds or gets a host-level
// answer such as connection refused. It returns false only when every probe times
// out or the local network reports no route to the destination, which is the
// down/filtered/unreachable case. Callers use a false result to record a coverage
// gap rather than accept an empty scan as a clean result.
func (c *Client) Reachable(ctx context.Context, ip string, ports []int) bool {
	if net.ParseIP(ip) == nil || len(ports) == 0 {
		return false
	}
	// The same policy gates the reachability tiebreaker before any dial. A rejected
	// target is a policy decision, not a reachability verdict: callers treat Scan's
	// typed error as the authority and never read this false as unreachable coverage.
	if err := c.checkTarget(ctx, ip); err != nil {
		return false
	}
	answered := make(chan bool, len(ports))
	var wg sync.WaitGroup
	var timeouts int64
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := c.dialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
			if err == nil {
				_ = conn.Close()
				answered <- true
				return
			}
			// A closed port replies with RST and proves the host is reachable. A timeout
			// or no-route error is still no answer from the target.
			if isNoAnswerError(err) {
				atomic.AddInt64(&timeouts, 1)
			} else {
				answered <- true
			}
		}(p)
	}
	go func() { wg.Wait(); close(answered) }()
	for a := range answered {
		if a {
			return true
		}
	}
	if int(timeouts) == len(ports) && len(ports) >= 3 {
		c.emit(ctx, ScanThrottled{IP: ip, ConsecutiveTimeouts: int(timeouts)})
	}
	return false
}

// checkTarget asks the injected authorizer whether ip may receive scan traffic. It
// emits a typed TargetRejected and returns a *scopecheck.RejectedError when the
// policy denies the target, and nil (permit) when the authorizer is unset or allows
// it. It performs no network I/O, so it is safe to call before any engine.
func (c *Client) checkTarget(ctx context.Context, ip string) error {
	if c.cfg.Allow == nil {
		return nil
	}
	allowed, reason := c.cfg.Allow(ctx, ip)
	if allowed {
		return nil
	}
	c.emit(ctx, TargetRejected{IP: ip, Reason: reason})
	return &scopecheck.RejectedError{Host: ip, Reason: reason}
}

func isNoAnswerError(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "host is unreachable")
}

func (c *Client) emitScanError(ctx context.Context, ip string, err error) {
	if err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) ||
		strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "access denied"):
		c.emit(ctx, PermissionDenied{ScanType: "connect", Err: err})
	case errors.Is(err, syscall.ENETUNREACH) || strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host") || strings.Contains(msg, "host is unreachable") ||
		strings.Contains(msg, "unreachable"):
		c.emit(ctx, NetworkUnreachable{IP: ip, Err: err})
	default:
		c.emit(ctx, ScanError{IP: ip, Err: err})
	}
}

// nmapCommandFor returns the nmap command line for scanning ip. nmap needs the -6
// flag to scan an IPv6 target and naabu does not add it, so without -6 naabu finds
// the open IPv6 ports but nmap returns no service/product/version for them. An IPv6
// address therefore gets -6 appended (once); an IPv4 address and an empty command
// are returned unchanged. The flag's position does not matter to nmap - naabu
// appends the target after this prefix.
func nmapCommandFor(cmd string, ip net.IP) string {
	if cmd == "" || ip.To4() != nil {
		return cmd
	}
	if slices.Contains(strings.Fields(cmd), "-6") {
		return cmd
	}
	return cmd + " -6"
}

func validateNmapCommand(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return nil
	}
	base := strings.ToLower(filepath.Base(fields[0]))
	if base != "nmap" && base != "nmap.exe" {
		return fmt.Errorf("portscan: nmap command must start with nmap, got %q", fields[0])
	}
	for i := 1; i < len(fields); i++ {
		field := fields[i]
		if !strings.HasPrefix(field, "-") {
			return fmt.Errorf("portscan: nmap command contains unexpected argument %q", field)
		}
		if allowedNmapFlag(field) {
			continue
		}
		if field == "--version-intensity" {
			if i+1 >= len(fields) || !validNmapVersionIntensity(fields[i+1]) {
				return fmt.Errorf("portscan: --version-intensity requires a value from 0 to 9")
			}
			i++
			continue
		}
		if strings.HasPrefix(field, "--version-intensity=") {
			value := strings.TrimPrefix(field, "--version-intensity=")
			if validNmapVersionIntensity(value) {
				continue
			}
			return fmt.Errorf("portscan: --version-intensity requires a value from 0 to 9")
		}
		return fmt.Errorf("portscan: unsupported nmap command flag %q", field)
	}
	return nil
}

func allowedNmapFlag(flag string) bool {
	switch flag {
	case "-sV", "-Pn", "-6", "--version-light", "--version-all", "--reason":
		return true
	}
	if len(flag) == 3 && strings.HasPrefix(flag, "-T") {
		return flag[2] >= '0' && flag[2] <= '5'
	}
	return false
}

func validNmapVersionIntensity(value string) bool {
	if len(value) != 1 {
		return false
	}
	return value[0] >= '0' && value[0] <= '9'
}

// toOpenPort maps a naabu port (with optional nmap service info) to an OpenPort.
func toOpenPort(p *port.Port) OpenPort {
	op := OpenPort{Port: p.Port, Protocol: p.Protocol.String()}
	if p.Service != nil {
		op.Service = p.Service.Name
		op.Product = p.Service.Product
		op.Version = p.Service.Version
		op.ExtraInfo = p.Service.ExtraInfo
		op.CPEs = append([]string(nil), p.Service.CPEs...)
		op.OSType = p.Service.OSType
		op.Banner = serviceBanner(p.Service)
	}
	return op
}

// serviceBanner derives a best-effort banner from nmap service detection. It
// prefers ServiceFP, the raw probe response nmap could not fold into a
// product/version match: that string carries the literal banner bytes the CVE
// and service-auth checks key on. A cleanly identified service has an empty
// ServiceFP, so it falls back to the assembled product/version/extra-info so a
// recognised service still surfaces a comparable banner-equivalent. The result
// is whitespace-trimmed and truncated to maxBannerLen (dropping a trailing
// partial rune so the value stays valid UTF-8).
func serviceBanner(s *port.Service) string {
	banner := strings.TrimSpace(s.ServiceFP)
	if banner == "" {
		parts := make([]string, 0, 3)
		for _, f := range []string{s.Product, s.Version, s.ExtraInfo} {
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

// joinPorts renders ports as the comma-separated list naabu expects.
func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}
