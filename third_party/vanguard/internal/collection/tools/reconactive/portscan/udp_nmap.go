package portscan

import (
	"context"
	"strconv"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// This file is the only place the nmap wrapper is named. Every other file in the
// package works with Vanguard's own types, so an upstream change breaks one
// adapter and its contract test rather than the collection contract: nmap.Run,
// nmap.Port, and nmap.Option appear in no event, no configuration, and no
// cross-package signature.

// udpRunOptions is the typed invocation the UDP pass builds from configuration.
// It exists so the argument list is assembled once, from reviewed fields, instead
// of being pasted together from a command string: nothing an operator writes in a
// profile reaches nmap as an argument.
type udpRunOptions struct {
	// NmapPath is the absolute executable resolved by collection preflight. It is
	// required: this pass never searches PATH at scan time.
	NmapPath string
	// IP is the single target address.
	IP string
	// IPv6 selects nmap's IPv6 mode. It is decided from the parsed address rather
	// than configured, because nmap needs -6 for an IPv6 target and silently scans
	// nothing useful without it.
	IPv6 bool
	// Ports is the exact port list to probe.
	Ports []int
	// Privileged adds --privileged, which tells nmap to stop deciding from its
	// effective UID whether it may open a raw socket. Collection preflight
	// establishes per machine whether it is needed; it is never assumed here.
	Privileged bool
	// ServiceDetection enables nmap's version detection on answering ports.
	ServiceDetection bool
	// VersionIntensity is the version-detection intensity, 0-9.
	VersionIntensity int
	// TimingTemplate is nmap's timing template, 0-5.
	TimingTemplate int
	// HostTimeout bounds the whole pass against this host.
	HostTimeout time.Duration
	// ProbeTimeout is the per-port response wait, applied as nmap's maximum
	// round-trip timeout: it is the knob that decides how long a silent port is
	// waited for before it becomes open|filtered.
	ProbeTimeout time.Duration
	// RatePerSecond caps the packet rate against this host.
	RatePerSecond int
	// Retries is the number of extra attempts after the first for a silent port.
	// Zero is valid and means exactly one attempt.
	Retries int
}

// nmapUDPOptions translates the typed options into the wrapper's option list.
//
// The scan technique, the target, the port list, and the output format are set
// here and are not configurable, because they are what makes this pass the
// reviewed thing it is: a UDP scan of named ports on one authorized address.
// Host discovery is skipped (-Pn) because a host that does not answer a ping can
// still answer a UDP probe, and DNS resolution is disabled because the target is
// already an address and a scan should not emit a lookup for it.
func nmapUDPOptions(o udpRunOptions) []nmap.Option {
	ports := make([]string, len(o.Ports))
	for i, p := range o.Ports {
		ports[i] = strconv.Itoa(p)
	}
	opts := []nmap.Option{
		nmap.WithBinaryPath(o.NmapPath),
		nmap.WithTargets(o.IP),
		nmap.WithPorts(ports...),
		nmap.WithUDPScan(),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
		// Reason output is what turns a state into evidence: "no-response" and
		// "port-unreach" are different facts about a silent port, and a capture
		// that kept only the state could not tell them apart later.
		nmap.WithReason(),
		nmap.WithNonInteractive(),
		nmap.WithTimingTemplate(nmap.Timing(o.TimingTemplate)),
		nmap.WithHostTimeout(o.HostTimeout),
		nmap.WithMaxRTTTimeout(o.ProbeTimeout),
		nmap.WithMaxRate(o.RatePerSecond),
		nmap.WithMaxRetries(o.Retries),
	}
	if o.IPv6 {
		opts = append(opts, nmap.WithIPv6Scanning())
	}
	if o.Privileged {
		opts = append(opts, nmap.WithPrivileged())
	}
	if o.ServiceDetection {
		opts = append(opts, nmap.WithServiceInfo(), nmap.WithVersionIntensity(int16(o.VersionIntensity)))
	}
	return opts
}

// runNmapUDP executes one UDP pass and returns the parsed run.
//
// The wrapper reports a cancelled or timed-out context as its own sentinel error,
// which would tell a caller the scan failed rather than that the collection was
// stopped. The context error is returned instead whenever the context is done, so
// an interrupted pass is an interruption everywhere it is read. The child process
// dies with the context: the wrapper starts it with exec.CommandContext.
//
// A run that produced evidence and then failed still returns that evidence, so the
// caller can publish what was found and report the loss separately.
func runNmapUDP(ctx context.Context, o udpRunOptions) (*nmap.Run, error) {
	scanner, err := nmap.NewScanner(ctx, nmapUDPOptions(o)...)
	if err != nil {
		return nil, err
	}
	run, _, err := scanner.Run()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return run, ctxErr
		}
		return run, err
	}
	return run, nil
}
