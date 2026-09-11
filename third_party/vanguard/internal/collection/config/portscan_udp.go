package config

import (
	"fmt"
	"slices"
	"time"
)

// Maximum values the UDP block accepts. They are hard ceilings, not defaults: a
// profile still has to state every value, and a value above one of these is a
// configuration error rather than something to clamp. They exist because a UDP
// probe is unacknowledged by design, so an over-wide port list or an over-fast
// rate buys nothing but traffic.
const (
	// UDPMaxPorts caps how many UDP ports one host is probed on. The shipped list
	// is eight discovery ports; the ceiling leaves room to widen it deliberately
	// without turning the pass into a sweep.
	UDPMaxPorts = 32
	// UDPMaxTimeout caps the per-port response wait. Longer waits do not make a
	// silent port answer; they only stretch the pass.
	UDPMaxTimeout = 30 * time.Second
	// UDPMaxRatePerSecond caps the per-host probe rate.
	UDPMaxRatePerSecond = 100
	// UDPMaxRetries caps re-probing a silent port. UDP silence is ambiguous by
	// nature, and no number of retries resolves it.
	UDPMaxRetries = 5
	// UDPMaxVersionIntensity is nmap's own upper bound for -sV intensity.
	UDPMaxVersionIntensity = 9
	// UDPMaxTimingTemplate is nmap's own upper bound for -T.
	UDPMaxTimingTemplate = 5
	// UDPMaxHostTimeout caps how long one host's UDP pass may run.
	UDPMaxHostTimeout = 30 * time.Minute
)

// PortScanUDP configures the UDP pass of the port scanner. It is an extension of
// portscan, not a separate tool: the UDP pass reuses the port scanner's source,
// tool log, target admission, host-concurrency slot, and active-host budget, and
// runs sequentially with the host's TCP pass.
//
// There is no engine selector. An enabled block means one nmap "-sU" pass per
// admitted host, invoked directly; no raw command fragment, argument list,
// privilege toggle, or fallback policy is expressible here, because those are
// review decisions rather than tuning.
//
// The block is required in every profile, like every other tool block, so
// behaviour never depends on a struct default. When enabled is false the
// remaining values are still parsed and range-checked, which keeps a disabled
// block from hiding a value that would fail the day someone enables it.
type PortScanUDP struct {
	// Enabled is the master switch. It may only be true when the port scanner and
	// the active phase are on, and it requires the deployed nmap to hold the
	// raw-socket capability: an enabled UDP pass without that privilege is a
	// preflight failure, never a silent downgrade.
	Enabled *bool `yaml:"enabled"`
	// Ports is the exact UDP port list probed on every admitted host. Entries must
	// be unique, in range, and at most UDPMaxPorts of them. There is no range
	// syntax and no "all ports" mode: a UDP sweep is out of scope.
	Ports []int `yaml:"ports"`
	// Timeout is how long one port is given to answer before the probe is treated
	// as unanswered. An unanswered UDP port is open|filtered, which is coverage,
	// not a service.
	Timeout Duration `yaml:"timeout"`
	// RatePerSecond caps the probe rate against one host.
	RatePerSecond *int `yaml:"rate_per_second"`
	// Retries is the number of extra attempts after the first for a silent port.
	// Zero is valid and means exactly one attempt.
	Retries *int `yaml:"retries"`
	// Nmap tunes the single nmap invocation the pass makes.
	Nmap PortScanUDPNmap `yaml:"nmap"`
}

// PortScanUDPNmap holds the reviewed subset of nmap tuning the UDP pass exposes.
// Every field maps to one typed option on the invocation; none of them is a raw
// argument, and the scan technique, target, and output format are not settings at
// all because the tool owns them.
type PortScanUDPNmap struct {
	// ServiceDetection runs nmap's version detection against answering ports.
	// Without it a positive UDP response is recorded as an open port with no
	// service identification.
	ServiceDetection *bool `yaml:"service_detection"`
	// VersionIntensity is nmap's version-detection intensity, 0 to
	// UDPMaxVersionIntensity.
	VersionIntensity *int `yaml:"version_intensity"`
	// TimingTemplate is nmap's timing template, 0 to UDPMaxTimingTemplate.
	TimingTemplate *int `yaml:"timing_template"`
	// HostTimeout bounds one host's UDP pass. On expiry the pass is over for that
	// host and what it did not reach is a recorded coverage gap.
	HostTimeout Duration `yaml:"host_timeout"`
}

// UDPEnabled reports whether the profile asked for a UDP pass. It is the one
// place that reads the nested pointers, so a caller never has to.
func (c *ScanProfile) UDPEnabled() bool {
	return c.Tools.PortScan.Enabled != nil && *c.Tools.PortScan.Enabled &&
		c.Tools.PortScan.UDP.Enabled != nil && *c.Tools.PortScan.UDP.Enabled
}

// validatePortScanUDP checks the UDP block. It is pure: it judges the document
// and nothing about the machine, so the same profile is valid or invalid
// everywhere. Whether this machine may actually open a raw socket is a runtime
// preflight question, not a configuration one.
//
// Every range is enforced whether or not the block is enabled, because a value
// that would fail on the day UDP is switched on should fail on the day it is
// written. Only the cross-block consistency rules need the switch.
func (c *ScanProfile) validatePortScanUDP(req func(bool, string)) {
	u := c.Tools.PortScan.UDP
	enabled := u.Enabled != nil && *u.Enabled

	req(u.Enabled != nil, "tools.portscan.udp.enabled is required")
	if enabled {
		req(c.Tools.PortScan.Enabled != nil && *c.Tools.PortScan.Enabled,
			"tools.portscan.udp.enabled requires tools.portscan.enabled")
		req(c.Phases.Active.Enabled != nil && *c.Phases.Active.Enabled,
			"tools.portscan.udp.enabled requires phases.active.enabled: a UDP pass sends traffic")
	}

	req(len(u.Ports) > 0, "tools.portscan.udp.ports must list at least one port")
	req(len(u.Ports) <= UDPMaxPorts,
		fmt.Sprintf("tools.portscan.udp.ports must list at most %d ports", UDPMaxPorts))
	for _, port := range u.Ports {
		req(port >= 1 && port <= 65535,
			fmt.Sprintf("tools.portscan.udp.ports contains out-of-range port %d (must be 1-65535)", port))
	}
	sorted := slices.Clone(u.Ports)
	slices.Sort(sorted)
	req(len(slices.Compact(sorted)) == len(u.Ports), "tools.portscan.udp.ports must not repeat a port")

	req(u.Timeout > 0, "tools.portscan.udp.timeout is required (e.g. \"3s\")")
	req(u.Timeout <= Duration(UDPMaxTimeout),
		fmt.Sprintf("tools.portscan.udp.timeout must be <= %s", UDPMaxTimeout))

	req(u.RatePerSecond != nil, "tools.portscan.udp.rate_per_second is required")
	req(u.RatePerSecond == nil || *u.RatePerSecond > 0, "tools.portscan.udp.rate_per_second must be > 0")
	req(u.RatePerSecond == nil || *u.RatePerSecond <= UDPMaxRatePerSecond,
		fmt.Sprintf("tools.portscan.udp.rate_per_second must be <= %d", UDPMaxRatePerSecond))

	req(u.Retries != nil, "tools.portscan.udp.retries is required (0 is valid and means one attempt)")
	req(u.Retries == nil || *u.Retries >= 0, "tools.portscan.udp.retries must be >= 0")
	req(u.Retries == nil || *u.Retries <= UDPMaxRetries,
		fmt.Sprintf("tools.portscan.udp.retries must be <= %d", UDPMaxRetries))

	n := u.Nmap
	req(n.ServiceDetection != nil, "tools.portscan.udp.nmap.service_detection is required")
	req(n.VersionIntensity != nil, "tools.portscan.udp.nmap.version_intensity is required")
	req(n.VersionIntensity == nil || (*n.VersionIntensity >= 0 && *n.VersionIntensity <= UDPMaxVersionIntensity),
		fmt.Sprintf("tools.portscan.udp.nmap.version_intensity must be 0-%d", UDPMaxVersionIntensity))
	req(n.TimingTemplate != nil, "tools.portscan.udp.nmap.timing_template is required")
	req(n.TimingTemplate == nil || (*n.TimingTemplate >= 0 && *n.TimingTemplate <= UDPMaxTimingTemplate),
		fmt.Sprintf("tools.portscan.udp.nmap.timing_template must be 0-%d", UDPMaxTimingTemplate))
	req(n.HostTimeout > 0, "tools.portscan.udp.nmap.host_timeout is required (e.g. \"5m\")")
	req(n.HostTimeout <= Duration(UDPMaxHostTimeout),
		fmt.Sprintf("tools.portscan.udp.nmap.host_timeout must be <= %s", UDPMaxHostTimeout))
	req(n.HostTimeout == 0 || u.Timeout == 0 || n.HostTimeout >= u.Timeout,
		"tools.portscan.udp.nmap.host_timeout must be >= tools.portscan.udp.timeout")
}
