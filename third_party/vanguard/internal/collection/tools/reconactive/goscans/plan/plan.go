package plan

import (
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/upstream"
)

// Skip reasons. They are constants because a skip is a recorded coverage decision
// that a later report compares across scans, and a reworded reason would look like
// a different decision.
const (
	ReasonNonTCP     = "non-tcp transport"
	ReasonServiceCap = "service cap reached"
	ReasonNotTLS     = "service is not tls"
	ReasonNotSSH     = "service is not ssh"
	ReasonNotWeb     = "service is not web"
)

// serviceHTTPS is the nmap service name for web over TLS. It is a constant because
// it appears in two selection tables, and both must mean the same thing.
const serviceHTTPS = "https"

// Module identifies one stage of the pipeline. It is a value rather than a free
// string so the selection tables, the skip reasons, and the error events cannot
// drift apart.
type Module uint8

// The pipeline stages. Discovery is first because it is the only input the others
// are allowed to have; the iota order is also the tie-break when two jobs for the
// same port are sorted.
const (
	Discovery Module = iota + 1
	Banner
	TLS
	SSH
	Crawl
	Enum
)

// String returns the stable event and log identifier for the module.
func (m Module) String() string {
	switch m {
	case Discovery:
		return "discovery"
	case Banner:
		return "banner"
	case TLS:
		return "tls"
	case SSH:
		return "ssh"
	case Crawl:
		return "crawl"
	case Enum:
		return "enum"
	default:
		return "unknown"
	}
}

// Modules selects which subordinate assessments run after discovery. Discovery
// itself is not a toggle: it is the only input the others are allowed to have, so
// turning it off would leave nothing to schedule.
type Modules struct {
	// Banner collects raw service banners over plain, TLS, Telnet, HTTP, and HTTPS.
	Banner bool
	// TLS runs the SSLyze-backed assessment.
	TLS bool
	// SSH assesses SSH algorithm and protocol choices.
	SSH bool
	// WebCrawl crawls web services to the configured depth.
	WebCrawl bool
	// WebEnum probes web services with the embedded probe set.
	WebEnum bool
}

// Any reports whether at least one subordinate module is enabled. A discovery-only
// run is legal but says so in its events rather than looking like a failed scan.
func (m Modules) Any() bool {
	return m.Banner || m.TLS || m.SSH || m.WebCrawl || m.WebEnum
}

// Names lists the enabled subordinate modules in pipeline order.
func (m Modules) Names() []string {
	var out []string
	for _, e := range []struct {
		mod     Module
		enabled bool
	}{
		{Banner, m.Banner}, {TLS, m.TLS}, {SSH, m.SSH}, {Crawl, m.WebCrawl}, {Enum, m.WebEnum},
	} {
		if e.enabled {
			out = append(out, e.mod.String())
		}
	}
	return out
}

// Job is one unit of subordinate work. Everything needed to run it is here, so a
// plan can be built, sorted, and asserted in a test without any upstream call.
type Job struct {
	// Module is the assessment to run.
	Module Module
	// IP is the host address to probe.
	IP string
	// Port is the service port.
	Port int
	// Protocol is the service transport, always "tcp" today.
	Protocol string
	// Vhosts are the server names handed to the module. Only the TLS and web
	// modules take them; upstream loops over them internally.
	Vhosts []string
	// HTTPS selects the scheme for a web job.
	HTTPS bool
}

// Skip is work that was deliberately not scheduled, with the reason recorded. A
// skip is emitted rather than dropped, because "we never looked" and "we looked and
// found nothing" are different facts and only one of them is a coverage gap.
type Skip struct {
	// Module is the assessment that did not run.
	Module Module
	// IP is the host address.
	IP string
	// Port is the service port.
	Port int
	// Protocol is the service transport.
	Protocol string
	// Reason is one of the Reason constants in this package.
	Reason string
}

// Options are the classification inputs. The configured port lists are additive:
// they name ports to treat as a protocol when nmap could not, and never suppress
// what nmap did recognize.
type Options struct {
	// Modules selects the enabled assessments.
	Modules Modules
	// TLSPorts are ports treated as TLS despite an unrecognized service name.
	TLSPorts []int
	// SSHPorts are ports treated as SSH despite an unrecognized service name.
	SSHPorts []int
	// HTTPPorts are ports treated as cleartext web despite an unrecognized name.
	HTTPPorts []int
	// HTTPSPorts are ports treated as web over TLS despite an unrecognized name.
	HTTPSPorts []int
	// MaxServicesPerHost caps how many services of one host may schedule work.
	MaxServicesPerHost int
}

// Selector turns a discovery result into a job plan. It is built once per run so
// the tables and the configured overrides are applied in exactly one place.
type Selector struct {
	modules    Modules
	tlsPorts   map[int]struct{}
	sshPorts   map[int]struct{}
	httpPorts  map[int]struct{}
	httpsPorts map[int]struct{}
	maxService int
}

// NewSelector builds the selector from validated options.
func NewSelector(o Options) Selector {
	return Selector{
		modules:    o.Modules,
		tlsPorts:   portSet(o.TLSPorts),
		sshPorts:   portSet(o.SSHPorts),
		httpPorts:  portSet(o.HTTPPorts),
		httpsPorts: portSet(o.HTTPSPorts),
		maxService: o.MaxServicesPerHost,
	}
}

// portSet turns a configured port list into a lookup set.
func portSet(ports []int) map[int]struct{} {
	out := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		out[p] = struct{}{}
	}
	return out
}

// tlsServiceNames are nmap service names that mean TLS on their own, without a
// tunnel attribute. nmap reports a TLS-wrapped service either as one of these or as
// the cleartext name plus tunnel "ssl", so both paths have to be checked.
var tlsServiceNames = map[string]struct{}{
	serviceHTTPS: {}, "ssl": {}, "https-alt": {}, "imaps": {}, "pop3s": {},
	"smtps": {}, "ldapssl": {}, "ftps": {}, "nntps": {}, "ircs-u": {},
	"tls": {}, "ssl/http": {},
}

// sshServiceNames are nmap service names that mean SSH.
var sshServiceNames = map[string]struct{}{
	"ssh": {}, "sftp": {},
}

// httpServiceNames are nmap service names that mean cleartext web.
var httpServiceNames = map[string]struct{}{
	"http": {}, "http-alt": {}, "http-proxy": {}, "www": {}, "webcache": {},
	"http-mgmt": {}, "caldav": {},
}

// httpsServiceNames are nmap service names that mean web over TLS.
var httpsServiceNames = map[string]struct{}{
	serviceHTTPS: {}, "https-alt": {}, "ssl/http": {}, "ssl/https": {},
}

// IsTLS reports whether a service should get a TLS assessment. The tunnel
// attribute is checked first because nmap describes an HTTPS service as name "http"
// with tunnel "ssl", and reading the name alone would call it cleartext.
func (s Selector) IsTLS(svc upstream.DiscoveryService) bool {
	if strings.EqualFold(svc.Tunnel, "ssl") {
		return true
	}
	if _, ok := tlsServiceNames[strings.ToLower(svc.Name)]; ok {
		return true
	}
	_, ok := s.tlsPorts[svc.Port]
	return ok
}

// IsSSH reports whether a service should get an SSH assessment.
func (s Selector) IsSSH(svc upstream.DiscoveryService) bool {
	if _, ok := sshServiceNames[strings.ToLower(svc.Name)]; ok {
		return true
	}
	_, ok := s.sshPorts[svc.Port]
	return ok
}

// IsWeb reports whether a service should get crawl and enumeration work, and
// whether those requests use TLS.
func (s Selector) IsWeb(svc upstream.DiscoveryService) (web, https bool) {
	name := strings.ToLower(svc.Name)
	if _, ok := httpsServiceNames[name]; ok {
		return true, true
	}
	if _, ok := s.httpsPorts[svc.Port]; ok {
		return true, true
	}
	if _, ok := httpServiceNames[name]; ok {
		// nmap reports TLS-wrapped HTTP as name "http" with tunnel "ssl".
		return true, strings.EqualFold(svc.Tunnel, "ssl")
	}
	if _, ok := s.httpPorts[svc.Port]; ok {
		return true, strings.EqualFold(svc.Tunnel, "ssl")
	}
	return false, false
}

// Services turns one discovered host's services into the subordinate jobs to run
// and the skips to record. The services must already be in SortServices order.
// Discovery output is the only input: nothing another Vanguard tool found may add,
// remove, or reorder anything here.
//
// The transport gate is load bearing rather than defensive. Upstream banner accepts
// "udp" and dials it, while the TLS, SSH, and web modules dial "tcp"
// unconditionally, so a selection keyed on port alone would either probe a UDP
// service with TCP-shaped traffic or record silence as a result.
func (s Selector) Services(services []upstream.DiscoveryService, ip string, vhosts []string) ([]Job, []Skip) {
	var jobs []Job
	var skips []Skip

	for i, svc := range services {
		if i >= s.maxService {
			skips = append(skips, s.skipAll(ip, svc, ReasonServiceCap)...)
			continue
		}
		if !strings.EqualFold(svc.Protocol, "tcp") {
			skips = append(skips, s.skipAll(ip, svc, ReasonNonTCP)...)
			continue
		}
		j, sk := s.serviceJobs(svc, ip, vhosts)
		jobs = append(jobs, j...)
		skips = append(skips, sk...)
	}

	return jobs, skips
}

// serviceJobs applies the module tables to one TCP service.
func (s Selector) serviceJobs(svc upstream.DiscoveryService, ip string, vhosts []string) ([]Job, []Skip) {
	proto := strings.ToLower(svc.Protocol)
	var jobs []Job
	var skips []Skip

	if s.modules.Banner {
		// Every reachable TCP service gets a banner probe: that is the module's whole
		// point, so there is no classification and never a skip.
		jobs = append(jobs, Job{Module: Banner, IP: ip, Port: svc.Port, Protocol: proto})
	}
	if s.modules.TLS {
		if s.IsTLS(svc) {
			jobs = append(jobs, Job{Module: TLS, IP: ip, Port: svc.Port, Protocol: proto, Vhosts: vhosts})
		} else {
			skips = append(skips, Skip{TLS, ip, svc.Port, proto, ReasonNotTLS})
		}
	}
	if s.modules.SSH {
		if s.IsSSH(svc) {
			jobs = append(jobs, Job{Module: SSH, IP: ip, Port: svc.Port, Protocol: proto})
		} else {
			skips = append(skips, Skip{SSH, ip, svc.Port, proto, ReasonNotSSH})
		}
	}

	web, https := s.IsWeb(svc)
	for _, m := range []struct {
		mod     Module
		enabled bool
	}{{Crawl, s.modules.WebCrawl}, {Enum, s.modules.WebEnum}} {
		if !m.enabled {
			continue
		}
		if web {
			jobs = append(jobs, Job{Module: m.mod, IP: ip, Port: svc.Port, Protocol: proto, Vhosts: vhosts, HTTPS: https})
		} else {
			skips = append(skips, Skip{m.mod, ip, svc.Port, proto, ReasonNotWeb})
		}
	}

	return jobs, skips
}

// skipAll records the same reason for every enabled subordinate module, used when a
// service is rejected before any module-specific classification runs.
func (s Selector) skipAll(ip string, svc upstream.DiscoveryService, reason string) []Skip {
	proto := strings.ToLower(svc.Protocol)
	var out []Skip
	for _, m := range []struct {
		mod     Module
		enabled bool
	}{
		{Banner, s.modules.Banner},
		{TLS, s.modules.TLS},
		{SSH, s.modules.SSH},
		{Crawl, s.modules.WebCrawl},
		{Enum, s.modules.WebEnum},
	} {
		if m.enabled {
			out = append(out, Skip{m.mod, ip, svc.Port, proto, reason})
		}
	}
	return out
}

// SortServices returns the host services in a deterministic order: protocol, then
// port, then tunnel. The same discovery result must always produce the same plan,
// and nmap does not promise an order.
func SortServices(services []upstream.DiscoveryService) []upstream.DiscoveryService {
	out := make([]upstream.DiscoveryService, len(services))
	copy(out, services)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if pa, pb := strings.ToLower(a.Protocol), strings.ToLower(b.Protocol); pa != pb {
			return pa < pb
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return strings.ToLower(a.Tunnel) < strings.ToLower(b.Tunnel)
	})
	return out
}

// SortJobs orders the plan by target, transport, port, and module so the event
// sequence for one discovery result is identical on every run.
func SortJobs(jobs []Job) {
	sort.SliceStable(jobs, func(i, j int) bool {
		a, b := jobs[i], jobs[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Module < b.Module
	})
}

// SortSkips orders recorded skips the same way jobs are ordered.
func SortSkips(skips []Skip) {
	sort.SliceStable(skips, func(i, j int) bool {
		a, b := skips[i], skips[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Module < b.Module
	})
}
