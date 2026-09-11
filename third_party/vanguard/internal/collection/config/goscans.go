package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// GoScansTool configures the Siemens GoScans active tool: one nmap-backed
// discovery scan per approved host, followed by banner, TLS, SSH, web crawling,
// and web enumeration against the services that discovery found.
//
// It is an active, free tool. It sends its own traffic, deliberately overlapping
// the port scanner and the HTTPS probe, because two independent observations of
// the same service are worth more than one. It uses no paid API and no credential.
// It does need two things from deployment that a scan never installs for itself:
// an nmap executable with the full NSE script set, and a Python environment that
// can run the pinned SSLyze. Both are checked read-only at startup when the tool
// is enabled, and not checked at all when it is disabled.
//
// The block is required in every profile so behaviour never depends on a struct
// default. When enabled is false the remaining values are still parsed but not
// enforced, which keeps a passive profile readable without making it a scan plan.
type GoScansTool struct {
	// Enabled is the master switch. It may only be true when the active phase is on.
	Enabled *bool `yaml:"enabled"`
	// Timeout bounds the whole tool: every subordinate timeout must fit inside it.
	// Orchestration applies it to the substage's context, and a run that hits it
	// stops starting work and records which approved hosts went unassessed, because
	// a short result must not read as a clean one for the hosts it never reached.
	Timeout Duration `yaml:"timeout"`
	// MaxTargets caps the isolated batch of hosts this tool assesses. It must not
	// exceed the engagement's limits.max_active_hosts when that limit is bounded,
	// because the tool reuses host reservations the scheduler already granted rather
	// than taking new ones. That cross-file check lives in Scan.validateComposition.
	MaxTargets *int `yaml:"max_targets"`
	// MaxParallelServices caps subordinate jobs in flight across the whole tool.
	MaxParallelServices *int `yaml:"max_parallel_services"`
	// MaxParallelServicesPerHost caps subordinate jobs in flight against one host,
	// so one host is never probed harder than this however much of the tool-wide
	// budget is free.
	MaxParallelServicesPerHost *int `yaml:"max_parallel_services_per_host"`
	// DiscoveryFromPortScan scopes this tool's own nmap to the ports the port
	// scanner already found open on a host, instead of letting it sweep its own
	// default range. It removes a second full sweep of every host, which is half
	// this tool's runtime.
	//
	// It is off by default because it trades coverage for time, and the trade is
	// only safe once tools.portscan.ports covers at least as much as the range this
	// tool would have swept. With the shipped 18-port list it does not: a service on
	// an unusual port that only the full sweep would have found becomes invisible to
	// both tools. Turn it on when the port scanner's list has been widened to match.
	//
	// A host the port scanner did not reach is swept in full regardless, so a failed
	// or skipped sweep never turns into a silently narrow assessment.
	DiscoveryFromPortScan *bool `yaml:"discovery_from_port_scan"`
	// MaxParallelTargets caps targets assessed at once. Targets are independent, so
	// this is what keeps one slow host from pacing the whole run. It multiplies with
	// neither cap above: max_parallel_services still bounds the jobs in flight
	// across every target together, which is the tool's traffic ceiling.
	MaxParallelTargets *int `yaml:"max_parallel_targets"`
	// UserAgent identifies the scanner in every web request the tool makes.
	UserAgent string `yaml:"user_agent"`
	// The webcrawler/webenum out-of-scope-HTTP grant is not a profile field: it is a
	// customer authorization owned by the engagement file
	// (authorization.goscans.allow_out_of_scope_http_requests), because it can send a
	// request before the engagement boundary is applied to it.

	// Nmap configures the discovery scan.
	Nmap GoScansNmap `yaml:"nmap"`
	// Sslyze configures the external TLS assessment runtime.
	Sslyze GoScansSslyze `yaml:"sslyze"`
	// Banner configures raw service banner collection.
	Banner GoScansBanner `yaml:"banner"`
	// Ssl configures the SSLyze-backed TLS assessment.
	Ssl GoScansSsl `yaml:"ssl"`
	// Ssh configures the SSH algorithm assessment.
	Ssh GoScansSsh `yaml:"ssh"`
	// WebCrawler configures bounded web crawling.
	WebCrawler GoScansWebCrawler `yaml:"webcrawler"`
	// WebEnum configures bounded web path enumeration.
	WebEnum GoScansWebEnum `yaml:"webenum"`
	// Ports adds protocol hints for ports nmap could not name.
	Ports GoScansPorts `yaml:"ports"`
	// Limits caps how much one host may contribute.
	Limits GoScansLimits `yaml:"limits"`
}

// GoScansNmap configures the discovery scan. The tool runs its own nmap process
// with its own arguments; it shares nothing with the port scanner except, possibly,
// the executable on disk.
type GoScansNmap struct {
	// Path is the nmap executable, resolved through PATH when it is a bare name.
	Path string `yaml:"path"`
	// Args is the argument list, passed as argv with no shell. It is validated
	// against a narrow allowlist: targets, output flags, NSE selection, and
	// raw-socket scan techniques are rejected, because the tool owns those and an
	// unprivileged connect scan is the reviewed baseline.
	Args []string `yaml:"args"`
	// Timeout bounds one discovery scan. It is also the longest a cancelled scan can
	// take to stop, because the upstream discovery module has no cancellation other
	// than this deadline, and abandoning it would orphan the nmap process.
	Timeout Duration `yaml:"timeout"`
	// DialTimeout bounds the extra connections discovery makes while reading subject
	// alternative names off a host it already found.
	DialTimeout Duration `yaml:"dial_timeout"`
}

// GoScansSslyze configures the external TLS assessment runtime. The interpreter is
// deployment-provided and version-pinned; a scan never installs or upgrades it.
type GoScansSslyze struct {
	// PythonPath is the interpreter that can run "python -m sslyze". Required when
	// the ssl module is enabled.
	PythonPath string `yaml:"python_path"`
	// Version is the exact SSLyze version deployment pinned, for example "6.3.1".
	// Startup fails when the environment reports a different one, so a silently
	// upgraded image cannot change what the scan measures.
	Version string `yaml:"version"`
	// AdditionalTruststore is an optional extra CA bundle. SSLyze always applies its
	// own default CAs; this only adds to them. Empty means none.
	AdditionalTruststore string `yaml:"additional_truststore"`
}

// GoScansBanner configures raw banner collection. Every discovered TCP service gets
// a banner probe, so the timeouts here multiply across the whole service inventory.
type GoScansBanner struct {
	// Enabled switches the module on.
	Enabled *bool `yaml:"enabled"`
	// DialTimeout bounds connecting to a service. It also bounds the ssh module's
	// connection, which has no separate knob: both make one plain TCP connection to
	// one discovered service, so it is required whenever banner or ssh is enabled.
	DialTimeout Duration `yaml:"dial_timeout"`
	// ReceiveTimeout bounds waiting for the banner bytes.
	ReceiveTimeout Duration `yaml:"receive_timeout"`
}

// GoScansSsl configures the TLS assessment.
type GoScansSsl struct {
	// Enabled switches the module on. It requires sslyze.python_path and
	// sslyze.version, and turns on the SSLyze part of startup preflight.
	Enabled *bool `yaml:"enabled"`
	// Timeout bounds one SSLyze run against one service.
	Timeout Duration `yaml:"timeout"`
}

// GoScansSsh configures the SSH assessment.
type GoScansSsh struct {
	// Enabled switches the module on.
	Enabled *bool `yaml:"enabled"`
	// Timeout bounds one SSH assessment.
	Timeout Duration `yaml:"timeout"`
}

// GoScansWebCrawler configures bounded web crawling.
type GoScansWebCrawler struct {
	// Enabled switches the module on.
	Enabled *bool `yaml:"enabled"`
	// Timeout bounds one crawl of one web service.
	Timeout Duration `yaml:"timeout"`
	// Depth is the maximum link depth followed from the entry page. It compounds
	// quickly: keep it low unless a specific engagement needs more.
	Depth *int `yaml:"depth"`
	// MaxThreads is the crawler's own request parallelism inside one crawl. It
	// multiplies with max_parallel_services_per_host, and through it with
	// max_parallel_targets, so keep it small.
	MaxThreads *int `yaml:"max_threads"`
	// MaxPages caps how many crawled pages are reported per crawl.
	MaxPages *int `yaml:"max_pages"`
	// RequestTimeout bounds a single HTTP request inside a crawl.
	RequestTimeout Duration `yaml:"request_timeout"`
}

// GoScansWebEnum configures bounded web path enumeration.
type GoScansWebEnum struct {
	// Enabled switches the module on.
	Enabled *bool `yaml:"enabled"`
	// Timeout bounds one enumeration of one web service.
	Timeout Duration `yaml:"timeout"`
	// ProbeProfile names one of the embedded, checksummed probe sets. There is no
	// option to point at a file: an operator-supplied probe list would put unreviewed
	// request paths into the runtime contract of an active scanner.
	ProbeProfile string `yaml:"probe_profile"`
	// ProbeRobots additionally derives probe paths from the target robots.txt.
	ProbeRobots *bool `yaml:"probe_robots"`
	// MaxItems caps how many enumeration hits are reported per service.
	MaxItems *int `yaml:"max_items"`
	// RequestTimeout bounds a single HTTP request inside an enumeration.
	RequestTimeout Duration `yaml:"request_timeout"`
}

// GoScansPorts adds protocol hints. The lists are additive: they say what to assume
// for a port nmap could not name, and never suppress what nmap did recognise.
type GoScansPorts struct {
	// Tls are ports assessed as TLS despite an unrecognised service name.
	Tls []int `yaml:"tls"`
	// Ssh are ports assessed as SSH despite an unrecognised service name.
	Ssh []int `yaml:"ssh"`
	// Http are ports treated as cleartext web despite an unrecognised service name.
	Http []int `yaml:"http"`
	// Https are ports treated as web over TLS despite an unrecognised service name.
	Https []int `yaml:"https"`
}

// GoScansLimits caps how much one host may contribute. Only the caps that change
// what the scanner sends, or how large a report becomes, are operator-tunable; the
// remaining event-payload bounds (cipher, certificate, and algorithm list sizes,
// NSE script output size, forwarded upstream log size) are fixed in the tool.
type GoScansLimits struct {
	// MaxServicesPerHost caps how many discovered services of one host schedule
	// subordinate work. Services beyond the cap are recorded as skips, so a capped
	// host is visibly capped rather than quietly short.
	MaxServicesPerHost *int `yaml:"max_services_per_host"`
	// MaxVhosts caps the virtual hosts passed to one TLS or web job. Each virtual
	// host is a separate pass over the target, so this multiplies request volume.
	MaxVhosts *int `yaml:"max_vhosts"`
	// MaxExcerptBytes caps the redacted excerpt kept from any response body or
	// banner. Full bodies are never stored; the byte count and a digest travel with
	// the excerpt.
	MaxExcerptBytes *int `yaml:"max_excerpt_bytes"`
}

// GoScansEnabled reports whether the GoScans tool is switched on, so an app can
// decide whether to run its external-runtime preflight at startup.
func (c *ScanProfile) GoScansEnabled() bool {
	return c.Tools.GoScans.Enabled != nil && *c.Tools.GoScans.Enabled
}

// goScansModulesEnabled reports whether at least one subordinate module is on.
func (g *GoScansTool) goScansModulesEnabled() bool {
	return isTrue(g.Banner.Enabled) || isTrue(g.Ssl.Enabled) || isTrue(g.Ssh.Enabled) ||
		isTrue(g.WebCrawler.Enabled) || isTrue(g.WebEnum.Enabled)
}

// isTrue reports whether an optional boolean is present and true.
func isTrue(b *bool) bool { return b != nil && *b }

// validateGoScans checks the goscans block. Only the master switch is required when
// the tool is off; everything else is enforced when it is on, so a passive profile
// can carry readable values without them becoming a scan plan.
func (c *ScanProfile) validateGoScans(req func(bool, string)) {
	g := &c.Tools.GoScans
	req(g.Enabled != nil, "tools.goscans.enabled is required")
	if !isTrue(g.Enabled) {
		return
	}

	req(isTrue(c.Phases.Active.Enabled),
		"tools.goscans.enabled is true but phases.active.enabled is not: goscans sends active traffic and cannot run in a passive scan")
	req(g.Timeout > 0, "tools.goscans.timeout is required (e.g. \"15m\")")
	req(g.MaxTargets != nil && *g.MaxTargets > 0, "tools.goscans.max_targets must be > 0")
	req(g.MaxParallelServices != nil && *g.MaxParallelServices > 0, "tools.goscans.max_parallel_services must be > 0")
	req(g.MaxParallelServicesPerHost != nil && *g.MaxParallelServicesPerHost > 0,
		"tools.goscans.max_parallel_services_per_host must be > 0")
	req(g.MaxParallelTargets != nil && *g.MaxParallelTargets > 0,
		"tools.goscans.max_parallel_targets must be > 0")
	req(strings.TrimSpace(g.UserAgent) != "", "tools.goscans.user_agent is required")

	// tools.goscans.max_targets must not exceed the engagement's active-host limit;
	// that check spans both files and lives in Scan.validateComposition.

	req(g.goScansModulesEnabled(),
		"tools.goscans has every subordinate module disabled: enable at least one, or set tools.goscans.enabled to false instead of running a discovery-only scan by accident")

	c.validateGoScansNmap(req)
	c.validateGoScansModules(req)
	c.validateGoScansPortsAndLimits(req)
}

// validateGoScansNmap checks the discovery scan configuration and the argument
// allowlist.
func (c *ScanProfile) validateGoScansNmap(req func(bool, string)) {
	g := &c.Tools.GoScans
	req(strings.TrimSpace(g.Nmap.Path) != "", "tools.goscans.nmap.path is required (e.g. \"nmap\")")
	req(len(g.Nmap.Args) > 0, "tools.goscans.nmap.args is required (e.g. [-sT, -sV, -Pn, -T4])")
	req(g.Nmap.Timeout > 0, "tools.goscans.nmap.timeout is required (e.g. \"5m\")")
	req(g.Nmap.DialTimeout > 0, "tools.goscans.nmap.dial_timeout is required (e.g. \"5s\")")
	if g.Timeout > 0 && g.Nmap.Timeout > 0 {
		req(g.Nmap.Timeout <= g.Timeout, "tools.goscans.nmap.timeout must not exceed tools.goscans.timeout")
	}
	for _, problem := range validateGoScansNmapArgs(g.Nmap.Args) {
		req(false, problem)
	}
	if strings.TrimSpace(g.Sslyze.AdditionalTruststore) != "" {
		req(filepath.IsAbs(g.Sslyze.AdditionalTruststore),
			"tools.goscans.sslyze.additional_truststore must be an absolute path")
	}
}

// validateGoScansModules checks each subordinate module block.
func (c *ScanProfile) validateGoScansModules(req func(bool, string)) {
	g := &c.Tools.GoScans
	fits := func(d Duration, key string) {
		req(d > 0, "tools.goscans."+key+" is required and must be > 0")
		if g.Timeout > 0 && d > 0 {
			req(d <= g.Timeout, "tools.goscans."+key+" must not exceed tools.goscans.timeout")
		}
	}

	req(g.Banner.Enabled != nil, "tools.goscans.banner.enabled is required")
	if isTrue(g.Banner.Enabled) {
		fits(g.Banner.ReceiveTimeout, "banner.receive_timeout")
	}
	// banner.dial_timeout is the TCP connect bound for the banner module and for the
	// ssh module, which has no separate knob: both make one plain connection to one
	// discovered service. It is therefore required whenever either module is on.
	if isTrue(g.Banner.Enabled) || isTrue(g.Ssh.Enabled) {
		fits(g.Banner.DialTimeout, "banner.dial_timeout")
	}

	req(g.Ssl.Enabled != nil, "tools.goscans.ssl.enabled is required")
	if isTrue(g.Ssl.Enabled) {
		fits(g.Ssl.Timeout, "ssl.timeout")
		req(strings.TrimSpace(g.Sslyze.PythonPath) != "",
			"tools.goscans.sslyze.python_path is required when tools.goscans.ssl.enabled is true")
		req(strings.TrimSpace(g.Sslyze.Version) != "",
			"tools.goscans.sslyze.version is required when tools.goscans.ssl.enabled is true (pin the deployed SSLyze version, e.g. \"6.3.1\")")
	}

	req(g.Ssh.Enabled != nil, "tools.goscans.ssh.enabled is required")
	if isTrue(g.Ssh.Enabled) {
		fits(g.Ssh.Timeout, "ssh.timeout")
	}

	req(g.WebCrawler.Enabled != nil, "tools.goscans.webcrawler.enabled is required")
	if isTrue(g.WebCrawler.Enabled) {
		fits(g.WebCrawler.Timeout, "webcrawler.timeout")
		fits(g.WebCrawler.RequestTimeout, "webcrawler.request_timeout")
		req(g.WebCrawler.Depth != nil && *g.WebCrawler.Depth > 0, "tools.goscans.webcrawler.depth must be > 0")
		req(g.WebCrawler.MaxThreads != nil && *g.WebCrawler.MaxThreads > 0, "tools.goscans.webcrawler.max_threads must be > 0")
		req(g.WebCrawler.MaxPages != nil && *g.WebCrawler.MaxPages > 0, "tools.goscans.webcrawler.max_pages must be > 0")
	}

	req(g.WebEnum.Enabled != nil, "tools.goscans.webenum.enabled is required")
	if isTrue(g.WebEnum.Enabled) {
		fits(g.WebEnum.Timeout, "webenum.timeout")
		fits(g.WebEnum.RequestTimeout, "webenum.request_timeout")
		req(g.WebEnum.ProbeRobots != nil, "tools.goscans.webenum.probe_robots is required")
		req(g.WebEnum.MaxItems != nil && *g.WebEnum.MaxItems > 0, "tools.goscans.webenum.max_items must be > 0")
		req(GoScansProbeProfiles[g.WebEnum.ProbeProfile],
			fmt.Sprintf("tools.goscans.webenum.probe_profile %q is not an embedded profile (allowed: %s)",
				g.WebEnum.ProbeProfile, strings.Join(goScansProbeProfileNames(), ", ")))
	}
}

// validateGoScansPortsAndLimits checks the port hints and the operator-tunable caps.
func (c *ScanProfile) validateGoScansPortsAndLimits(req func(bool, string)) {
	g := &c.Tools.GoScans
	for _, list := range []struct {
		key   string
		ports []int
	}{
		{"tls", g.Ports.Tls}, {"ssh", g.Ports.Ssh}, {"http", g.Ports.Http}, {"https", g.Ports.Https},
	} {
		for _, p := range list.ports {
			req(p > 0 && p <= 65535,
				fmt.Sprintf("tools.goscans.ports.%s contains invalid port %d (must be 1-65535)", list.key, p))
		}
	}
	req(g.Limits.MaxServicesPerHost != nil && *g.Limits.MaxServicesPerHost > 0,
		"tools.goscans.limits.max_services_per_host must be > 0")
	req(g.Limits.MaxVhosts != nil && *g.Limits.MaxVhosts > 0, "tools.goscans.limits.max_vhosts must be > 0")
	req(g.Limits.MaxExcerptBytes != nil && *g.Limits.MaxExcerptBytes > 0,
		"tools.goscans.limits.max_excerpt_bytes must be > 0")
}

// GoScansProbeProfiles are the embedded web enumeration probe sets a configuration
// may name. There is no file-path option on purpose: an operator-supplied probe
// list would put unreviewed request paths into an active scanner's contract.
var GoScansProbeProfiles = map[string]bool{
	"embedded-safe-default": true,
}

// goScansProbeProfileNames lists the allowed profiles for an error message.
func goScansProbeProfileNames() []string {
	names := make([]string, 0, len(GoScansProbeProfiles))
	for name := range GoScansProbeProfiles {
		names = append(names, name)
	}
	return names
}

// Repeated rejection reasons, so a whole family of flags gives one consistent
// answer instead of eight slightly different ones.
const (
	whyRawSocket        = "raw-socket scan techniques need privileges the scan does not hold; use -sT"
	whyToolOwnsOutput   = "scan output is owned by the tool"
	whyToolOwnsScripts  = "the NSE script list is fixed by the tool"
	whyScopeOwnsTargets = "scope exclusion is enforced before a target reaches this tool"
)

// goScansRejectedNmapArgs maps a forbidden argument to why it is forbidden. These
// are rejected by name rather than falling through to the generic "unsupported
// flag" message, because each one has a specific, actionable answer.
var goScansRejectedNmapArgs = map[string]string{
	"-sU":                "UDP scanning belongs to tools.portscan: upstream goscans discovery keeps only ports whose nmap state is exactly \"open\", and an unanswered UDP port is \"open|filtered\", so -sU spends UDP traffic and returns nothing",
	"-sS":                whyRawSocket,
	"-sA":                whyRawSocket,
	"-sF":                whyRawSocket,
	"-sN":                whyRawSocket,
	"-sX":                whyRawSocket,
	"-sW":                whyRawSocket,
	"-sM":                whyRawSocket,
	"-sO":                whyRawSocket,
	"-O":                 "OS fingerprinting needs raw sockets the scan does not hold",
	"--privileged":       "the scan runs unprivileged by design; do not claim privileges it does not have",
	"--unprivileged":     "privilege mode is decided by deployment, not by scan arguments",
	"--script-updatedb":  "a scan never updates the NSE database",
	"--datadir":          "the nmap data directory is owned by deployment",
	"--reason":           "the tool adds this argument itself",
	"--webxml":           "the tool adds this argument itself",
	"-iL":                "targets come from the scan scope, not from a file",
	"-iR":                "random targets are never in scope",
	"--exclude":          whyScopeOwnsTargets,
	"--excludefile":      whyScopeOwnsTargets,
	"-oA":                whyToolOwnsOutput,
	"-oN":                whyToolOwnsOutput,
	"-oX":                whyToolOwnsOutput,
	"-oG":                whyToolOwnsOutput,
	"-oS":                whyToolOwnsOutput,
	"--stylesheet":       whyToolOwnsOutput,
	"--resume":           "a scan is never resumed from an nmap output file",
	"--script":           whyToolOwnsScripts,
	"--script-args":      whyToolOwnsScripts,
	"--script-args-file": whyToolOwnsScripts,
}

// goScansAllowedNmapArgs is the reviewed argument allowlist for the discovery scan.
var goScansAllowedNmapArgs = map[string]bool{
	"-sT": true, "-sV": true, "-Pn": true, "-6": true, "-n": true, "-R": true,
	"--open": true, "--version-light": true, "--version-all": true, "--traceroute": true,
}

// goScansValuedNmapArgs are allowed arguments that take a value, in either
// "--flag value" or "--flag=value" form.
var goScansValuedNmapArgs = map[string]bool{
	"--host-timeout": true, "--max-retries": true, "--max-rate": true, "--min-rate": true,
	"--max-rtt-timeout": true, "--initial-rtt-timeout": true, "-p": true, "--top-ports": true,
	"--version-intensity": true,
}

// validateGoScansNmapArgs enforces the argument allowlist and returns one problem
// per offending argument. The list is argv, never a shell command line, so a shell
// metacharacter here is a sign the operator expected shell parsing that will not
// happen; it is rejected rather than passed through as a literal.
func validateGoScansNmapArgs(args []string) []string {
	var problems []string
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "" {
			problems = append(problems, "tools.goscans.nmap.args contains an empty argument")
			continue
		}
		if strings.ContainsAny(arg, ";|&<>`$\n") {
			problems = append(problems, fmt.Sprintf(
				"tools.goscans.nmap.args %q contains shell syntax; the list is passed as argv and never through a shell", arg))
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			problems = append(problems, fmt.Sprintf(
				"tools.goscans.nmap.args %q is not a flag; targets are supplied by the scan scope, not by arguments", arg))
			continue
		}

		name, hasValue := arg, false
		if eq := strings.IndexByte(arg, '='); eq > 0 {
			name, hasValue = arg[:eq], true
		}
		if why, rejected := goScansRejectedNmapArgs[name]; rejected {
			problems = append(problems, fmt.Sprintf("tools.goscans.nmap.args %q is not allowed: %s", name, why))
			continue
		}
		if goScansAllowedNmapArgs[name] {
			continue
		}
		if isGoScansTimingTemplate(name) {
			continue
		}
		if goScansValuedNmapArgs[name] {
			if hasValue {
				continue
			}
			if i+1 >= len(args) {
				problems = append(problems, fmt.Sprintf("tools.goscans.nmap.args %q requires a value", name))
				continue
			}
			i++
			continue
		}
		// "-p80,443" is the one nmap flag whose value is commonly glued to it.
		if strings.HasPrefix(arg, "-p") && len(arg) > 2 {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"tools.goscans.nmap.args %q is not in the reviewed allowlist; add it there after a privilege and coverage review rather than passing it through", arg))
	}
	return problems
}

// isGoScansTimingTemplate reports whether arg is an nmap timing template (-T0..-T5).
func isGoScansTimingTemplate(arg string) bool {
	return len(arg) == 3 && strings.HasPrefix(arg, "-T") && arg[2] >= '0' && arg[2] <= '5'
}
