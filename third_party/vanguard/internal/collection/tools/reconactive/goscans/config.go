package goscans

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/plan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/upstream"
)

// Limits caps what one target may contribute to the event stream. They exist
// because the upstream result structures are only partly bounded: banner probes
// are truncated at 2048 bytes upstream, but crawler and enumeration HTML bodies
// are read without a size limit, and a cipher or certificate list is as long as
// the server makes it. Every cap is applied at the event boundary and reported
// with a truncation flag, so a capped result is visibly capped rather than
// silently short.
type Limits struct {
	// MaxServicesPerHost caps how many discovered services one host may schedule
	// work for. Services are considered in port order, so the cap is deterministic.
	MaxServicesPerHost int
	// MaxVhosts caps the virtual hosts passed to one web or TLS job.
	MaxVhosts int
	// MaxCrawlPages caps the page events emitted per crawl job.
	MaxCrawlPages int
	// MaxEnumItems caps the enumeration hits emitted per job.
	MaxEnumItems int
	// MaxCertificates caps the certificate chains reported per TLS job.
	MaxCertificates int
	// MaxCiphers caps the accepted cipher suites reported per TLS job.
	MaxCiphers int
	// MaxSSHAlgorithms caps each SSH algorithm list.
	MaxSSHAlgorithms int
	// MaxScriptOutputBytes caps NSE script output kept per script.
	MaxScriptOutputBytes int
	// MaxExcerptBytes caps the redacted excerpt kept from any response body or
	// banner. The full byte count and a digest are reported alongside it.
	MaxExcerptBytes int
	// MaxUpstreamLogBytes caps one forwarded upstream log line.
	MaxUpstreamLogBytes int
}

// DefaultLimits are deliberately small. This tool corroborates other tools rather
// than replacing them, so a target that produces a thousand pages is a target
// worth truncating, not worth recording in full.
func DefaultLimits() Limits {
	return Limits{
		MaxServicesPerHost:   200,
		MaxVhosts:            25,
		MaxCrawlPages:        200,
		MaxEnumItems:         100,
		MaxCertificates:      10,
		MaxCiphers:           100,
		MaxSSHAlgorithms:     50,
		MaxScriptOutputBytes: 4096,
		MaxExcerptBytes:      512,
		MaxUpstreamLogBytes:  512,
	}
}

// Runtime is the external dependency set the startup check resolved: the nmap and
// Python executables that were actually found on this machine and the versions
// they reported.
//
// It travels with the configuration so the run records the runtime that produced
// its results rather than the one the configuration asked for. Those differ more
// often than they should: a path resolves through PATH to a different binary than
// the operator expected, or an image is rebuilt on a newer base. A finding about a
// weak cipher is only as reproducible as the SSLyze that measured it, so the
// version belongs in the stream next to the finding.
type Runtime struct {
	// NmapPath is the resolved absolute nmap executable, and NmapVersion the
	// version it reported.
	NmapPath    string
	NmapVersion string
	// PythonPath is the resolved interpreter that runs SSLyze, and PythonVersion
	// the version it reported. Both are empty when the TLS module is off, because
	// nothing then checks or runs an interpreter.
	PythonPath    string
	PythonVersion string
	// SslyzeVersion is the version the resolved environment reported, which
	// startup already required to equal the pinned one.
	SslyzeVersion string
}

// Config is the immutable snapshot the actor runs from. It is validated once, in
// New, before any network operation: an invalid executable path, timeout, or limit
// is a configuration bug and must not surface halfway through a scan.
type Config struct {
	// NmapPath is the nmap executable GoScans discovery runs. It may be the same
	// executable the port scanner uses, but nothing else is shared: this tool builds
	// its own arguments, its own process, and its own results.
	NmapPath string
	// NmapArgs are the raw scan arguments. Upstream always appends --reason, --webxml,
	// and its forced NSE script list on top. TCP only for now: a UDP technique here
	// would spend traffic and return almost nothing, because upstream discovery keeps
	// only ports in state "open" and nmap reports an unanswered UDP port as
	// "open|filtered".
	NmapArgs []string
	// PythonPath is the interpreter that can run "python -m sslyze" (the SSLyze
	// executable on Windows). Required when Modules.TLS is set.
	PythonPath string
	// SslyzeAdditionalTruststore is an optional extra CA bundle file handed to
	// SSLyze. It only adds to the SSLyze default CA set, which always applies.
	// Empty means the default set alone decides trust.
	SslyzeAdditionalTruststore string
	// Runtime is what the startup dependency check actually resolved on this
	// machine. It is reported, never enforced: the check that fails a wrong version
	// already ran before the actor was built, and an empty Runtime simply means
	// nobody resolved one, which is the normal case in a test.
	Runtime Runtime

	// Modules selects the subordinate assessments.
	Modules Modules

	// TLSPorts are ports treated as TLS even when discovery reports no SSL tunnel
	// and an unrecognized service name.
	TLSPorts []int
	// SSHPorts are ports treated as SSH even when discovery reports an unrecognized
	// service name.
	SSHPorts []int
	// HTTPPorts are ports treated as cleartext web even when discovery reports an
	// unrecognized service name.
	HTTPPorts []int
	// HTTPSPorts are ports treated as TLS web even when discovery reports an
	// unrecognized service name.
	HTTPSPorts []int

	// DiscoveryTimeout bounds one discovery scan. It is also the longest the actor
	// can be blocked after cancellation, because upstream discovery has no context.
	DiscoveryTimeout time.Duration
	// DiscoveryDialTimeout bounds the extra connections discovery makes while
	// post-processing a host for subject alternative names.
	DiscoveryDialTimeout time.Duration
	// BannerDialTimeout bounds connecting to a service for a banner.
	BannerDialTimeout time.Duration
	// BannerReceiveTimeout bounds waiting for banner bytes.
	BannerReceiveTimeout time.Duration
	// TLSTimeout bounds one SSLyze run.
	TLSTimeout time.Duration
	// SSHTimeout bounds one SSH assessment.
	SSHTimeout time.Duration
	// CrawlTimeout bounds one crawl job.
	CrawlTimeout time.Duration
	// CrawlRequestTimeout bounds a single HTTP request inside a crawl.
	CrawlRequestTimeout time.Duration
	// EnumTimeout bounds one enumeration job.
	EnumTimeout time.Duration
	// EnumRequestTimeout bounds a single HTTP request inside an enumeration.
	EnumRequestTimeout time.Duration

	// MaxConcurrency caps subordinate jobs in flight across the whole actor. It is
	// the tool's traffic ceiling: no arrangement of targets and hosts exceeds it.
	MaxConcurrency int
	// MaxConcurrencyPerHost caps subordinate jobs in flight against one host, so a
	// single host is never probed harder than this however much of the tool-wide
	// budget is free. Neither knob has to be kept consistent with the other: a
	// per-host cap above the tool-wide one simply never binds.
	MaxConcurrencyPerHost int
	// MaxParallelTargets caps targets assessed at once. Targets are otherwise
	// independent, so this is what keeps one slow host from pacing the whole run,
	// and it multiplies with neither cap above: MaxConcurrency still bounds the
	// jobs in flight across every target together.
	MaxParallelTargets int

	// CrawlDepth is the maximum link depth followed from a crawl entry page.
	CrawlDepth int
	// CrawlThreads is the crawler request parallelism within one crawl job. It
	// multiplies with MaxConcurrencyPerHost, and through it with the number of
	// targets in flight, so keep it small.
	CrawlThreads int
	// ProbeRobots additionally derives enumeration probes from robots.txt.
	ProbeRobots bool
	// UserAgent identifies the scanner in web requests.
	UserAgent string

	// Limits caps what one target contributes to the event stream.
	Limits Limits

	// TempRoot is the parent directory the actor creates its own temporary root in.
	// Empty uses the system temporary directory. The actor never writes outside the
	// root it creates, and removes it on success, failure, and cancellation.
	TempRoot string

	// Sink receives every tool event. A nil sink drops them.
	Sink tooleventlog.EventSink
	// Upstream builds the GoScans scanners. Nil selects the live implementation;
	// tests substitute a fake.
	Upstream upstream.Upstream

	// AllowUnscopedWebModules lets WebCrawl and WebEnum run against the live
	// upstream implementation even though its requester follows redirects and
	// resolves links on its own, with no seam to authorize a destination before
	// dialing it. Without it those modules are refused here, before the first
	// packet, because the caller cannot keep their traffic inside the engagement.
	//
	// It exists so an operator with an explicit mandate can trade that guarantee
	// for the crawler's coverage. The caller that sets it owns two obligations: it
	// must have been asked for deliberately, and it must apply its own boundary to
	// the results instead, marking every observation of a destination it would have
	// refused so later analysis can tell it apart from scope-enforced evidence.
	AllowUnscopedWebModules bool
}

// Modules selects which subordinate assessments run after discovery. It is an
// alias so a caller configures the tool from this one package: the planning types
// live in the plan subpackage because that is where the selection tables are, but
// nothing outside the tool should have to import a leaf of it to switch a module on.
type Modules = plan.Modules

// selectorOptions projects the configuration onto the pure planning inputs, so the
// selection tables never see a timeout, a path, or a sink.
func (c *Config) selectorOptions() plan.Options {
	return plan.Options{
		Modules:            c.Modules,
		TLSPorts:           c.TLSPorts,
		SSHPorts:           c.SSHPorts,
		HTTPPorts:          c.HTTPPorts,
		HTTPSPorts:         c.HTTPSPorts,
		MaxServicesPerHost: c.Limits.MaxServicesPerHost,
	}
}

// Target is one scope-approved host to assess. It carries only data orchestration
// already approved: no other active tool result may add, remove, or reprioritize
// anything here.
type Target struct {
	// IP is the canonical address to scan.
	IP string
	// Vhosts are the virtual host names passed to the TLS and web modules, from
	// passive inventory only.
	Vhosts []string
	// DomainOrder ranks candidate domains by plausibility for discovery name
	// selection. Order is significant and is preserved as given.
	DomainOrder []string
	// Ports scopes discovery to a known set of open TCP ports instead of letting it
	// sweep its own default range. It is supplied when another tool has already
	// swept this host, so the sweep is not paid for twice.
	//
	// Empty means full discovery, and that is the safe reading: a host nothing else
	// reached, or one whose sweep failed, must still be swept here rather than
	// silently assessed as having nothing open. The distinction matters because an
	// empty port set and an unscanned host look identical afterwards.
	Ports []int
}

// normalize returns the target with a trimmed IP and its vhosts trimmed, lowercased,
// deduplicated, and sorted, so the same passive inventory always produces the same
// job plan regardless of discovery order.
func (t Target) normalize(maxVhosts int) Target {
	out := Target{IP: strings.TrimSpace(t.IP), DomainOrder: t.DomainOrder, Ports: normalizePorts(t.Ports)}
	seen := make(map[string]struct{}, len(t.Vhosts))
	for _, v := range t.Vhosts {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || v == out.IP {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out.Vhosts = append(out.Vhosts, v)
	}
	sort.Strings(out.Vhosts)
	if maxVhosts > 0 && len(out.Vhosts) > maxVhosts {
		out.Vhosts = out.Vhosts[:maxVhosts]
	}
	return out
}

// normalizePorts sorts a supplied port set, drops duplicates, and drops anything
// outside the valid TCP range, so the same input always renders the same scan
// argument and a bad entry cannot reach the command line.
//
// A set that had entries but none usable returns nil, which means full discovery.
// That is the honest reading of it: nothing was said about which ports to scan, so
// nothing may be assumed about the ones not scanned.
func normalizePorts(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, 0, len(in))
	seen := make(map[int]struct{}, len(in))
	for _, p := range in {
		if p < 1 || p > 65535 {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Ints(out)
	return out
}

// validate checks the configuration completely before the first network operation.
// It reports the first problem it finds, naming the field, because a scan that
// starts on a half-valid configuration wastes traffic against real targets.
func (c *Config) validate() error {
	if strings.TrimSpace(c.NmapPath) == "" {
		return fmt.Errorf("goscans: Config.NmapPath must not be empty")
	}
	if c.Modules.TLS && strings.TrimSpace(c.PythonPath) == "" {
		return fmt.Errorf("goscans: Config.PythonPath is required when the TLS module is enabled")
	}
	if strings.TrimSpace(c.UserAgent) == "" {
		return fmt.Errorf("goscans: Config.UserAgent must not be empty")
	}
	if c.Upstream == nil && (c.Modules.WebCrawl || c.Modules.WebEnum) && !c.AllowUnscopedWebModules {
		return fmt.Errorf("goscans: WebCrawl and WebEnum are unavailable with the upstream implementation because its internal redirect loop cannot enforce engagement scope without modifying third-party vendor code; set Config.AllowUnscopedWebModules to run them anyway and mark what they produce as unscoped")
	}
	// Only the values an enabled module actually reads are required. A disabled
	// module's timeout is not a setting the caller has to invent, and demanding one
	// would turn "this module is off" into a startup failure.
	for _, d := range []struct {
		name     string
		val      time.Duration
		required bool
	}{
		{"DiscoveryTimeout", c.DiscoveryTimeout, true},
		{"DiscoveryDialTimeout", c.DiscoveryDialTimeout, true},
		// The banner dial timeout also bounds the SSH module's connection: both make
		// one plain TCP connection to one discovered service, so there is one knob.
		{"BannerDialTimeout", c.BannerDialTimeout, c.Modules.Banner || c.Modules.SSH},
		{"BannerReceiveTimeout", c.BannerReceiveTimeout, c.Modules.Banner},
		{"TLSTimeout", c.TLSTimeout, c.Modules.TLS},
		{"SSHTimeout", c.SSHTimeout, c.Modules.SSH},
		{"CrawlTimeout", c.CrawlTimeout, c.Modules.WebCrawl},
		{"CrawlRequestTimeout", c.CrawlRequestTimeout, c.Modules.WebCrawl},
		{"EnumTimeout", c.EnumTimeout, c.Modules.WebEnum},
		{"EnumRequestTimeout", c.EnumRequestTimeout, c.Modules.WebEnum},
	} {
		if d.required && d.val <= 0 {
			return fmt.Errorf("goscans: Config.%s must be positive", d.name)
		}
	}
	if c.Modules.WebCrawl {
		for _, n := range []struct {
			name string
			val  int
		}{
			{"CrawlDepth", c.CrawlDepth},
			{"CrawlThreads", c.CrawlThreads},
		} {
			if n.val <= 0 {
				return fmt.Errorf("goscans: Config.%s must be positive", n.name)
			}
		}
	}
	for _, n := range []struct {
		name string
		val  int
	}{
		{"MaxConcurrency", c.MaxConcurrency},
		{"MaxConcurrencyPerHost", c.MaxConcurrencyPerHost},
		{"MaxParallelTargets", c.MaxParallelTargets},
		{"Limits.MaxServicesPerHost", c.Limits.MaxServicesPerHost},
		{"Limits.MaxVhosts", c.Limits.MaxVhosts},
		{"Limits.MaxCrawlPages", c.Limits.MaxCrawlPages},
		{"Limits.MaxEnumItems", c.Limits.MaxEnumItems},
		{"Limits.MaxCertificates", c.Limits.MaxCertificates},
		{"Limits.MaxCiphers", c.Limits.MaxCiphers},
		{"Limits.MaxSSHAlgorithms", c.Limits.MaxSSHAlgorithms},
		{"Limits.MaxScriptOutputBytes", c.Limits.MaxScriptOutputBytes},
		{"Limits.MaxExcerptBytes", c.Limits.MaxExcerptBytes},
		{"Limits.MaxUpstreamLogBytes", c.Limits.MaxUpstreamLogBytes},
	} {
		if n.val <= 0 {
			return fmt.Errorf("goscans: Config.%s must be positive", n.name)
		}
	}
	for _, a := range c.NmapArgs {
		if strings.EqualFold(strings.TrimSpace(a), "-sU") {
			return fmt.Errorf("goscans: Config.NmapArgs must not request a UDP scan: upstream discovery keeps only ports in state \"open\" and drops every unanswered UDP port")
		}
	}
	return nil
}

// validateTargets rejects an empty or malformed target list. Hostnames are refused
// on purpose: orchestration resolves names, and letting a name through here would
// make the job plan depend on this actor's own resolver.
func validateTargets(targets []Target) error {
	if len(targets) == 0 {
		return fmt.Errorf("goscans: at least one target is required")
	}
	for i, t := range targets {
		ip := strings.TrimSpace(t.IP)
		if ip == "" {
			return fmt.Errorf("goscans: target %d has an empty IP", i)
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("goscans: target %d IP %q is not a valid IP address", i, ip)
		}
	}
	return nil
}
