package orchestration

import (
	"context"
	"net/netip"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/httpprobe"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/https"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/portscan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/smtp"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/wappalyzer"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/webinfo"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/asn"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/breach"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/censys"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/certspotter"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/crtsh"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/dnsinfo"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/mailsec"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/netlas"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/shodan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/subfinder"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/virustotal"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/websearch"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/whois"
)

// Config fully and explicitly defines a scan. It carries no defaults: every
// value must be set pby the caller. Apps build it from the audit configuration
// file (see internal/collection/config), so a scan is reproducible from that file alone.
//
// A tool runs only if both its phase and the tool itself are enabled.
type Config struct {
	// Environment is the execution provenance payload emitted immediately after
	// ScanStarted. The orchestrator supplies the event envelope.
	Environment events.ScanEnvironmentRecorded
	// Phase toggles.
	EnablePassive bool
	EnableActive  bool

	// Per-tool toggles. crt.sh and Censys are absent: each is controlled by the
	// mode in its own tool config (Crtsh.Mode, Censys.Mode), which is the sole
	// authority for whether the tool is constructed, logged, and scheduled.
	EnableCertspotter bool
	EnableSubfinder   bool
	EnableDnsInfo     bool
	// EnableZoneTransfer runs the direct authoritative-server AXFR check in the
	// active phase after passive DNS has supplied nameservers.
	EnableZoneTransfer bool
	EnableAsnInfo      bool
	EnableWhois        bool
	EnableMailSec      bool
	EnableBreach       bool
	EnableVirusTotal   bool
	EnableWebSearch    bool
	EnableShodan       bool
	EnableNetlas       bool
	EnablePortScan     bool
	// EnablePortScanUDP turns on the port scanner's sibling UDP pass. It is not a
	// second tool and not a second budget: the UDP pass reuses the admitted host,
	// its concurrency slot, and its deadline, and runs sequentially with that
	// host's TCP pass. Off, the TCP flow is exactly what it was before UDP existed.
	EnablePortScanUDP bool
	EnableHttpProbe   bool
	EnableHttps       bool
	EnableSmtp        bool
	EnableWebInfo     bool
	// EnableWappalyzer turns on the standalone WappalyzerGo fingerprint probe. It is
	// independent: it reads no other HTTP tool's flag and no other HTTP tool's flag
	// reads it, so it runs alone or beside them.
	EnableWappalyzer bool
	// EnableGoScans turns on the terminal GoScans substage. It is an active host tool
	// like the port scanner and is approved through the same gates, but it runs after
	// the streaming workers drain rather than per arriving IP.
	EnableGoScans bool

	// Tool settings.
	Crtsh       crtsh.Config
	Certspotter certspotter.Config
	Subfinder   subfinder.Config
	DnsInfo     dnsinfo.Config
	AsnInfo     asn.Config
	Whois       whois.Config
	MailSec     mailsec.Config
	Breach      breach.Config
	Censys      censys.Config
	Virustotal  virustotal.Config
	WebSearch   websearch.Config
	Shodan      shodan.Config
	Netlas      netlas.Config
	ActivePorts []int
	// ActiveUDPPorts is the exact UDP port list probed on every admitted host. It
	// is separate from ActivePorts because the two transports are independent
	// passes: a UDP list is a short, reviewed discovery set, not the TCP list read
	// over a different protocol.
	ActiveUDPPorts []int
	PortScan       portscan.Config
	// PortScanHostConcurrency caps simultaneous per-host naabu runners. It is
	// separate from both the per-runner packet rate and the shared discovery cap.
	PortScanHostConcurrency int
	HttpProbe               httpprobe.Config
	Https                   https.Config
	Smtp                    smtp.Config
	WebInfo                 webinfo.Config
	Wappalyzer              wappalyzer.Config
	// GoScans is the isolated actor's own immutable run snapshot. Nothing in it is
	// shared with another tool: the executable path may coincide with the port
	// scanner's, but the arguments, processes, timeouts, limits, and results do not.
	GoScans goscans.Config
	// GoScansMaxTargets caps the isolated batch of approved hosts the substage
	// assesses; positive values are required when enabled. It is a lower cap inside the global active-host
	// budget, not a second budget: an approved host costs one budget unit whether one
	// host tool probes it or both do.
	GoScansMaxTargets int
	// GoScansDiscoveryFromPortScan scopes the substage's own nmap to the ports the
	// port scanner already found open, rather than letting it sweep its own default
	// range. It is off unless the port scanner's own port list is wide enough that
	// narrowing costs no coverage; see the tool configuration for the trade.
	GoScansDiscoveryFromPortScan bool
	// GoScansIgnoreHTTPScope lets the substage run the GoScans webcrawler and
	// webenum modules even though the upstream requester owns its redirect and link
	// following and cannot ask the request authorizer before dialing. It is off by
	// default: the modules are cleared before construction and the lost coverage is
	// recorded as an issue.
	//
	// Turning it on is an engagement decision, not a tuning knob. It readmits the one
	// HTTP path in the scan whose destinations cannot be checked before the dial, so
	// it needs a mandate that tolerates a request to wherever a crawl leads. The
	// stage records the override once for the run, then applies the scope to each
	// result instead of to each request: an endpoint the policy would have allowed is
	// ordinary evidence, and one it would have refused keeps its data but is stamped
	// unscoped and its host reported, so the out-of-scope contacts stay identifiable
	// in the event stream, the asset provenance, and the report.
	GoScansIgnoreHTTPScope bool
	// GoScansTimeout bounds the whole substage. It is applied here rather than
	// inside the actor because expiring it is a coverage decision: the stage records
	// which approved hosts went unassessed instead of letting a short result read as
	// the estate's answer. The actor drains work already in flight before returning,
	// so this bounds when new work stops rather than when the last child process does.
	GoScansTimeout time.Duration

	// Discovery / crawler settings.
	MaxConcurrency int
	MaxDepth       int
	RestrictToRoot bool

	// CertspotterCrossCheckMinRatio is the minimum acceptable ratio of crt.sh's
	// discovered subdomain count to certspotter's before the passive phase raises a
	// coverage warning (crtsh_count < ratio * certspotter_count). 0 disables the
	// cross-check. See coverage.go.
	CertspotterCrossCheckMinRatio float64

	// Root is the scanned domain: the engagement's scan root, and the target every
	// discovery starts from. It is the run's identity in the event stream, stamped on
	// ScanStarted and ScanCompleted, and Run refuses an empty one.
	Root string

	// Scope and budget settings keep a run focused on one customer. The root above is
	// the scanned domain; Include/Exclude/DepthCap refine it.
	ScopeInclude  []string
	ScopeExclude  []string
	ScopeDepthCap int
	// ScopeExcludeIPs are the canonical (masked) excluded CIDR prefixes from the
	// engagement's scope.ip_ranges.exclude. Every address they contain is a hard
	// traffic boundary for active tools: the deny wins over any domain that resolves
	// to it. Compiled once here so no tool re-parses the YAML list.
	ScopeExcludeIPs []netip.Prefix
	// MaxPaidLookupsPerTool caps calls to each paid tool (breach/censys/virustotal/
	// shodan/netlas); -1 means unlimited. MaxActiveHosts caps the combined active
	// sweep (per-domain probes and per-IP host scans share the cap). For both fields,
	// -1 means unlimited and 0 permits no work.
	MaxPaidLookupsPerTool int
	MaxActiveHosts        int
	// ProviderHostProbePolicy gates active probing of provider-only IPs - an address a
	// Censys/Shodan/Netlas host-intel provider attributed to an in-scope domain but
	// that domain's own DNS never resolved. The asset-graph and findings integration
	// ignore it; only the provider-host scheduling path is gated.
	ProviderHostProbePolicy ProviderHostProbePolicy

	// ScanID, when non-empty, fixes the scan identity instead of generating a fresh
	// one in Run. The app sets it to the identity it also records in the capture
	// manifest, so the manifest and the event stream of one collection cannot
	// disagree; an empty value makes Run generate its own.
	ScanID string

	// DomainEventSink and the per-tool Sink fields are wired by the app, not the
	// configuration file.
	DomainEventSink events.DomainEventSink

	// GoScansBuilder overrides how the terminal GoScans substage builds its runner.
	// Nil (the normal case) builds the real actor.
	GoScansBuilder GoScansBuilder
}

// ProviderHostProbePolicy is the resolved provider-only active-probe policy.
type ProviderHostProbePolicy string

const (
	// ProviderHostProbeNever never probes provider-only hosts.
	ProviderHostProbeNever ProviderHostProbePolicy = "never"
	// ProviderHostProbeCorroborated requires independent ownership evidence.
	ProviderHostProbeCorroborated ProviderHostProbePolicy = "corroborated"
	// ProviderHostProbeAlways trusts the provider attribution.
	ProviderHostProbeAlways ProviderHostProbePolicy = "always"
)

// SetGoScansRuntime records the external dependency set an app's startup checks
// resolved on this machine, so the GoScans tool reports the nmap and SSLyze that
// actually produced its results rather than the paths the configuration named.
//
// It takes plain strings rather than the tool's own type so an app can pass what it
// resolved without depending on the tool package: the orchestrator is what owns the
// actor's configuration, and the value is not in the config file. Leaving it unset
// is normal in a test, and reports the runtime as absent.
func (c *Config) SetGoScansRuntime(nmapPath, nmapVersion, pythonPath, pythonVersion, sslyzeVersion string) {
	c.GoScans.Runtime = goscans.Runtime{
		NmapPath:      nmapPath,
		NmapVersion:   nmapVersion,
		PythonPath:    pythonPath,
		PythonVersion: pythonVersion,
		SslyzeVersion: sslyzeVersion,
	}
}

// SetPortScanUDPRuntime records what the startup checks established about the
// nmap that will run the UDP pass: the absolute executable they resolved and
// proved able to open a raw socket, and whether that nmap needs --privileged on
// this machine. Neither value is in the configuration file - the first resolves
// through PATH to whatever is there on the day, and the second depends on how the
// capability was granted - so both have to arrive from the checks that measured
// them.
//
// It takes plain values rather than the app's own type so an app can pass what it
// resolved without the orchestrator depending on the package that resolved it.
// Leaving it unset is normal in a test; a client built from an unset runtime
// refuses to run a UDP pass rather than searching PATH at scan time.
func (c *Config) SetPortScanUDPRuntime(nmapPath string, privileged bool) {
	c.PortScan.UDP.NmapPath = nmapPath
	c.PortScan.UDP.Privileged = privileged
}

// GoScansRunner is the terminal GoScans substage capability the orchestrator
// drives: one bounded run over a fixed, already-approved target list, reporting
// everything it learns as tool events. *goscans.Actor satisfies it.
type GoScansRunner interface {
	Run(ctx context.Context) error
}

// GoScansBuilder builds the runner for one execution. The tool is built per run
// rather than injected ready-made, because the target list is part of the actor's
// identity: it is validated and normalized at construction, before any traffic. Nil
// selects the real actor; a test substitutes a fake so target collection, capping,
// and stage lifecycle can be exercised without nmap.
type GoScansBuilder func(cfg goscans.Config, targets []goscans.Target) (GoScansRunner, error)

// certificateProber is the one-handshake ownership check used by the corroborated
// provider-host policy. *https.Client satisfies it.
type certificateProber interface {
	ProbeCertificate(ctx context.Context, address, serverName string) (*https.CertificateEvidence, error)
}
