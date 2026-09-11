package orchestration

import (
	"slices"

	"github.com/velgard-sk/vanguard/internal/collection/config"
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

// FromConfig maps a validated scan profile and engagement to a Config. It must be
// called only after config.ScanProfile.Validate, config.ScanProfile.ValidateAPIKeys,
// and config.EngagementConfig.Validate have all succeeded (config.LoadScan does the
// per-file and cross-file checks); it dereferences required pointers and assumes any
// paid tool enabled in the profile already has a non-empty key. The profile supplies
// how the scan runs (phases, tools, tuning); the engagement supplies who and where
// (scope, limits, authorizations). DomainEventSink and the per-tool Sink fields are
// left unset for the app to wire.
func FromConfig(c *config.ScanProfile, eng *config.EngagementConfig, keys *config.APIKeys) Config {
	subfinderKeys, subfinderProviders := subfinderProviderPolicy(
		keys,
		*c.Tools.Subfinder.All,
		*c.Tools.VirusTotal.Enabled && *c.Tools.VirusTotal.EnableSubdomains,
	)
	return Config{
		EnablePassive:      *c.Phases.Passive.Enabled,
		EnableActive:       *c.Phases.Active.Enabled,
		EnableCertspotter:  *c.Tools.Certspotter.Enabled,
		EnableSubfinder:    *c.Tools.Subfinder.Enabled,
		EnableDnsInfo:      *c.Tools.DnsInfo.Enabled,
		EnableZoneTransfer: *c.Tools.DnsInfo.ZoneTransfer,
		EnableAsnInfo:      *c.Tools.Asn.Enabled,
		EnableWhois:        *c.Tools.Whois.Enabled,
		EnableMailSec:      *c.Tools.MailSec.Enabled,
		EnableBreach:       *c.Tools.Breach.Enabled,
		EnableVirusTotal:   *c.Tools.VirusTotal.Enabled,
		EnableWebSearch:    *c.Tools.WebSearch.Enabled,
		EnableShodan:       *c.Tools.Shodan.Enabled,
		EnableNetlas:       *c.Tools.Netlas.Enabled,
		EnablePortScan:     *c.Tools.PortScan.Enabled,
		EnablePortScanUDP:  c.UDPEnabled(),
		EnableHttpProbe:    *c.Tools.HttpProbe.Enabled,
		EnableHttps:        *c.Tools.Https.Enabled,
		EnableSmtp:         *c.Tools.Smtp.Enabled,
		EnableWebInfo:      *c.Tools.WebInfo.Enabled,
		EnableWappalyzer:   *c.Tools.Wappalyzer.Enabled,
		EnableGoScans:      c.GoScansEnabled(),
		Crtsh: crtsh.Config{
			// The validated mode string is the tool's own vocabulary: config checked
			// it against the same set crtsh.Modes defines, so the conversion is a
			// rename, not a policy decision.
			Mode:                 crtsh.Mode(c.Tools.Crtsh.Mode),
			BaseURL:              c.Tools.Crtsh.BaseURL,
			Timeout:              c.Tools.Crtsh.Timeout.Std(),
			MaxRetries:           *c.Tools.Crtsh.MaxRetries,
			BackoffMin:           c.Tools.Crtsh.BackoffMin.Std(),
			BackoffMax:           c.Tools.Crtsh.BackoffMax.Std(),
			DegradedRecheckDelay: c.Tools.Crtsh.DegradedRecheckDelay.Std(),
			MaxQueryTime:         c.Tools.Crtsh.MaxQueryTime.Std(),
			MaxBodyBytes:         *c.Tools.Crtsh.MaxBodyBytes,
		},
		Certspotter: certspotter.Config{
			APIKey:       keys.Certspotter,
			BaseURL:      c.Tools.Certspotter.BaseURL,
			Timeout:      c.Tools.Certspotter.Timeout.Std(),
			MaxPages:     *c.Tools.Certspotter.MaxPages,
			MaxBodyBytes: *c.Tools.Certspotter.MaxBodyBytes,
		},
		CertspotterCrossCheckMinRatio: *c.Tools.Certspotter.CrossCheckMinRatio,
		Subfinder: subfinder.Config{
			Threads:            *c.Tools.Subfinder.Threads,
			Timeout:            c.Tools.Subfinder.Timeout.Std(),
			MaxEnumerationTime: c.Tools.Subfinder.MaxEnumerationTime.Std(),
			All:                *c.Tools.Subfinder.All,
			ProviderKeys:       subfinderKeys,
			Providers:          subfinderProviders,
		},
		DnsInfo: dnsinfo.Config{
			Resolver: c.Tools.DnsInfo.Resolver,
			Timeout:  c.Tools.DnsInfo.Timeout.Std(),
		},
		AsnInfo: asn.Config{
			Resolver:   c.Tools.Asn.Resolver,
			Timeout:    c.Tools.Asn.Timeout.Std(),
			MaxRetries: *c.Tools.Asn.MaxRetries,
			BackoffMin: c.Tools.Asn.BackoffMin.Std(),
			BackoffMax: c.Tools.Asn.BackoffMax.Std(),
		},
		Whois: whois.Config{
			Timeout: c.Tools.Whois.Timeout.Std(),
		},
		MailSec: mailsec.Config{
			Resolver:   c.Tools.MailSec.Resolver,
			Timeout:    c.Tools.MailSec.Timeout.Std(),
			MaxRetries: *c.Tools.MailSec.MaxRetries,
			BackoffMin: c.Tools.MailSec.BackoffMin.Std(),
			BackoffMax: c.Tools.MailSec.BackoffMax.Std(),
		},
		Breach: breach.Config{
			APIKey:  keys.Breach,
			BaseURL: c.Tools.Breach.BaseURL,
			Timeout: c.Tools.Breach.Timeout.Std(),
		},
		Censys: censys.Config{
			Mode:     censys.Mode(c.Tools.Censys.Mode),
			APIKey:   keys.Censys,
			OrgID:    keys.CensysOrgID,
			MaxHosts: *c.Tools.Censys.MaxHosts,
		},
		Virustotal: virustotal.Config{
			APIKey:            keys.VirusTotal,
			EnableSubdomains:  *c.Tools.VirusTotal.EnableSubdomains,
			MaxSubdomains:     *c.Tools.VirusTotal.MaxSubdomains,
			IteratorBatchSize: *c.Tools.VirusTotal.IteratorBatchSize,
		},
		WebSearch: websearch.Config{
			APIKey:             keys.WebSearch,
			MaxResultsPerQuery: *c.Tools.WebSearch.MaxResultsPerQuery,
		},
		Shodan: shodan.Config{
			APIKey:   keys.Shodan,
			MaxHosts: *c.Tools.Shodan.MaxHosts,
			Timeout:  c.Tools.Shodan.Timeout.Std(),
		},
		Netlas: netlas.Config{
			APIKey:   keys.Netlas,
			MaxHosts: *c.Tools.Netlas.MaxHosts,
			MaxPages: *c.Tools.Netlas.MaxPages,
			Timeout:  c.Tools.Netlas.Timeout.Std(),
		},
		ActivePorts:    c.Tools.PortScan.Ports,
		ActiveUDPPorts: c.Tools.PortScan.UDP.Ports,
		PortScan: portscan.Config{
			Timeout:       c.Tools.PortScan.Timeout.Std(),
			RatePerSecond: *c.Tools.PortScan.RatePerSecond,
			NmapCommand:   c.Tools.PortScan.NmapCommand,
			// The executable and the privilege flag are deliberately absent here:
			// they are not in the file. Startup resolution supplies them through
			// Config.SetPortScanUDPRuntime, so the nmap that was proved capable is
			// the nmap that runs.
			UDP: udpConfigFor(c.Tools.PortScan.UDP, c.UDPEnabled()),
		},
		PortScanHostConcurrency: *c.Tools.PortScan.HostConcurrency,
		HttpProbe: httpprobe.Config{
			Timeout:      c.Tools.HttpProbe.Timeout.Std(),
			MaxBodyBytes: *c.Tools.HttpProbe.MaxBodyBytes,
			UserAgent:    c.Tools.HttpProbe.UserAgent,
		},
		Https: https.Config{
			Timeout: c.Tools.Https.Timeout.Std(),
			// Resolve through the same DNS server the passive phase uses, so the
			// active probe never fails to look up a name the passive phase resolved.
			ResolverAddr: c.Tools.DnsInfo.Resolver,
		},
		Smtp: smtp.Config{
			Timeout:      c.Tools.Smtp.Timeout.Std(),
			ResolverAddr: c.Tools.DnsInfo.Resolver,
		},
		WebInfo: webinfo.Config{
			Timeout:      c.Tools.WebInfo.Timeout.Std(),
			MaxRedirects: *c.Tools.WebInfo.MaxRedirects,
			MaxBodyBytes: *c.Tools.WebInfo.MaxBodyBytes,
			ResolverAddr: c.Tools.DnsInfo.Resolver,
		},
		// Wappalyzer resolves through the same DNS server as the passive phase and
		// the other active probes, so it never fails to look up a name discovery
		// already resolved.
		Wappalyzer: wappalyzer.Config{
			Timeout:      c.Tools.Wappalyzer.Timeout.Std(),
			MaxRedirects: *c.Tools.Wappalyzer.MaxRedirects,
			MaxBodyBytes: *c.Tools.Wappalyzer.MaxBodyBytes,
			UserAgent:    c.Tools.Wappalyzer.UserAgent,
			ResolverAddr: c.Tools.DnsInfo.Resolver,
		},
		GoScans:                      goScansFromConfig(&c.Tools.GoScans),
		GoScansMaxTargets:            goScansMaxTargets(&c.Tools.GoScans),
		GoScansTimeout:               c.Tools.GoScans.Timeout.Std(),
		GoScansDiscoveryFromPortScan: c.Tools.GoScans.DiscoveryFromPortScan != nil && *c.Tools.GoScans.DiscoveryFromPortScan,
		GoScansIgnoreHTTPScope:       deref(eng.Authorization.GoScans.AllowOutOfScopeHTTPRequests),
		MaxConcurrency:               *c.Discovery.MaxConcurrency,
		MaxDepth:                     *c.Discovery.MaxDepth,
		RestrictToRoot:               deref(eng.Scope.Domains.RestrictDiscoveryToRoots),
		Root:                         eng.Root(),
		ScopeInclude:                 eng.Scope.Domains.Include,
		ScopeExclude:                 eng.ExcludedDomains(),
		ScopeExcludeIPs:              eng.ExcludedIPPrefixes(),
		ScopeDepthCap:                *eng.Scope.DepthCap,
		ProviderHostProbePolicy:      ProviderHostProbePolicy(eng.Scope.ProbeProviderHosts),
		MaxPaidLookupsPerTool:        *eng.Limits.MaxPaidLookupsPerTool,
		MaxActiveHosts:               *eng.Limits.MaxActiveHosts,
	}
}

// deref reports whether an optional boolean is present and true. FromConfig runs
// only after both files validated, so a required bool is non-nil on the paths that
// read it; the guard keeps an omitted optional mapping cleanly to false.
func deref(p *bool) bool { return p != nil && *p }

// goScansMaxTargets reads the isolated batch cap off the block, or 0 (unlimited)
// when the tool is disabled and the value was never required to be present.
func goScansMaxTargets(g *config.GoScansTool) int {
	if g.Enabled == nil || !*g.Enabled || g.MaxTargets == nil {
		return 0
	}
	return *g.MaxTargets
}

// goScansFromConfig maps the goscans block to the actor's run snapshot. A disabled
// block maps to the zero Config and is never handed to the actor, so the pointer
// dereferences below run only on the enabled path Config.Validate has already
// checked. Per-module values are read only when their module is on, because that is
// exactly when validation required them; a disabled module's timeout is not a value
// this function may invent.
//
// The event-payload limits start from the tool's own defaults and are overridden
// only where the configuration exposes a knob: the caps that change what the scanner
// sends, or how large a report becomes, are the operator's, and the rest (cipher,
// certificate, algorithm-list, script-output, and upstream-log bounds) belong to the
// tool.
func goScansFromConfig(g *config.GoScansTool) goscans.Config {
	if g.Enabled == nil || !*g.Enabled {
		return goscans.Config{}
	}
	on := func(p *bool) bool { return p != nil && *p }

	limits := goscans.DefaultLimits()
	limits.MaxServicesPerHost = *g.Limits.MaxServicesPerHost
	limits.MaxVhosts = *g.Limits.MaxVhosts
	limits.MaxExcerptBytes = *g.Limits.MaxExcerptBytes
	if on(g.WebCrawler.Enabled) {
		limits.MaxCrawlPages = *g.WebCrawler.MaxPages
	}
	if on(g.WebEnum.Enabled) {
		limits.MaxEnumItems = *g.WebEnum.MaxItems
	}

	cfg := goscans.Config{
		NmapPath:                   g.Nmap.Path,
		NmapArgs:                   slices.Clone(g.Nmap.Args),
		PythonPath:                 g.Sslyze.PythonPath,
		SslyzeAdditionalTruststore: g.Sslyze.AdditionalTruststore,
		Modules: goscans.Modules{
			Banner:   on(g.Banner.Enabled),
			TLS:      on(g.Ssl.Enabled),
			SSH:      on(g.Ssh.Enabled),
			WebCrawl: on(g.WebCrawler.Enabled),
			WebEnum:  on(g.WebEnum.Enabled),
		},
		TLSPorts:              slices.Clone(g.Ports.Tls),
		SSHPorts:              slices.Clone(g.Ports.Ssh),
		HTTPPorts:             slices.Clone(g.Ports.Http),
		HTTPSPorts:            slices.Clone(g.Ports.Https),
		DiscoveryTimeout:      g.Nmap.Timeout.Std(),
		DiscoveryDialTimeout:  g.Nmap.DialTimeout.Std(),
		MaxConcurrency:        *g.MaxParallelServices,
		MaxConcurrencyPerHost: *g.MaxParallelServicesPerHost,
		MaxParallelTargets:    *g.MaxParallelTargets,
		UserAgent:             g.UserAgent,
		Limits:                limits,
	}
	// banner.dial_timeout is the TCP connect bound for the banner module and for the
	// ssh module, which has no separate knob: both make one plain connection to one
	// discovered service.
	if on(g.Banner.Enabled) || on(g.Ssh.Enabled) {
		cfg.BannerDialTimeout = g.Banner.DialTimeout.Std()
	}
	if on(g.Banner.Enabled) {
		cfg.BannerReceiveTimeout = g.Banner.ReceiveTimeout.Std()
	}
	if on(g.Ssl.Enabled) {
		cfg.TLSTimeout = g.Ssl.Timeout.Std()
	}
	if on(g.Ssh.Enabled) {
		cfg.SSHTimeout = g.Ssh.Timeout.Std()
	}
	if on(g.WebCrawler.Enabled) {
		cfg.CrawlTimeout = g.WebCrawler.Timeout.Std()
		cfg.CrawlRequestTimeout = g.WebCrawler.RequestTimeout.Std()
		cfg.CrawlDepth = *g.WebCrawler.Depth
		cfg.CrawlThreads = *g.WebCrawler.MaxThreads
	}
	if on(g.WebEnum.Enabled) {
		cfg.EnumTimeout = g.WebEnum.Timeout.Std()
		cfg.EnumRequestTimeout = g.WebEnum.RequestTimeout.Std()
		cfg.ProbeRobots = on(g.WebEnum.ProbeRobots)
	}
	return cfg
}

// subfinderProviderPolicy maps Vanguard's API keys onto subfinder's own source
// names so subfinder is driven entirely from Vanguard config rather than ambient
// host state (see the subfinder package). Orchestration is the policy authority
// here: it returns both the keys subfinder receives and the disposition of every
// keyed source it decided about, so the tool can tell a deliberate decision from a
// genuinely absent credential instead of guessing from an empty key map.
//
// VirusTotal is the free-tier source that materially improves passive subdomain
// coverage and is the one whose absence silently gutted discovery on a fresh
// server. Its disposition follows the policy:
//
//	key present, Vanguard VT subdomains enabled  -> handled elsewhere, key withheld
//	key present, Vanguard VT subdomains disabled -> configured, key passed
//	key absent, all sources requested            -> missing, operator must act
//	key absent, all sources not requested        -> disabled, silent by policy
//
// Withholding keeps one VT subdomain path instead of two, so the quota is spent
// once by the dedicated tool. The paid host-intel sources (shodan/censys/netlas)
// are deliberately left to Vanguard's own budget-controlled tools rather than
// spent inside subfinder, and are not declared here because the subfinder client
// does not diagnose them.
func subfinderProviderPolicy(keys *config.APIKeys, allSources, vanguardVirusTotalSubdomains bool) (map[string][]string, []subfinder.ProviderStatus) {
	m := map[string][]string{}
	status := subfinder.ProviderStatus{Provider: "virustotal"}
	switch {
	case keys != nil && keys.VirusTotal != "" && vanguardVirusTotalSubdomains:
		status.Disposition = subfinder.DispositionHandledElsewhere
		status.Owner = "virustotal"
	case keys != nil && keys.VirusTotal != "":
		m["virustotal"] = []string{keys.VirusTotal}
		status.Disposition = subfinder.DispositionConfigured
	case allSources:
		status.Disposition = subfinder.DispositionMissing
	default:
		status.Disposition = subfinder.DispositionDisabled
	}
	return m, []subfinder.ProviderStatus{status}
}

// udpConfigFor maps the profile block onto the port scanner UDP settings. A
// disabled pass maps to the zero value, so nothing about the client changes for a
// profile that did not ask for UDP.
//
// Enabled is not the block flag alone: it also requires the port scanner itself,
// because the UDP pass is that tool extension rather than a tool of its own. The
// executable path and the privilege flag are absent by design and arrive later
// from startup resolution.
func udpConfigFor(u config.PortScanUDP, enabled bool) portscan.UDPConfig {
	if !enabled {
		return portscan.UDPConfig{}
	}
	derefInt := func(p *int) int {
		if p == nil {
			return 0
		}
		return *p
	}
	return portscan.UDPConfig{
		Enabled:          true,
		ProbeTimeout:     u.Timeout.Std(),
		RatePerSecond:    derefInt(u.RatePerSecond),
		Retries:          derefInt(u.Retries),
		ServiceDetection: deref(u.Nmap.ServiceDetection),
		VersionIntensity: derefInt(u.Nmap.VersionIntensity),
		TimingTemplate:   derefInt(u.Nmap.TimingTemplate),
		HostTimeout:      u.Nmap.HostTimeout.Std(),
		// The tool-side cap is the profile ceiling, so a programmatic caller cannot
		// widen a reviewed discovery pass into a sweep by handing it a longer list
		// than the profile could have expressed.
		MaxPorts: config.UDPMaxPorts,
	}
}
