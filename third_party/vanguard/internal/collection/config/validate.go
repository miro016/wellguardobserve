package config

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// Validate enforces that every required value is present and sane. It reports
// all problems at once so the operator can fix the file in one pass.
func (c *ScanProfile) Validate() error {
	var problems []string
	req := func(cond bool, msg string) {
		if !cond {
			problems = append(problems, msg)
		}
	}

	req(c.Phases.Passive.Enabled != nil, "phases.passive.enabled is required")
	req(c.Phases.Active.Enabled != nil, "phases.active.enabled is required")
	// Active reconnaissance probes what the passive phase discovered, so a profile
	// that enables it without passive asks for work that has no targets. The check
	// runs here, on the document, so it fails before a destination is claimed.
	req(!c.PhaseSet().Active || c.PhaseSet().Passive, "phases.active requires phases.passive; enable phases.passive")

	req(c.Discovery.MaxDepth != nil, "discovery.max_depth is required")
	req(c.Discovery.MaxDepth == nil || *c.Discovery.MaxDepth >= 0, "discovery.max_depth must be >= 0")
	req(c.Discovery.MaxConcurrency != nil, "discovery.max_concurrency is required")
	req(c.Discovery.MaxConcurrency == nil || *c.Discovery.MaxConcurrency > 0, "discovery.max_concurrency must be > 0")

	c.validateCrtsh(req)
	c.validateCertspotter(req)
	c.validateGoScans(req)

	// subfinder
	req(c.Tools.Subfinder.Enabled != nil, "tools.subfinder.enabled is required")
	req(c.Tools.Subfinder.Threads != nil, "tools.subfinder.threads is required")
	req(c.Tools.Subfinder.Threads == nil || *c.Tools.Subfinder.Threads > 0, "tools.subfinder.threads must be > 0")
	req(c.Tools.Subfinder.Timeout > 0, "tools.subfinder.timeout is required (e.g. \"30s\")")
	req(c.Tools.Subfinder.MaxEnumerationTime > 0, "tools.subfinder.max_enumeration_time is required (e.g. \"2m\")")
	req(c.Tools.Subfinder.All != nil, "tools.subfinder.all is required")

	// dnsinfo
	req(c.Tools.DnsInfo.Enabled != nil, "tools.dnsinfo.enabled is required")
	req(c.Tools.DnsInfo.ZoneTransfer != nil, "tools.dnsinfo.zone_transfer is required")
	req(c.Tools.DnsInfo.Resolver != "", "tools.dnsinfo.resolver is required (e.g. \"8.8.8.8:53\")")
	req(c.Tools.DnsInfo.Timeout > 0, "tools.dnsinfo.timeout is required (e.g. \"5s\")")

	// asn
	req(c.Tools.Asn.Enabled != nil, "tools.asn.enabled is required")
	req(c.Tools.Asn.Resolver != "", "tools.asn.resolver is required (e.g. \"8.8.8.8:53\")")
	req(c.Tools.Asn.Timeout > 0, "tools.asn.timeout is required (e.g. \"5s\")")
	req(c.Tools.Asn.MaxRetries != nil, "tools.asn.max_retries is required")
	reqLimit(req, "tools.asn.max_retries", c.Tools.Asn.MaxRetries)
	req(c.Tools.Asn.BackoffMin > 0, "tools.asn.backoff_min is required (e.g. \"200ms\")")
	req(c.Tools.Asn.BackoffMax > 0, "tools.asn.backoff_max is required (e.g. \"2s\")")

	// whois
	req(c.Tools.Whois.Enabled != nil, "tools.whois.enabled is required")
	req(c.Tools.Whois.Timeout > 0, "tools.whois.timeout is required (e.g. \"15s\")")

	// mailsec
	req(c.Tools.MailSec.Enabled != nil, "tools.mailsec.enabled is required")
	req(c.Tools.MailSec.Resolver != "", "tools.mailsec.resolver is required (e.g. \"8.8.8.8:53\")")
	req(c.Tools.MailSec.Timeout > 0, "tools.mailsec.timeout is required (e.g. \"5s\")")
	req(c.Tools.MailSec.MaxRetries != nil, "tools.mailsec.max_retries is required")
	reqLimit(req, "tools.mailsec.max_retries", c.Tools.MailSec.MaxRetries)
	req(c.Tools.MailSec.BackoffMin > 0, "tools.mailsec.backoff_min is required (e.g. \"200ms\")")
	req(c.Tools.MailSec.BackoffMax > 0, "tools.mailsec.backoff_max is required (e.g. \"2s\")")

	// breach
	req(c.Tools.Breach.Enabled != nil, "tools.breach.enabled is required")
	req(c.Tools.Breach.BaseURL != "", "tools.breach.base_url is required (e.g. \"https://haveibeenpwned.com\")")
	req(c.Tools.Breach.Timeout > 0, "tools.breach.timeout is required (e.g. \"15s\")")

	// censys
	reqMode(req, "tools.censys.mode", c.Tools.Censys.Mode, censysModes)
	req(c.Tools.Censys.MaxHosts != nil, "tools.censys.max_hosts is required")
	req(c.Tools.Censys.MaxHosts == nil || *c.Tools.Censys.MaxHosts > 0, "tools.censys.max_hosts must be > 0")

	// virustotal
	req(c.Tools.VirusTotal.Enabled != nil, "tools.virustotal.enabled is required")
	req(c.Tools.VirusTotal.EnableSubdomains != nil, "tools.virustotal.enable_subdomains is required")
	req(c.Tools.VirusTotal.MaxSubdomains != nil, "tools.virustotal.max_subdomains is required")
	req(c.Tools.VirusTotal.MaxSubdomains == nil || *c.Tools.VirusTotal.MaxSubdomains > 0, "tools.virustotal.max_subdomains must be > 0")
	req(c.Tools.VirusTotal.IteratorBatchSize != nil, "tools.virustotal.iterator_batch_size is required")
	req(c.Tools.VirusTotal.IteratorBatchSize == nil || *c.Tools.VirusTotal.IteratorBatchSize > 0, "tools.virustotal.iterator_batch_size must be > 0")

	// websearch
	req(c.Tools.WebSearch.Enabled != nil, "tools.websearch.enabled is required")
	req(c.Tools.WebSearch.MaxResultsPerQuery != nil, "tools.websearch.max_results_per_query is required")
	req(c.Tools.WebSearch.MaxResultsPerQuery == nil || *c.Tools.WebSearch.MaxResultsPerQuery > 0, "tools.websearch.max_results_per_query must be > 0")

	// shodan
	req(c.Tools.Shodan.Enabled != nil, "tools.shodan.enabled is required")
	req(c.Tools.Shodan.MaxHosts != nil, "tools.shodan.max_hosts is required")
	req(c.Tools.Shodan.MaxHosts == nil || *c.Tools.Shodan.MaxHosts > 0, "tools.shodan.max_hosts must be > 0")
	req(c.Tools.Shodan.Timeout > 0, "tools.shodan.timeout is required (e.g. \"30s\")")

	// netlas
	req(c.Tools.Netlas.Enabled != nil, "tools.netlas.enabled is required")
	req(c.Tools.Netlas.MaxHosts != nil, "tools.netlas.max_hosts is required")
	req(c.Tools.Netlas.MaxHosts == nil || *c.Tools.Netlas.MaxHosts > 0, "tools.netlas.max_hosts must be > 0")
	req(c.Tools.Netlas.MaxPages != nil, "tools.netlas.max_pages is required")
	req(c.Tools.Netlas.MaxPages == nil || *c.Tools.Netlas.MaxPages > 0, "tools.netlas.max_pages must be > 0")
	req(c.Tools.Netlas.Timeout > 0, "tools.netlas.timeout is required (e.g. \"30s\")")

	c.validateActiveTools(req)

	if len(problems) > 0 {
		return fmt.Errorf("  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// validateActiveTools checks the active-phase probe blocks. It is split out of
// Validate to keep that function readable as the tool set grows; the rules are the
// same fail-fast, report-everything rules.
func (c *ScanProfile) validateActiveTools(req func(bool, string)) {
	// portscan
	req(c.Tools.PortScan.Enabled != nil, "tools.portscan.enabled is required")
	req(c.Tools.PortScan.Timeout > 0, "tools.portscan.timeout is required (e.g. \"2s\")")
	req(c.Tools.PortScan.RatePerSecond != nil, "tools.portscan.rate_per_second is required (replaces tools.portscan.concurrency)")
	req(c.Tools.PortScan.RatePerSecond == nil || *c.Tools.PortScan.RatePerSecond > 0, "tools.portscan.rate_per_second must be > 0")
	req(c.Tools.PortScan.HostConcurrency != nil, "tools.portscan.host_concurrency is required")
	req(c.Tools.PortScan.HostConcurrency == nil || *c.Tools.PortScan.HostConcurrency > 0, "tools.portscan.host_concurrency must be > 0")
	req(c.Tools.PortScan.HostConcurrency == nil || c.Discovery.MaxConcurrency == nil || *c.Tools.PortScan.HostConcurrency < *c.Discovery.MaxConcurrency,
		"tools.portscan.host_concurrency must be less than discovery.max_concurrency so port scans cannot consume every discovery slot")
	req(len(c.Tools.PortScan.Ports) > 0, "tools.portscan.ports must list at least one port")
	req(c.Tools.PortScan.NmapCommand != "", "tools.portscan.nmap_command is required (e.g. \"nmap -sV -Pn -T4\")")
	c.validatePortScanUDP(req)

	// httpprobe
	req(c.Tools.HttpProbe.Enabled != nil, "tools.httpprobe.enabled is required")
	req(c.Tools.HttpProbe.Timeout > 0, "tools.httpprobe.timeout is required (e.g. \"5s\")")
	req(c.Tools.HttpProbe.MaxBodyBytes != nil, "tools.httpprobe.max_body_bytes is required")
	req(c.Tools.HttpProbe.MaxBodyBytes == nil || *c.Tools.HttpProbe.MaxBodyBytes > 0, "tools.httpprobe.max_body_bytes must be > 0")
	req(c.Tools.HttpProbe.UserAgent != "", "tools.httpprobe.user_agent is required")

	// https
	req(c.Tools.Https.Enabled != nil, "tools.https.enabled is required")
	req(c.Tools.Https.Timeout > 0, "tools.https.timeout is required (e.g. \"10s\")")

	// smtp
	req(c.Tools.Smtp.Enabled != nil, "tools.smtp.enabled is required")
	req(c.Tools.Smtp.Timeout > 0, "tools.smtp.timeout is required (e.g. \"10s\")")

	// webinfo
	req(c.Tools.WebInfo.Enabled != nil, "tools.webinfo.enabled is required")
	req(c.Tools.WebInfo.Timeout > 0, "tools.webinfo.timeout is required (e.g. \"10s\")")
	req(c.Tools.WebInfo.MaxRedirects != nil, "tools.webinfo.max_redirects is required")
	req(c.Tools.WebInfo.MaxRedirects == nil || *c.Tools.WebInfo.MaxRedirects > 0, "tools.webinfo.max_redirects must be > 0")
	req(c.Tools.WebInfo.MaxBodyBytes != nil, "tools.webinfo.max_body_bytes is required")
	req(c.Tools.WebInfo.MaxBodyBytes == nil || *c.Tools.WebInfo.MaxBodyBytes > 0, "tools.webinfo.max_body_bytes must be > 0")

	// wappalyzer. Deliberately no cross-tool rule: the tool owns its request and its
	// fingerprint engine, so it is valid enabled alone and valid alongside every other
	// HTTP tool. The active phase is its only other gate.
	req(c.Tools.Wappalyzer.Enabled != nil, "tools.wappalyzer.enabled is required")
	req(c.Tools.Wappalyzer.Timeout > 0, "tools.wappalyzer.timeout is required (e.g. \"10s\")")
	req(c.Tools.Wappalyzer.MaxRedirects != nil, "tools.wappalyzer.max_redirects is required")
	req(c.Tools.Wappalyzer.MaxRedirects == nil || *c.Tools.Wappalyzer.MaxRedirects > 0, "tools.wappalyzer.max_redirects must be > 0")
	req(c.Tools.Wappalyzer.MaxBodyBytes != nil, "tools.wappalyzer.max_body_bytes is required")
	req(c.Tools.Wappalyzer.MaxBodyBytes == nil || *c.Tools.Wappalyzer.MaxBodyBytes > 0, "tools.wappalyzer.max_body_bytes must be > 0")
	req(c.Tools.Wappalyzer.UserAgent != "", "tools.wappalyzer.user_agent is required")
}

// ValidateAPIKeys checks that every paid service selected in the config file has a
// corresponding API key. It must be called only after Validate has succeeded.
// Censys requires a key only in service mode; its cache-only mode cannot make a paid
// call. A paid service selected with no key is a misconfiguration, not a silent
// downgrade: the caller should fail to start and show this error rather than run
// with the tool quietly skipped.
func (c *ScanProfile) ValidateAPIKeys(keys *APIKeys) error {
	var problems []string
	req := func(enabled *bool, key, tool, env string) {
		if *enabled && key == "" {
			problems = append(problems, fmt.Sprintf("tools.%s.enabled is true but %s is not set", tool, env))
		}
	}

	req(c.Tools.Breach.Enabled, keys.Breach, "breach", "HIBP_API_KEY")
	// Censys is mode-driven: only the service mode needs a key. embedded_cache_only
	// answers from compiled-in data, so it is valid with no Censys credentials at
	// all - and a key that happens to be set never turns it back into API access.
	if c.Tools.Censys.Mode == modeEnabled && keys.Censys == "" {
		problems = append(problems, fmt.Sprintf("tools.censys.mode is %q but CENSYS_API_KEY is not set", modeEnabled))
	}
	req(c.Tools.VirusTotal.Enabled, keys.VirusTotal, "virustotal", "VIRUSTOTAL_API_KEY")
	req(c.Tools.WebSearch.Enabled, keys.WebSearch, "websearch", "SERPAPI_API_KEY")
	req(c.Tools.Shodan.Enabled, keys.Shodan, "shodan", "SHODAN_API_KEY")
	req(c.Tools.Netlas.Enabled, keys.Netlas, "netlas", "NETLAS_API_KEY")

	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// ValidateExternalTools checks that the external binaries the enabled tools
// depend on are installed. The naabu port scanner fingerprints services with
// nmap, so an enabled portscan with no nmap on PATH is a misconfiguration:
// the caller should fail to start and show this error rather than run
// the scan and crash mid-flight. It must be called only after Validate succeeds.
func (c *ScanProfile) ValidateExternalTools() error {
	var problems []string
	if c.Tools.PortScan.Enabled != nil && *c.Tools.PortScan.Enabled {
		if _, err := exec.LookPath("nmap"); err != nil {
			problems = append(problems, "tools.portscan.enabled is true but nmap was not found on PATH (install nmap or disable tools.portscan)")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// validateCrtsh checks the crtsh tool block. It is split out of Validate to keep
// that function's cyclomatic complexity in check; crtsh carries the most fields
// (the never-give-up retry/budget knobs).
func (c *ScanProfile) validateCrtsh(req func(bool, string)) {
	reqMode(req, "tools.crtsh.mode", c.Tools.Crtsh.Mode, crtshModes)
	req(c.Tools.Crtsh.BaseURL != "", "tools.crtsh.base_url is required")
	req(c.Tools.Crtsh.Timeout > 0, "tools.crtsh.timeout is required (e.g. \"30s\")")
	req(c.Tools.Crtsh.MaxRetries != nil, "tools.crtsh.max_retries is required")
	reqLimit(req, "tools.crtsh.max_retries", c.Tools.Crtsh.MaxRetries)
	req(c.Tools.Crtsh.MaxRetries == nil || *c.Tools.Crtsh.MaxRetries != 0,
		"tools.crtsh.max_retries: 0 no longer means unlimited; use -1 for unlimited or a positive retry count")
	req(c.Tools.Crtsh.BackoffMin > 0, "tools.crtsh.backoff_min is required (e.g. \"1s\")")
	req(c.Tools.Crtsh.BackoffMax > 0, "tools.crtsh.backoff_max is required (e.g. \"10s\")")
	req(c.Tools.Crtsh.DegradedRecheckDelay > 0, "tools.crtsh.degraded_recheck_delay is required (e.g. \"5s\")")
	req(c.Tools.Crtsh.MaxQueryTime != nil, "tools.crtsh.max_query_time is required (use \"-1s\" for unlimited)")
	req(c.Tools.Crtsh.MaxQueryTime == nil || *c.Tools.Crtsh.MaxQueryTime == -1*Duration(time.Second) || *c.Tools.Crtsh.MaxQueryTime >= 0,
		"tools.crtsh.max_query_time must be -1s or >= 0s (-1s = unlimited, 0s = no wait)")
	req(c.Tools.Crtsh.MaxBodyBytes != nil, "tools.crtsh.max_body_bytes is required")
	req(c.Tools.Crtsh.MaxBodyBytes == nil || *c.Tools.Crtsh.MaxBodyBytes > 0, "tools.crtsh.max_body_bytes must be > 0")
}

// validateCertspotter checks the certspotter tool block. It is split out of
// Validate to keep that function's cyclomatic complexity in check.
func (c *ScanProfile) validateCertspotter(req func(bool, string)) {
	req(c.Tools.Certspotter.Enabled != nil, "tools.certspotter.enabled is required")
	req(c.Tools.Certspotter.BaseURL != "", "tools.certspotter.base_url is required (e.g. \"https://api.certspotter.com\")")
	req(c.Tools.Certspotter.Timeout > 0, "tools.certspotter.timeout is required (e.g. \"30s\")")
	req(c.Tools.Certspotter.MaxPages != nil, "tools.certspotter.max_pages is required")
	req(c.Tools.Certspotter.MaxPages == nil || *c.Tools.Certspotter.MaxPages > 0, "tools.certspotter.max_pages must be > 0")
	req(c.Tools.Certspotter.MaxBodyBytes != nil, "tools.certspotter.max_body_bytes is required")
	req(c.Tools.Certspotter.MaxBodyBytes == nil || *c.Tools.Certspotter.MaxBodyBytes > 0, "tools.certspotter.max_body_bytes must be > 0")
	req(c.Tools.Certspotter.CrossCheckMinRatio != nil, "tools.certspotter.cross_check_min_ratio is required (use 0.0 to disable the cross-check)")
	req(c.Tools.Certspotter.CrossCheckMinRatio == nil || *c.Tools.Certspotter.CrossCheckMinRatio >= 0, "tools.certspotter.cross_check_min_ratio must be >= 0")
}

// reqLimit applies the shared count-limit encoding: -1 is unlimited, 0 is none,
// and positive values are finite limits.
func reqLimit(req func(bool, string), name string, value *int) {
	req(value == nil || *value >= -1, fmt.Sprintf("%s must be >= -1 (-1 = unlimited, 0 = none)", name))
}

// The accepted tools.<tool>.mode values. The config layer stays tool-independent: it
// validates these strings and orchestration converts a validated value into the
// respective tool package's own mode type. crt.sh falls back to the service on a
// cache miss, so its cache mode is "support"; Censys never falls back, so its cache
// mode is "only".
const (
	modeDisabled             = "disabled"
	modeEnabled              = "enabled"
	modeEmbeddedCacheSupport = "embedded_cache_support"
	modeEmbeddedCacheOnly    = "embedded_cache_only"
)

var (
	crtshModes  = []string{modeDisabled, modeEnabled, modeEmbeddedCacheSupport}
	censysModes = []string{modeDisabled, modeEnabled, modeEmbeddedCacheOnly}
)

// reqMode checks one mode field: it must be present and one of the tool's allowed
// values. Both messages name the field and list the allowed values, so a stale
// profile (one still carrying the removed "enabled" boolean, which strict decoding
// rejects first) or a typo reports what to write instead.
func reqMode(req func(bool, string), field, value string, allowed []string) {
	if value == "" {
		req(false, fmt.Sprintf("%s is required (one of: %s)", field, strings.Join(allowed, ", ")))
		return
	}
	req(slices.Contains(allowed, value),
		fmt.Sprintf("%s %q is invalid (one of: %s)", field, value, strings.Join(allowed, ", ")))
}
