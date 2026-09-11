package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScanProfile is the reusable, audit-grade "how" half of a scan configuration,
// loaded from a YAML file. It owns the phases that run, the tools that are enabled,
// and every tool's tuning; the customer identity, scope, limits, and authorizations
// live in the disjoint [EngagementConfig]. The two are composed, never merged (see
// [Scan]). Every setting is mandatory: the application supplies no defaults, so the
// profile alone determines how the scan runs. Boolean and integer toggles use
// pointers so an omitted value is detected and rejected rather than silently
// defaulting.
type ScanProfile struct {
	Phases    Phases    `yaml:"phases"`
	Discovery Discovery `yaml:"discovery"`
	Tools     Tools     `yaml:"tools"`
}

// ProviderHostProbePolicy controls whether provider-only IPs may receive active
// traffic. It is explicit and closed so a misspelling cannot silently broaden scope.
// It is owned by the engagement scope (see [EngagementScope.ProbeProviderHosts]).
type ProviderHostProbePolicy string

const (
	// ProviderHostProbeNever never sends active traffic to a provider-only IP.
	ProviderHostProbeNever ProviderHostProbePolicy = "never"
	// ProviderHostProbeCorroborated requires PTR, netblock, or certificate evidence.
	ProviderHostProbeCorroborated ProviderHostProbePolicy = "corroborated"
	// ProviderHostProbeAlways trusts provider attribution without corroboration.
	ProviderHostProbeAlways ProviderHostProbePolicy = "always"
)

// Phases enables or disables whole reconnaissance phases.
type Phases struct {
	Passive Phase `yaml:"passive"`
	Active  Phase `yaml:"active"`
}

// Phase is a single phase toggle.
type Phase struct {
	Enabled *bool `yaml:"enabled"`
}

// Discovery holds crawler/discovery settings that drive the passive phase. The
// customer-boundary restriction (restrict_discovery_to_roots) is owned by the
// engagement scope, not this block.
type Discovery struct {
	MaxDepth       *int `yaml:"max_depth"`
	MaxConcurrency *int `yaml:"max_concurrency"`
}

// Tools holds the per-tool configuration blocks.
type Tools struct {
	Crtsh       CrtshTool       `yaml:"crtsh"`
	Certspotter CertspotterTool `yaml:"certspotter"`
	Subfinder   SubfinderTool   `yaml:"subfinder"`
	DnsInfo     DnsInfoTool     `yaml:"dnsinfo"`
	Asn         AsnTool         `yaml:"asn"`
	Whois       WhoisTool       `yaml:"whois"`
	MailSec     MailSecTool     `yaml:"mailsec"`
	Breach      BreachTool      `yaml:"breach"`
	Censys      CensysTool      `yaml:"censys"`
	VirusTotal  VirusTotalTool  `yaml:"virustotal"`
	WebSearch   WebSearchTool   `yaml:"websearch"`
	Shodan      ShodanTool      `yaml:"shodan"`
	Netlas      NetlasTool      `yaml:"netlas"`
	PortScan    PortScanTool    `yaml:"portscan"`
	HttpProbe   HttpProbeTool   `yaml:"httpprobe"`
	Https       HttpsTool       `yaml:"https"`
	Smtp        SmtpTool        `yaml:"smtp"`
	WebInfo     WebInfoTool     `yaml:"webinfo"`
	Wappalyzer  WappalyzerTool  `yaml:"wappalyzer"`
	GoScans     GoScansTool     `yaml:"goscans"`
}

// CrtshTool configures the crt.sh certificate-transparency client (passive).
type CrtshTool struct {
	// Mode selects where results come from: "disabled" (crt.sh does not run),
	// "enabled" (query crt.sh), or "embedded_cache_support" (answer from the
	// compiled-in fixture when it has the query, otherwise query crt.sh exactly as
	// "enabled" does). It replaces the old enabled flag: one value controls the tool,
	// so a mode and a flag can never disagree.
	Mode    string   `yaml:"mode"`
	BaseURL string   `yaml:"base_url"`
	Timeout Duration `yaml:"timeout"`
	// MaxRetries is the retry count after the first attempt; -1 means retry
	// indefinitely (never give up) and 0 means no retries. crt.sh is the sole certificate source, so the
	// default favours completeness - see crtsh.ScanProfile.MaxRetries.
	MaxRetries *int     `yaml:"max_retries"`
	BackoffMin Duration `yaml:"backoff_min"`
	BackoffMax Duration `yaml:"backoff_max"`
	// DegradedRecheckDelay is the cooldown before re-querying a suspicious empty
	// result: a 200 with zero certificates that arrived only after crt.sh emitted
	// retryable backend failures during the same search. crt.sh signals "no
	// certificates" the same way it can return a short/empty body while degraded, so
	// such an empty is re-queried once after this delay before being accepted; a
	// still-empty re-query is flagged as a data-quality issue rather than recorded as
	// a trustworthy zero. Required and positive - see crtsh.ScanProfile.DegradedRecheckDelay.
	DegradedRecheckDelay Duration `yaml:"degraded_recheck_delay"`
	// MaxQueryTime caps the total wall-clock time per search; "-1s" means unlimited
	// and "0s" means no wait. A pointer makes omission a hard error.
	MaxQueryTime *Duration `yaml:"max_query_time"`
	MaxBodyBytes *int64    `yaml:"max_body_bytes"`
}

// CertspotterTool configures the certspotter second Certificate Transparency
// source (passive). It corroborates the crt.sh crawler's coverage: certspotter
// reads the same CT logs, so a materially smaller crt.sh subdomain set signals a
// truncated crt.sh response. The optional API token is not a config field: the app
// injects it from the CERTSPOTTER_API_KEY environment variable for higher rate
// limits, and the tool runs unauthenticated (more tightly rate limited) without it.
type CertspotterTool struct {
	Enabled *bool    `yaml:"enabled"`
	BaseURL string   `yaml:"base_url"`
	Timeout Duration `yaml:"timeout"`
	// MaxPages caps how many result pages certspotter pagination fetches.
	MaxPages     *int   `yaml:"max_pages"`
	MaxBodyBytes *int64 `yaml:"max_body_bytes"`
	// CrossCheckMinRatio is the minimum acceptable ratio of crt.sh's discovered
	// subdomain count to certspotter's before a coverage warning is raised: a
	// warning fires when crtsh_count < ratio * certspotter_count. Use 0.0 to disable
	// the cross-check (collect certspotter's names but never warn). Conservative
	// values (well below 1.0) avoid false positives from benign CT-log lag.
	CrossCheckMinRatio *float64 `yaml:"cross_check_min_ratio"`
}

// SubfinderTool configures passive subdomain enumeration via subfinder, which
// aggregates many third-party passive DNS sources (passive).
type SubfinderTool struct {
	Enabled            *bool    `yaml:"enabled"`
	Threads            *int     `yaml:"threads"`
	Timeout            Duration `yaml:"timeout"`
	MaxEnumerationTime Duration `yaml:"max_enumeration_time"`
	All                *bool    `yaml:"all"`
}

// DnsInfoTool configures passive DNS resolution and the optional active zone-transfer check.
type DnsInfoTool struct {
	Enabled      *bool    `yaml:"enabled"`
	ZoneTransfer *bool    `yaml:"zone_transfer"`
	Resolver     string   `yaml:"resolver"`
	Timeout      Duration `yaml:"timeout"`
}

// AsnTool configures the ASN lookup client (passive).
type AsnTool struct {
	Enabled  *bool    `yaml:"enabled"`
	Resolver string   `yaml:"resolver"`
	Timeout  Duration `yaml:"timeout"`
	// MaxRetries is the number of extra attempts after the first for a transient
	// TXT-query failure (UDP timeout, SERVFAIL); 0 disables retrying. A definitive
	// negative (NXDOMAIN, empty answer) is never retried. Completeness-first: ASN
	// data lost to a transient flake is a coverage hole, so a small retry is the
	// default - see asn.ScanProfile.MaxRetries.
	MaxRetries *int     `yaml:"max_retries"`
	BackoffMin Duration `yaml:"backoff_min"`
	BackoffMax Duration `yaml:"backoff_max"`
}

// WhoisTool configures the WHOIS/RDAP registration lookup client (passive).
type WhoisTool struct {
	Enabled *bool    `yaml:"enabled"`
	Timeout Duration `yaml:"timeout"`
}

// MailSecTool configures the email-security probe (SPF/DMARC/DKIM/BIMI, passive).
type MailSecTool struct {
	Enabled  *bool    `yaml:"enabled"`
	Resolver string   `yaml:"resolver"`
	Timeout  Duration `yaml:"timeout"`
	// MaxRetries is the number of extra attempts after the first for a transient
	// DNS-query failure (UDP timeout, SERVFAIL); 0 disables retrying. A definitive
	// negative (NXDOMAIN) is never retried. A transient timeout on the MX query
	// otherwise reports MX 0 for a live mail domain - see mailsec.ScanProfile.MaxRetries.
	MaxRetries *int     `yaml:"max_retries"`
	BackoffMin Duration `yaml:"backoff_min"`
	BackoffMax Duration `yaml:"backoff_max"`
}

// BreachTool configures the HaveIBeenPwned breach-data lookup (passive). The
// HIBP API key is not a config field: the app injects it from the HIBP_API_KEY
// environment variable so the secret stays out of the audit configuration.
type BreachTool struct {
	Enabled *bool    `yaml:"enabled"`
	BaseURL string   `yaml:"base_url"`
	Timeout Duration `yaml:"timeout"`
}

// CensysTool configures the Censys GlobalData host search (passive). The Censys
// Personal Access Token is not a config field: the app injects it from the
// CENSYS_API_KEY environment variable so the secret stays out of the audit
// configuration. The Censys organization ID is likewise injected from
// CENSYS_ORG_ID rather than read here; it is optional but without it requests
// run against the free wallet and paid query types 403 (see censys.ScanProfile.OrgID).
type CensysTool struct {
	// Mode selects where results come from: "disabled" (Censys does not run),
	// "enabled" (query the Censys API, which requires CENSYS_API_KEY and spends paid
	// budget), or "embedded_cache_only" (answer from the compiled-in fixture and
	// never reach Censys - no key required, no paid request, and a lookup miss stays
	// a miss). It replaces the old enabled flag: one value controls the tool, so a
	// mode and a flag can never disagree.
	Mode     string `yaml:"mode"`
	MaxHosts *int   `yaml:"max_hosts"`
}

// VirusTotalTool configures the VirusTotal domain-intelligence lookup (passive).
// The API key is not a config field: the app injects it from the
// VIRUSTOTAL_API_KEY environment variable so the secret stays out of the audit
// configuration.
type VirusTotalTool struct {
	Enabled           *bool `yaml:"enabled"`
	EnableSubdomains  *bool `yaml:"enable_subdomains"`
	MaxSubdomains     *int  `yaml:"max_subdomains"`
	IteratorBatchSize *int  `yaml:"iterator_batch_size"`
}

// WebSearchTool configures the SerpAPI Google-dork asset discovery (passive). The
// SerpAPI key is not a config field: the app injects it from the SERPAPI_API_KEY
// environment variable so the secret stays out of the audit configuration.
type WebSearchTool struct {
	Enabled            *bool `yaml:"enabled"`
	MaxResultsPerQuery *int  `yaml:"max_results_per_query"`
}

// ShodanTool configures the Shodan host-intelligence search (passive). The Shodan
// API key is not a config field: the app injects it from the SHODAN_API_KEY
// environment variable so the secret stays out of the audit configuration.
type ShodanTool struct {
	Enabled  *bool    `yaml:"enabled"`
	MaxHosts *int     `yaml:"max_hosts"`
	Timeout  Duration `yaml:"timeout"`
}

// NetlasTool configures the Netlas internet-scan search (passive). The Netlas API
// key is not a config field: the app injects it from the NETLAS_API_KEY
// environment variable so the secret stays out of the audit configuration.
type NetlasTool struct {
	Enabled  *bool    `yaml:"enabled"`
	MaxHosts *int     `yaml:"max_hosts"`
	MaxPages *int     `yaml:"max_pages"`
	Timeout  Duration `yaml:"timeout"`
}

// PortScanTool configures the naabu port scanner with nmap service detection
// (active). NmapCommand is the nmap command line naabu runs against open ports;
// nmap must be installed on the host (see ScanProfile.ValidateExternalTools).
//
// Every field outside the UDP block describes the TCP pass. UDP is a second,
// independent pass over the same admitted hosts (see [PortScanUDP]); it neither
// replaces nor reinterprets any TCP setting, and the two share only the host
// admission, the host-concurrency slot, and the active-host budget.
type PortScanTool struct {
	Enabled         *bool    `yaml:"enabled"`
	Timeout         Duration `yaml:"timeout"`
	RatePerSecond   *int     `yaml:"rate_per_second"`
	HostConcurrency *int     `yaml:"host_concurrency"`
	Ports           []int    `yaml:"ports"`
	NmapCommand     string   `yaml:"nmap_command"`
	// UDP configures the optional UDP pass. The block is required; its own
	// enabled flag decides whether the pass runs.
	UDP PortScanUDP `yaml:"udp"`
}

// HttpProbeTool configures the HTTP probe (active).
type HttpProbeTool struct {
	Enabled      *bool    `yaml:"enabled"`
	Timeout      Duration `yaml:"timeout"`
	MaxBodyBytes *int64   `yaml:"max_body_bytes"`
	UserAgent    string   `yaml:"user_agent"`
}

// HttpsTool configures the active HTTPS TLS/cert/HSTS probe (active).
type HttpsTool struct {
	Enabled *bool    `yaml:"enabled"`
	Timeout Duration `yaml:"timeout"`
}

// SmtpTool configures the active SMTP STARTTLS probe of MX hosts (active).
type SmtpTool struct {
	Enabled *bool    `yaml:"enabled"`
	Timeout Duration `yaml:"timeout"`
}

// WebInfoTool configures the active HTTP / technology-stack probe (active).
type WebInfoTool struct {
	Enabled      *bool    `yaml:"enabled"`
	Timeout      Duration `yaml:"timeout"`
	MaxRedirects *int     `yaml:"max_redirects"`
	MaxBodyBytes *int64   `yaml:"max_body_bytes"`
}

// WappalyzerTool configures the standalone WappalyzerGo technology fingerprint probe
// (active). The tool is independent of the other HTTP tools: enabling it requires
// none of them and disabling them does not disable it. Every field that shapes a
// request is here, so a config snapshot fully explains what the tool sent - no
// environment variable or ambient state changes its behaviour. The fingerprint
// database is the one embedded in the library; there is no path to point elsewhere,
// which is what keeps a scan reproducible.
type WappalyzerTool struct {
	Enabled *bool    `yaml:"enabled"`
	Timeout Duration `yaml:"timeout"`
	// MaxRedirects caps the redirect hops one attempt follows.
	MaxRedirects *int `yaml:"max_redirects"`
	// MaxBodyBytes is the hard cap on the response body read for fingerprinting.
	MaxBodyBytes *int64 `yaml:"max_body_bytes"`
	UserAgent    string `yaml:"user_agent"`
}

// Load reads and validates a scan configuration file. Unknown fields are
// rejected so a typo cannot silently fall back to a default.
func Load(path string) (ScanProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("read config %s: %w", path, err)
	}
	return ParseProfile(b, path)
}

// ParseProfile validates a scan profile held as bytes, exactly as [Load] validates
// one held as a file. source names where the bytes came from and appears in every
// message, so a caller that never had a file (an embedded resource, a database row,
// an API response) still gets an error an operator can place.
//
// The bytes are read, never kept: the caller owns them, and the capture snapshot is
// written from the caller's copy so what is validated and what is recorded are the
// same bytes.
func ParseProfile(b []byte, source string) (ScanProfile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)

	var c ScanProfile
	if err := dec.Decode(&c); err != nil {
		if strings.Contains(string(b), "\n    concurrency:") {
			return ScanProfile{}, fmt.Errorf("parse config %s: tools.portscan.concurrency was replaced by tools.portscan.rate_per_second; add tools.portscan.host_concurrency too: %w", source, err)
		}
		return ScanProfile{}, fmt.Errorf("parse config %s: %w", source, err)
	}
	if err := c.Validate(); err != nil {
		return ScanProfile{}, fmt.Errorf("invalid config %s:\n%w", source, err)
	}
	return c, nil
}

// APIKeys holds the secret API keys for the paid tools (breach, censys,
// virustotal, websearch, shodan, netlas). They are supplied by whoever starts a
// collection rather than read here, so secrets never appear in the audit-grade
// config file and this package looks at no process state; the vanguard-collect
// command's environment convention lives with the command. Use
// [ScanProfile.ValidateAPIKeys] to fail fast when a paid tool is enabled in the
// config file but its key is missing.
type APIKeys struct {
	Breach     string
	Censys     string
	VirusTotal string
	WebSearch  string
	Shodan     string
	Netlas     string
	// Certspotter is optional: certspotter serves unauthenticated queries (at a
	// lower rate limit), so an enabled certspotter with no key is not an error. It
	// is therefore not checked by ValidateAPIKeys.
	Certspotter string
	// CensysOrgID is the Censys organization ID (see censys.ScanProfile.OrgID).
	// Optional: not checked by ValidateAPIKeys, since Censys falls back to the
	// authenticated user's free wallet when it is empty.
	CensysOrgID string
}
