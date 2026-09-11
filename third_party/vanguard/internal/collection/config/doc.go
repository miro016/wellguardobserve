// Package config loads the explicit, audit-grade scan configuration shared by the
// CLI.
//
// A scan is defined by TWO disjoint YAML files, composed and never merged:
//
//   - [EngagementConfig] - the customer-specific "who and where": customer identity,
//     the scan root(s), scope (domain include/exclude, IP-range exclude, depth cap,
//     provider-host policy), engagement-wide limits, and the exceptional
//     authorization (out-of-scope GoScans HTTP).
//   - [ScanProfile] - the reusable "how": which phases run, which tools are enabled,
//     and every tool setting.
//
// The ownership rule is simple: the engagement says who and where Vanguard may scan;
// the profile says how it performs that scan. No field exists in both schemas, and
// neither overrides the other. [Scan] pairs the two and [LoadScan] validates each
// file on its own (strict decode: unknown fields and missing required values are
// rejected, all problems reported at once) and then the constraints that span both
// (the GoScans target cap must not exceed the engagement's active-host limit). The application supplies no
// defaults, so the pair alone reproduces the scan and serves as the audit record.
//
// # Files and bytes
//
// Every loader exists twice: [Load], [LoadEngagement] and [LoadScan] read a path,
// and [ParseProfile], [ParseEngagement] and [ParseScan] take the document as bytes.
// The path form reads the file once and delegates, so both forms accept and reject
// exactly the same configurations and there is one validator rather than two.
//
// The byte form exists because a configuration is not necessarily a file: an
// application embedding the collection stage may hold its engagement in a database,
// an embedded resource, or an API response, and must not have to materialise a
// temporary file to run a scan. The bytes stay the caller's - they are read, never
// retained - and the source name a caller passes is what appears in the messages, so
// an error can still be placed by whoever supplied the document.
//
// # Snapshot storage lives elsewhere
//
// A collection keeps verbatim copies of the two documents each execution ran with,
// but this package does not write them. Parsing, validating, and reasoning about a
// configuration is filename-independent work; deciding where a collection puts its
// bytes is not. The snapshot writers therefore live in
// internal/collection/persistence, which owns the collection directory, and this
// package neither joins a path nor opens a file.
//
// What survives the split is the property that made the snapshots worth keeping:
// the bytes that were validated here are the bytes that get recorded, because they
// travel as bytes rather than as a re-marshalled document.
//
// This package has no dependency on orchestration or any tool package: it only
// loads, validates, stores, and exposes the YAML-shaped config. The mapping from a
// ScanProfile plus an EngagementConfig to an orchestration.Config lives in the
// orchestration package instead (see orchestration.FromConfig), keeping the
// dependency direction one way. As new tools and phases are added, extend the
// Tools/Phases structs and Validate accordingly, and keep the shipped templates
// under configs/profiles/ and configs/engagements/ in step so operators always have
// a complete, documented starting point.
// Count-style limits share one encoding: zero means none, minus one means
// unlimited, and positive values are finite. Duration caps use zero for no wait
// and minus one second for unlimited. Port scanning names its per-host packet rate
// and host concurrency separately; AXFR is an explicit active dnsinfo capability.
//
// Tool blocks carry no cross-tool requirements. Each tool's run switch stands on
// its own and the phase gate is the only other condition. Most switches are boolean
// enabled flags; crt.sh and Censys use the required modes documented below. An
// operator can enable one tool of a family without discovering an implicit
// dependency at run time.
// tools.wappalyzer, for example, is valid enabled alone and valid enabled beside
// tools.httpprobe and tools.webinfo.
//
// The goscans block is the one tool block with an external runtime requirement
// beyond nmap. It configures the Siemens GoScans active tool, which runs its own
// nmap discovery per host and then banner, TLS, SSH, crawl, and path-enumeration
// checks against the services that discovery found. Validate enforces every value
// only while the tool is enabled, and refuses an enabled goscans in a profile whose
// active phase is off, because the tool sends traffic by definition.
//
// Two constraints in that block are worth knowing before editing a profile. First,
// tools.goscans.nmap.args is argv, never a shell line, and is checked against a
// reviewed allowlist: targets, output flags, NSE selection, and raw-socket scan
// techniques are rejected by name, because the tool owns those and an unprivileged
// TCP connect scan is the reviewed baseline. -sU is rejected specifically, pointing
// at tools.portscan, because upstream goscans discovery keeps only ports whose nmap
// state is exactly "open" while an unanswered UDP port is "open|filtered", so a UDP
// technique there spends traffic and returns nothing. Second,
// tools.goscans.webenum.probe_profile may only name an embedded, checksummed probe
// set: there is no file-path option, because an operator-supplied probe list would
// put unreviewed request paths into an active scanner's contract.
//
// The UDP scan is where that technique does live: tools.portscan.udp. It is a
// nested block of the port scanner rather than a tool of its own, because the UDP
// pass reuses the port scanner's source, tool log, target admission,
// host-concurrency slot, and active-host budget - enabling it admits no extra host
// and spends no extra budget unit. Its own enabled flag decides whether the pass
// runs, and it may only be true when both the port scanner and the active phase
// are on.
//
// The block carries no engine selector, no argument list, no privilege toggle, and
// no fallback policy: an enabled block means one nmap -sU pass built from the
// typed fields, and every one of those choices is a review decision rather than
// tuning. Whether this machine may actually open the raw socket that needs is not
// a configuration question at all - Validate stays a pure judgement of the
// document, and the capability is proven by the runtime preflight in
// internal/apps/scankit, which fails collection rather than downgrading the scan.
//
// Every bound in the block is enforced whether or not it is enabled, so a value
// that would fail the day someone flips the switch fails the day it is written.
// The UDP fields neither replace nor reinterpret any TCP field beside them: the two
// transports are independent passes over the same admitted hosts.
//
// The webcrawler/webenum out-of-scope-HTTP grant is not a profile key: it is a
// customer authorization owned by the engagement file
// (authorization.goscans.allow_out_of_scope_http_requests). Its default is a safety
// decision rather than a struct default standing in for one: false/absent clears the
// webcrawler and webenum modules before the tool starts, because their upstream
// requester dials redirects and links without asking Vanguard's request authorizer.
// Setting it to true runs them and moves the scope check from the request to the
// result: each fetched endpoint is judged afterwards, and only one the policy would
// have refused is marked unscoped and its host reported. It needs an engagement
// mandate that tolerates a request to wherever a crawl leads.
//
// One knob is shared on purpose: tools.goscans.banner.dial_timeout is the TCP
// connect bound for the banner module and for the ssh module, which has none of its
// own, because both make one plain connection to one discovered service. It is
// therefore required whenever either module is enabled, and only then: a disabled
// module's timeout is not a value a profile has to invent.
//
// The block deliberately exposes no credential, proxy, download folder, probe-file
// path, or toggle for the excluded upstream modules (SMB, NFS, OT discovery, Active
// Directory enrichment, the upstream vulnerability-template wrapper). Event-payload bounds that do
// not change what the scanner sends (cipher, certificate, and algorithm list sizes,
// NSE script output size, forwarded upstream log size) are fixed in the tool rather
// than operator-tunable.
//
// Verifying that the configured nmap, Python, and SSLyze actually exist and carry
// the right versions is a startup check, not a config check: it executes commands,
// and this package stays a pure decode-and-check of the file. That check runs only
// when the tool is enabled, so a passive profile never requires any of them.
//
// # Phases
//
// [ScanProfile.PhaseSet] derives the set of enabled reconnaissance phases (passive,
// active) from a validated config, and [PhaseSet.Names] renders it as the canonical
// name list the collection manifest (internal/collection/persistence) records as
// what a collection was asked to cover. A phase's prerequisites are enforced on the document itself:
// active reconnaissance probes what passive discovery found, so [ScanProfile.Validate]
// rejects a profile that enables active without passive before a destination is
// claimed.
//
// The engagement's scope.probe_provider_hosts is the required three-state policy for
// an IP a passive host-intel provider (Censys/Shodan/Netlas) attributed to an
// in-scope domain but that domain's own DNS never resolved: never, corroborated, or
// always. The shipped engagements use corroborated, which requires an in-scope PTR, a routed prefix shared
// with a DNS-confirmed estate address, or an in-scope DNS SAN from one bounded TLS
// certificate preflight. The inferred asset stays in the graph under every policy,
// and the allow/skip reason is recorded as a provider-probe issue. See
// orchestration.doc.go "Provider-only hosts rejoin the asset graph" for execution.
//
// Paid tools (breach, censys, virustotal, websearch, shodan, netlas) need a
// secret API key that must never live in the audit-grade config file, so it is
// supplied separately as [APIKeys] by whoever starts the collection.
// [ScanProfile.ValidateAPIKeys] fails fast, naming the tool and the expected
// environment variable, when a paid tool is enabled but its key is unset. Censys
// requires its key only in mode "enabled"; "embedded_cache_only" cannot call the
// API and needs none. The caller must perform this check right after Load and
// refuse to start on error, rather than silently running with the tool
// downgraded to disabled.
//
// # Tool modes (crt.sh and Censys)
//
// Most tools carry a boolean enabled. crt.sh ([CrtshTool.Mode]) and Censys
// ([CensysTool.Mode]) instead carry a required mode string, because each has a third
// behaviour: results compiled into its own tool package as a development fixture.
// There is no enabled key for these two, so a mode and a flag can never disagree, and
// strict decoding rejects a stale profile that still carries one.
//
//   - tools.crtsh.mode: "disabled" (the tool and the passive crawler do not run),
//     "enabled" (query crt.sh), "embedded_cache_support" (answer from the fixture
//     when it has the query, otherwise query crt.sh exactly as "enabled" does).
//   - tools.censys.mode: "disabled", "enabled" (query the Censys API),
//     "embedded_cache_only" (answer from the fixture and never reach Censys; a
//     domain the fixture lacks yields no result rather than an API call).
//
// This package stays tool-independent: it validates the strings against the two
// allowed sets, reporting the field and the allowed values for a missing or unknown
// value, and orchestration converts a validated value into the tool package's own
// mode type. Only Censys "enabled" requires CENSYS_API_KEY: "embedded_cache_only"
// validates with no Censys credentials at all, and a key that happens to be set never
// turns it back into API access.
package config
