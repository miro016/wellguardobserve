// Package upstream is the single boundary between Vanguard and the Siemens
// GoScans library.
//
// Nothing else in the codebase imports GoScans. Everything here is either a type
// alias for an upstream result the actor has to read, a narrow runner interface
// the actor drives, or a request struct that fixes the arguments this integration
// is willing to pass. That keeps the surface auditable: to see everything Vanguard
// can ask GoScans to do, read this package.
//
// # Upstream compatibility
//
// The pinned version lives in go.mod and go.sum, which are the only record of it;
// note the upstream tag is lightweight and can be moved, so the checksum in go.sum
// is what actually detects a rewritten release. Everything below describes upstream
// behavior that a version bump can invalidate, so re-check it whenever the module
// version changes.
//
// Imported upstream packages:
//
//   - discovery, nmap-driven host and service discovery, the only input to every
//     other module here;
//   - banner, plain/TLS/Telnet/HTTP/HTTPS banner collection;
//   - ssl, TLS assessment driven by an external SSLyze process;
//   - ssh, SSH algorithm and protocol assessment;
//   - webcrawler, bounded web crawling;
//   - webenum, bounded web path and vhost enumeration;
//   - utils, the shared logger interface and helpers the above packages expose in
//     their signatures.
//
// Deliberately not imported: smb (the Linux implementation panics when called),
// nfs (setup and execution need privileged mount, showmount, and sudoers changes),
// filecrawler and template (file-share crawling, out of scope for an external
// estate), and the upstream vulnerability-template wrapper (it downloads templates
// during setup). Adding any of them needs a fresh privilege and event review, not
// just an import.
//
// Three upstream packages are compiled into the binary even though they are
// excluded from the product surface, because discovery imports them
// unconditionally: discovery/ad (Active Directory enrichment), discovery/netapi
// (Windows share and group lookups), and discovery/ot (layer-2 OT discovery via
// libpcap). Import-level exclusion is not possible without forking upstream, so the
// exclusion is enforced at the call boundary instead, and that boundary is narrow
// and checkable:
//
//   - AD enrichment only runs when the discovery constructor is given LDAP
//     credentials, and DiscoveryRequest has no field to supply one.
//   - netapi lookups only run on Windows; the Linux implementation is a stub.
//   - OT discovery only runs after an explicit EnableOtScanner call, which this
//     package never makes. Without it the OT scanner stays nil and no raw socket,
//     pcap handle, or layer-2 probe is ever created.
//
// # Request-scope limitation
//
// Upstream's crawler and enumerator disable the HTTP client's automatic redirect
// following and follow Location headers manually inside utils.Requester.Get, then
// only check SameScope after the redirected response has arrived. That is one
// response too late for an engagement boundary: the request to the out-of-scope host
// has already been sent. Upstream also hardcodes the requester factories in its
// constructors, so there is no pre-request interception point out of the box.
//
// The vendor tree is third-party-owned and remains unmodified. Because the required
// authorization cannot be inserted at this boundary, the live [Implementation]
// must not receive WebCrawler or WebEnum requests. The parent package enforces that
// rule in configuration validation, and production orchestration also clears both
// module flags while recording a coverage issue. Request structs and runner methods
// remain here so controlled alternate Upstream implementations can exercise actor
// planning and result translation without network traffic.
//
// # External runtime
//
// discovery needs an nmap executable and ssl needs a Python interpreter that can
// run "python -m sslyze" (the SSLyze executable on Windows). Both versions are
// probed by the upstream constructors, so each TLS request costs two extra process
// spawns. Neither runtime is installed or updated by a scan: deployment provides
// them and the scan performs read-only checks only.
//
// In particular, upstream discovery.Setup and discovery.CheckSetup must never be
// called on Linux, and this package does not. Setup runs setcap against both the
// nmap binary and the Vanguard binary and requires elevation; CheckSetup shells out
// to setcap -v, insists on raw-socket capabilities that only OT discovery needs,
// and sets the process-global NMAP_PRIVILEGED environment variable. An unprivileged
// TCP connect scan needs none of that.
//
// Skipping upstream Setup has one consequence worth naming: Setup is also the only
// caller of the upstream routine that prunes unsupported NSE scripts from the
// forced discovery script list. Without it, discovery always requests all of
// smb-os-discovery, ssl-cert, http-ntlm-info, rdp-ntlm-info, telnet-ntlm-info,
// smtp-ntlm-info, pop3-ntlm-info, imap-ntlm-info, ms-sql-ntlm-info, and
// rdp-enum-encryption, and nmap fails the whole scan if one of them is missing.
// Preflight therefore has to verify script availability itself, read-only.
//
// # Behavior the caller has to work around
//
//   - Cancellation is uneven. SSLRunner, SSHRunner, WebCrawlerRunner, and
//     WebEnumRunner accept a context through SetContext. DiscoveryRunner does not:
//     upstream builds its own context internally and honors only the Run timeout.
//     BannerRunner has neither, only the dial and receive timeouts it was built
//     with. Every Run is blocking and none can be interrupted through its return
//     value, so a caller that abandons one abandons a live child process with it.
//   - The crawler writes to disk even with downloads disabled. Its constructor
//     creates a download URL list inside WebCrawlerRequest.OutputFolder and fails if
//     it cannot, and a background worker appends to that file for the whole crawl.
//     The folder is mandatory and must be caller-owned temporary space.
//   - The enumerator reads its probe list from a file path and rejects anything
//     that is not a regular file, so an embedded probe set has to be materialized
//     before the scanner is constructed.
//   - Result payloads are only partly bounded. banner truncates each probe at 2048
//     bytes, but the HTML bodies in crawler pages and enumeration items are read
//     without a size limit.
//   - ssl keeps its cipher table in a process-global initialized once per process
//     (primed here before the first TLS scanner), and discovery keeps global DNS
//     and Active Directory throttles. Neither is per-scan state, so concurrency
//     limits belong to the caller.
package upstream
