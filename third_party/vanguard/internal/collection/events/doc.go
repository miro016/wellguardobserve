// Package events defines the shared domain event vocabulary for the Vanguard application.
//
// By using Domain Events, the reconnaissance actor logic remains asynchronous and entirely decoupled from
// presentation, data persistence (JSON/JSONL sinks), and real-time state tracking (projections).
//
// # Domain Concepts (Ubiquitous Language)
//
//   - EventMeta: Shared metadata envelope embedded in every domain event.
//     Carries a stable EventID, ScanID for run correlation, CausationID for causation
//     links, Source for tool provenance, Phase, Category, Severity,
//     ObservationKind, and CapturedAt.
//   - AnalysisAsOf: The fixed cutoff every temporal judgement over a stream is made
//     against, derived from the stream itself by DeriveAnalysisAsOf (the latest
//     ScanCompleted, or the latest observation flagged partial when a run was
//     interrupted). It lives here because it is a property of the event stream, and
//     every consumer that folds the stream needs it computed the same way. Nothing
//     downstream may read a wall clock: doing so would make the same capture classify
//     differently on every rebuild.
//   - DomainEvent: Common interface for all domain events. Every event carries EventMeta
//     and a human-readable String(). At() returns CapturedAt.
//   - ScanStarted: Emitted at the beginning of a scan run.
//   - ScanEnvironmentRecorded: Emitted immediately after ScanStarted with the
//     build, runtime, module, configuration, and embedded-data identities that
//     make one execution reproducible and its diffs interpretable. Actor
//     (BuildIdentity) is the provenance of the execution: the program that ran it
//     and the one opaque version whoever started it chose. It is an alias of the
//     shared internal/buildid type, the same value the capture manifest records on
//     the filesystem, so the event-stream provenance and the manifest provenance of
//     one execution are the same value rather than two independently collected
//     ones. Nothing downstream parses that version; a diff compares it whole.
//   - ScanCompleted: Emitted at the end of a scan run with total duration.
//   - DnsDomainNameDiscovered: Emitted when a new domain name is discovered by a passive
//     source (crt.sh crawler, subfinder, VirusTotal, and the other enumerators).
//     DiscoverySource records how it was found and is named distinctly from
//     EventMeta.Source (the producing tool) to avoid a JSON key collision.
//     SourceObservedAt optionally carries a provider's real-world name observation,
//     while EventMeta.CapturedAt remains the scan observation time.
//   - DnsRecordsDiscovered: Emitted when DNS records for a domain are resolved.
//   - ZoneTransferDiscovered: Emitted when an active DNS zone transfer succeeds.
//   - DomainRegistrationDiscovered: Emitted when registration data (registrar,
//     lifecycle dates, contacts) is gathered for a domain via WHOIS or RDAP.
//     DataSource records which leg answered ("whois"/"rdap"); with Source it
//     enables cross-tool comparison of overlapping fields.
//   - MailSecurityDiscovered: Emitted when email-authentication records (SPF, DMARC,
//     DKIM, BIMI) are gathered for a domain. Folds into the owning Domain alongside
//     DnsInfo and Registration; DMARCSeverity grades the p= policy and the SPF
//     analysis tracks the RFC 7208 lookup budget.
//   - CertificateDiscovered: Emitted for both historical-log and live-probe
//     certificate observations. CertificateData separates ValidFrom/ValidUntil,
//     LoggedAt, and LiveVerifiedAt; EventMeta.ObservationKind states how it was obtained.
//   - FindingRaised: Emitted when a rule derives a potential weakness from another
//     event. Its envelope ObservationKind is always "derived" (a finding is derived,
//     never observed), so the acquisition method and instant of the underlying
//     evidence ride on EvidenceObservationKind and EvidenceObservedAt. A provider
//     finding keeps the provider's own observation time, or zero when the provider
//     supplied none; scan time is never substituted.
//   - IPAddressDiscovered: Emitted when a domain resolves to an IP address (A or AAAA).
//     The bridge between DNS (domain) and infrastructure (netblock, ASN). Confidence
//     ("confirmed") stamps the address as directly resolved on the IP asset.
//   - ActiveTargetApproved: Emitted after a normalized domain or IP passes every
//     pre-traffic scope, ownership, deduplication, and active-budget gate. It is the
//     canonical positive authorization record, so the stream says what was allowed to
//     receive traffic and why; discovery alone never grants contact permission.
//   - NetblockDiscovered: Emitted when an IP is mapped to its routed prefix and ASN.
//   - IPReachabilityObserved: Emitted when the active phase determines whether the
//     scanner can route to an IP. The typed State names the verdict so the projection
//     records the exact case: reachable, the IPv6-only / no-route skip (never probed),
//     or a probed host that answered nothing (down or filtered). An unreachable verdict
//     stamps the coverage gap onto the IP asset (alongside the coverage IssueObserved),
//     so the report and JSON can show per-IP reachability rather than only an opaque
//     issue, and the IPv6 gap stays distinct from the down/filtered one.
//   - HostOSGuessed: Active-phase event carrying an inferred OS family for a host,
//     aggregated from nmap per-service ostype hints. A weak, inferred signal (not a
//     privileged -O fingerprint); folds onto the IP asset as a guess, never asserted.
//   - FindingRaised: Emitted when a detector identifies a potential weakness against an
//     asset (CategoryFinding). Distinct from IssueObserved: a finding is noteworthy about
//     the target, an issue is a fault in our own scan. Severity is carried in EventMeta.
//     Confidence ("confirmed"/"inferred") marks a derived/banner-inferred finding; a
//     later "confirmed" report of the same rule+asset upgrades it, and the risk model
//     down-weights inferred ones.
//     KnownExploited flags a finding whose CVE is in the bundled known-exploited (CISA
//     KEV) snapshot (internal/projections/intel); the risk model up-weights it.
//   - ServiceDiscovered: Active-phase event for an open port and identified service on an IP.
//   - HttpEndpointDiscovered: Active-phase event for an HTTP(S) endpoint that responded.
//     AuthType/AuthEvidence carry an observed authentication surface (login form,
//     WWW-Authenticate challenge, 401/403) classified from the response the probe
//     already fetched; it folds onto the host's domain (AuthSurface facet) and feeds
//     risk criticality and the credential-stuffing scenario. No login traffic is made.
//   - HttpRedirectObserved: Active-phase event for a 3xx response received from
//     FromURL and the followed or rejected policy decision for its resolved ToURL.
//     A rejected destination is referenced evidence, not proof that it responded.
//   - TechnologyFingerprinted: Active-phase event identifying a technology on an endpoint.
//     Carries the name, detected version, matched evidence, and - when the producing
//     tool has them - the fingerprint Categories and CPEs, both sorted and deduped by
//     the producer so replay is byte-identical. Several tools report technologies on
//     the same URL, so projections merge by case-insensitive name and union the sets
//     instead of keeping the first report.
//     The active-phase events set Phase = PhaseActive and require sending traffic to the target.
//   - IssueObserved: Emitted when non-fatal errors or reconnaissance issues occur.
//     Severity, CausationID, and Source are carried in the embedded EventMeta. Class
//     carries the
//     producer's own classification ("coverage", "timeout", "dependency", ...) for
//     a tool that raises more than one kind under one Source: an unreachable host
//     and a missing dependency cannot be told apart by Source, and reporting the
//     unreachable host as a tool failure tells a reader the opposite of what
//     happened. It is empty when the producer did not classify, and readers fall
//     back to the Source.
//   - HostProfileObserved: Host-level active evidence beside the service list - the
//     name the host publishes for itself, the other names and addresses that answer
//     for it, an ordered list of OS candidates, a MAC address when the host shares
//     the scanner's segment, an uptime estimate, the reason the scanner considered
//     the host up, and the traceroute path. Every field is an inference, never an
//     assertion; HostOSGuessed remains the single derived OS the asset graph folds.
//   - ServiceScriptObserved: One host or service script result (an nmap NSE script
//     today) as bounded evidence: the script identifier, the bounded output with its
//     original size and digest, and a ParseStatus saying whether a reviewed parser
//     handled it. An unrecognised script is retained as evidence and never promoted
//     to a finding on its own.
//   - TlsSecurityAssessed: A full TLS assessment of one endpoint and server name, on
//     any port. Distinct from TlsPostureDiscovered, which is the HTTPS-shaped view of
//     a domain: this one keys on IP/Port/ServerName, so TLS on SMTP, LDAP, or a
//     database service keeps its port and gains no HTTP meaning it never had. Each
//     section carries an AssessmentState, so an untested check can never read as a
//     passed one. AssessedNames states which names the measurement covers: a producer
//     that measured several names but returned one result for them leaves ServerName
//     empty rather than naming one of them arbitrarily.
//   - SshPostureDiscovered: The algorithms and protocol an SSH endpoint offers -
//     key exchanges, host-key types, ciphers, MACs, compression, and authentication
//     mechanisms - kept structured rather than flattened into a banner string,
//     because the offer is what the security question is about.
//   - DomainEventSink: Common receiver interface implemented by persistence sinks, reporters, and UI controllers.
//
// # Metadata Envelope (EventMeta)
//
// Every domain event embeds EventMeta which provides:
//   - EventID: stable SHA-256 hash of payload and timestamp, unique per event.
//   - ScanID: shared across all events in one Orchestrator.Run call, enabling event replay.
//   - CausationID: links back to the system event (or another domain event) that caused this one.
//   - Source: the tool that produced the underlying data ("crtsh", "dnsinfo", "asn", "orchestrator").
//   - Phase: PhasePassive for non-intrusive collection; PhaseActive for direct target
//     interaction.
//   - Category: groups events into lifecycle, discovery, finding, or issue.
//   - Severity: ranks issues and findings (Info, Low, Medium, High, Critical).
//   - ObservationKind: states whether a claim came from input, a historical log,
//     a passive snapshot, a DNS answer, an active probe, derivation,
//     lifecycle control, or an operational issue. It is independent of confidence.
//
// # Volatile vs semantic envelope fields
//
// The envelope mixes two kinds of field. Five are volatile: they differ between any
// two scan runs by construction, so anything comparing events across runs for a
// stable semantic identity (the scan-comparison feature, internal/projections/scandiff) must
// exclude them:
//
//   - EventID - a hash of payload plus timestamp; unique per event.
//   - ScanID - unique per scan session.
//   - CausationID - an EventID reference, so it inherits volatility.
//   - CapturedAt - wall-clock time of the run.
//   - ToolCorrID - a per-invocation correlation id.
//
// VolatileMetaFields() returns exactly these names and is the single source of truth
// for the split; a reflection test asserts each is a real EventMeta field so the
// list cannot drift from the struct. The remaining envelope fields (Source, Phase,
// Category, Severity, ObservationKind, UnscopedRequest, RetrievalSource) are semantic
// and are retained in a comparison - a severity change, for example, is a real change.
//
// RetrievalSource is semantic on purpose. It says whether an observation came from the
// provider during this scan ("service") or from the fixture compiled into the tool
// package ("cache_embedded"), and a cache-backed acquisition should stay
// distinguishable from a service-backed one when comparing raw events, even though the
// two fold to identical projections. It is orthogonal to Source, which keeps naming the
// provider ("censys", "crtsh") and never becomes a cache label. It is optional: every
// event written before the field existed, every root input event, and every tool that
// has not adopted retrieval provenance leave it empty, so absence means "not stated",
// never "service".
//
// A few typed-payload fields are provenance that legitimately varies run to run and
// would otherwise read as spurious changes - DnsDomainNameDiscovered.DiscoverySource
// / .Depth / .ParentDomain (how/where the name was found this run),
// DnsRecordsDiscovered.Resolver (which resolver answered),
// CertificateDiscovered.SearchQuery (the query that surfaced the cert), and
// IssueObserved.Payload (the raw triggering payload). They are documented here as
// provenance; the comparison excludes them from per-type payload equality rather
// than the events package restructuring around them.
//
// Deferred refinements (recorded, not adopted): nesting the volatile fields into a
// Provenance sub-struct, a first-class Identity() method on each event, and stronger
// natural keys (a machine IssueObserved.Code, a certificate Fingerprint). None is
// needed today - scandiff is the only identity consumer and issues are summarized as
// counts rather than diffed per event - so the codebase convention of not abstracting
// before a second/third consumer keeps the envelope as-is. Revisit when a second
// consumer of semantic identity appears.
//
// # Design Decisions
//
//   - Event-driven Communication: Prevents direct coupling between actors and projections, enabling simple unit testing of projections.
//   - Separation of Concerns: System-level events (retries, raw client errors, protocol specific failures) reside in the specific tool packages, while domain-level outcomes reside here.
//   - Metadata Stamping: The orchestrator (single translator) is responsible for populating EventMeta when translating system events into domain events. Domain event structs do not self-populate metadata.
//   - Scan Lifecycle: Every scan run is bracketed by ScanStarted/ScanCompleted. There is no
//     hard passive/active phase boundary: discovery and active probing run as one scheduled,
//     bounded-concurrency pipeline, and each event's EventMeta.Phase still tags it passive or
//     active for grouping. Progress is observed from the per-tool event stream.
//
// # Versioning and the event registry (replay)
//
// Every persisted event carries SchemaVersion. During the POC, incompatible event
// vocabulary changes may replace version 1 without a migration path; scans must be
// recaptured before replay. This deliberately favors a clear current model over
// temporary backwards-compatible aliases.
// Decoding a typed log back into concrete events is driven by a registry
// (registry.go): each event type is wired in one place via a register call in
// init, mapping its type tag (the struct name, see TypeName) to a decoder that
// returns the event in its canonical form (value or pointer). DecodeByType
// dispatches on the tag; an unknown tag is an error, flagging an event that was
// persisted but never registered.
//
// This registry is the single extension point for the event vocabulary: adding a
// new event type (a new tool or a new recon phase) means
// adding one register call and one sample in the round-trip test, which enforces
// that the registry and the known types stay in sync. The persistence codec and
// replay then handle the new type with no further change.
package events
