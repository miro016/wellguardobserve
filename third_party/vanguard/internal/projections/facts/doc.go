// Package facts folds the domain-event stream into a facts knowledge graph: a
// self-describing, externalizable view of a scan in the product-owner "facts"
// vocabulary (assets, observations, evidence, relationships, finding candidates,
// issues). It is a pure read model, the facts analogue of the findings and threats
// packages: it does no I/O, folds deterministically, and rebuilds identically from
// events.jsonl on replay. The wiring that loads a scan's stream and writes the graph
// to graphs/facts.{json,md,html} below a caller-provided destination lives in
// internal/projections/persistence; factsreport renders only the HTML bytes.
// Scan environment records are retained as top-level provenance rather than
// modeled as target assets or observations.
//
// # Why a separate graph
//
// A tool result is only a claim ("some source said something"). The graph translates
// each domain event into facts and links them, so a consumer can walk the chain
// RawEvent -> Observation -> Evidence -> Relationship/Finding and audit exactly why a
// fact is believed. The six node/edge kinds are:
//
//   - Asset - a thing that exists (Domain, Subdomain, ExternalDomain, IPAddress, Netblock,
//     Provider, Service, Endpoint, Technology, DnsRecord, MailService, Certificate), keyed by
//     a canonical key (see keys.go). Scope is decided against the scan root: a name outside
//     the root is an ExternalDomain, kept with its evidence and edges but not counted as
//     in-scope attack surface.
//   - Observation - a claim by a source about an asset (who, when, from which event).
//     Never deduplicated: the same subdomain from three sources is three observations.
//   - Evidence - a usable proof derived from an observation that supports a relationship.
//   - Relationship - an edge between two assets (subdomain_of, resolves_to, cname_to,
//     ptr_to, has_mx, has_ns, has_txt, has_dns_record, exposes_service, serves_endpoint,
//     hosted_by_provider, belongs_to_asn, runs_technology, host_observed_technology,
//     redirects_to, cert_covers_name).
//   - FindingCandidate - an evidence-backed potential weakness, keyed by rule+asset
//     (the FindingRaised id). A FindingRaised raises one. Its asset
//     reference is the canonical key of the kind the event declares, built by the same
//     identity functions the normalizers use ([github.com/velgard-sk/vanguard/internal/projections/entities.EndpointID],
//     [github.com/velgard-sk/vanguard/internal/projections/entities.CertificateID], ServiceID), so a
//     finding always names an asset this graph materializes. factsAssetKey normalizes
//     that key; it never repairs one, because a rewrite here would make facts disagree
//     with the findings model and the threat scenarios about the same
//     persisted event.
//   - Issue - a coverage/ingestion problem (a truncated passive result, a malformed
//     record, an event type without a normalizer yet), never a target risk.
//
// # Provenance is the event envelope
//
// Every observation, evidence item, and relationship carries the provenance drawn from
// the event's [github.com/velgard-sk/vanguard/internal/collection/events.EventMeta]:
// raw_event_id is EventID, caused_by_raw_event_id is CausationID, source is Source,
// mode is Phase, observation_kind is ObservationKind, captured_at is CapturedAt,
// and tool_corr_id is ToolCorrID (which joins a fact back to the exact provider call
// in tooling.jsonl). SourceObservedAt, certificate validity, logging time, and live
// verification remain separate optional fields on each observation.
//
// # Every asset is joined to the graph
//
// An asset that participates in no relationship is a defect, not a stylistic preference: a
// fact the graph asserts exists but cannot relate to anything is unusable by a consumer, and
// it invariably means a normalizer materialized a node and forgot the edge that gave it
// meaning. Three rules keep the graph joined, and [Graph.Integrity] enforces the result.
//
// Every Endpoint is joined to its host by serves_endpoint, derived from the URL authority
// alone. That is the host the request addressed. It is worth stating plainly what the
// events do not carry: an HTTP endpoint event records the URL, the status, and the
// response, and nothing in it identifies the address that served a hostname URL. So an
// endpoint on a name is joined to the name, an endpoint on a literal address is joined to
// the address, and the link between the two is left to resolves_to, where it is separately
// evidenced. Attaching the endpoint to every address the name has ever resolved to would
// claim far more than one HTTP response proved, and keying a service on a DNS name is not
// the identity the Service model uses. A URL that is relative, malformed, or not HTTP(S)
// becomes a quarantine issue instead of an unjoinable endpoint.
// runs_technology and redirects_to stay independent: they may corroborate an endpoint, but an
// endpoint with neither is still connected.
//
// A DnsRecord node exists only where the literal record value is the modeled subject: NS, TXT,
// and the mixed types a zone transfer dumps (joined by has_dns_record). A, AAAA, CNAME, MX,
// and PTR each model something that is already an asset, so the direct edge from the owner to
// that target carries the record's whole meaning and the parallel record node - which nothing
// referenced - is not created. PTR gets its own ptr_to edge from the address at medium
// confidence rather than folding into resolves_to: a reverse record is the address owner's
// label for itself, not proof the name resolves back, and the disagreement between the two is
// exactly what reverse DNS is useful for.
//
// A passive host source (Censys, Shodan, Netlas) reports products at host level with no port
// mapping, so it emits host_observed_technology from the IPAddress at medium confidence and
// passive mode, with evidence that says the product was seen on the host rather than that a
// service runs it. Only an independent service or endpoint fingerprint adds runs_technology,
// alongside the host edge rather than replacing or upgrading it.
//
// # Integrity is checked before anything is written
//
// [Graph.Integrity] is a pure validator over the rendered snapshot, so tests and report
// generation judge exactly the same bytes. It checks unique typed asset identity, that every
// asset relationship resolves both endpoints, uniqueness of (type, from, to) after the merge,
// and non-zero degree for every asset whose type is not allowlisted for isolation with a
// stated reason (see isolationAllowlist).
//
// The two finding edge types do not have two assets as endpoints and are not drawn by the
// HTML view, so they are counted separately and never contribute to an asset's degree.
// Counting them would let an asset that is invisibly isolated on screen pass the check.
//
// Being undrawn is only an accounting fact. Their endpoints are validated exactly like any
// other edge's - the from side must be a finding candidate, the to side an asset key or an
// evidence id - and a defect is an ordinary violation. Report generation refuses to write
// when any check fails: the viewer can only drop an edge whose endpoint is not a node, and
// a finding whose target does not exist is a weakness the artifact cannot lead anyone to.
// The attack-surface contraction refuses the same graph before contracting it, so one
// invariant covers both artifacts.
//
// A HttpRedirectObserved normalizes into a live http_redirect_observed claim on
// the responding FromURL, evidence containing status and policy disposition, a
// serves_endpoint edge from the host in FromURL's own authority to the responding
// Endpoint, and a redirects_to edge to the normalized destination host. The 3xx is a
// direct response from the FromURL authority, so that host edge carries the same high
// confidence and live currentness a probed endpoint would. The destination has a
// no-subject-time assertion and currentness_unknown until another event proves it
// current. Cross-root names are ExternalDomain assets and never become in-scope
// attack surface merely because a Location header referenced them.
//
// Observation currentness is also machine-readable and separate from Confidence. The
// shared exhaustive vocabulary is live_verified, currently_resolved, valid_unverified,
// recent_passive, historical_only, and currentness_unknown. The classified surface puts
// every asset and relationship into one primary class while retaining all weaker evidence
// as badges; it never filters the complete graph.
//
// # One fixed cutoff, never a clock
//
// Every currentness label is evaluated against a single analysis as-of time, derived
// from the stream by [Build] and exposed as [Graph.AnalysisAsOf]: the latest
// ScanCompleted, or the latest observation flagged partial when a run was
// interrupted. A collection carries one completion; taking the latest is corrupt-log
// tolerance, and every event keeps its own captured_at either way.
//
// Reading each event's own capture time instead would give two certificates observed
// minutes apart two different cutoffs; reading the wall clock would make the same
// capture classify differently on every rebuild. Both bounds of a validity window are
// inclusive: a certificate whose valid_until equals the cutoff is still valid.
//
// [Build] fails rather than folding a stream with no capture times. Every event the
// orchestrator emits stamps CapturedAt, so a stream with none is truncated or written
// by an incompatible vocabulary, and every label derived from it would be silently
// wrong. The cutoff, the partial flag, and the data view are stamped into facts.json
// and stated above the counts in facts.md, so no reader has to guess what
// "historical" was measured from.
//
// # Assertions preserve temporal meaning
//
// Every source claim becomes a TemporalAssertion. Point observations, genuine validity
// intervals, capture time, source observation time, and live verification time remain
// distinct. A source with no real-world time is retained with source_time_missing; its
// capture time may keep FirstSeen/LastSeen sortable but never becomes evidence that the
// subject existed then. FirstSeen/LastSeen are therefore ordering summaries, not lifecycle
// claims. TemporalSummary exposes the safe aggregates, including real intervals and whether
// a subject is source-dated or fallback-only.
//
// # The view is the boundary for projections built on this graph
//
// [Graph.View] returns a deeply copied, deterministically sorted read-only [View] holding
// the assets, observations, evidence, relationships, finding candidates, classified
// currentness, scan identity, analysis cutoff, freshness policy, and coverage counts. It
// is what a downstream projection consumes, so nothing has to decode facts.json, reach
// into the fold's mutable indexes, or fold the event stream a second time.
//
// The attack-surface contraction
// ([github.com/velgard-sk/vanguard/internal/projections/attacksurface]) is the
// first consumer. Keeping the direction one-way - events, this graph, the view, then the
// contraction - leaves one authority for provenance and temporal meaning: a normalizer fix
// here reaches every projection on the next replay, with no second implementation of what
// a source claimed drifting behind it. The copy is deep down to the attribute maps and
// assertion lists, so a consumer that sorts or annotates what it was given cannot corrupt
// the graph it came from.
//
// # Position relative to Inventory
//
// This is not a replacement for [github.com/velgard-sk/vanguard/internal/projections.Inventory]
// or the assetgraph view. Inventory is the internal, in-memory asset model the report
// consumes; the facts graph is an externalizable interchange artifact in the
// product-owner language that promotes observations and evidence to first-class nodes.
// It reuses leaf identity where that is free - a Service asset keys on the canonical
// [github.com/velgard-sk/vanguard/internal/projections/entities.ServiceID] ("host/port/proto")
// so a passive Censys service and an active service land on one node - but is otherwise
// an independent fold. They land on one node only when they agree on the transport:
// a service Vanguard scanned itself states one (an older capture that left the field
// empty means tcp by the active scanner's contract), while a provider that named none
// keys on entities.ProtocolUnknown so its observation stays visible without passing as
// the TCP service on the same port. A provider transport that is neither tcp nor udp
// is quarantined as an issue carrying the offending text, because a provider schema
// change must be reported rather than guessed at.
//
// # Technology assets accumulate their metadata
//
// A Technology asset is keyed by the canonical product identity from
// [github.com/velgard-sk/vanguard/internal/valueobjects.NormalizeTechnology],
// not by the name a tool happened to report. Four tools spell one web server four ways
// - "IIS" from the fingerprint catalogue, "Microsoft-IIS" from a Server header,
// "Microsoft-IIS/10.0" from a display string, "Microsoft IIS httpd" from nmap - and
// keying on the reported name turned that into four assets, which defeats the point of
// an asset graph. The same normalizer backs the inventory merge and the data-quality
// comparison, so all three agree on what one product is. Its
// versions, categories, and cpes attributes are therefore sorted string sets that union
// across observations (Graph.unionAssetSet), not scalars. CPEs on Technology assets are
// product-level identities: version stays in versions and on observation metadata. A
// service observation's operating-system or hardware CPE describes its host, so it is
// stored under platform_cpes on IPAddress asset instead of being misfiled as listening
// product identity. TechnologyFingerprinted events keep all parts on Technology asset
// because fingerprinted technology can itself be operating system. Generic attribute merge
// fills a key only when absent, which would freeze whichever version was seen first
// anywhere in the scan and drop a second endpoint's version or a second tool's CPEs.
// The single version an individual report carried stays on that report's observation
// metadata, so per-observation detail is not lost to the merged set.
//
// # Determinism and coverage
//
// [Graph.Apply] normalizes every event through [events.AsValue] before dispatching, so a
// live value and a replayed pointer of the same event fold identically (the parity guard
// documented in the projections package doc). Assets and relationships deduplicate by
// canonical key; observations and evidence do not. Rendering sorts every collection, so
// the same stream yields byte-identical output. Coverage is honest in two dimensions: an
// event type without a projection decision is counted under Coverage.UnmappedByType, while
// TemporalCoverage reports source dating, fallbacks, provider ages, freshness windows,
// class reconciliation, and temporal anomalies. Neither mechanism drops evidence.
// ActiveTargetApproved is an intentional mapped no-op: it records a scheduler authorization
// decision rather than an observation about a target, so it creates no fact asset but also
// must not be mislabeled as an unhandled event type.
//
// The anomaly ledger is deliberately about what a source could have dated and did
// not. A subject established only by derived assertions - a finding and the edges
// wiring it to its asset and evidence - has no source that observed it, so nothing
// could ever have dated it and a scan-time fallback there is not a coverage gap.
// Those subjects are counted as DerivedOnlySubjects rather than flagged; on two real
// scans they were 430 of 515 anomaly rows, every one of them unfixable and none of
// them about the target. The rendered coverage block prints the anomaly counts by
// type, not the rows: the full ledger goes to its own report, because one type fires
// once per subject and inline it buries every section after it.
// # Assessment facets
//
// The active assessment events normalize onto the assets they concern: a host
// profile onto the IPAddress, and a script result, a TLS assessment, and an SSH
// posture onto the Service (a host-scope script lands on the address). Each becomes
// an observation with its own confidence and its evidence, never an asset
// attribute: every field a host profile carries is an inference, and an attribute
// reads as a fact about the asset.
//
// The per-section assessment states travel on the TLS observation metadata. Without
// them a consumer reading an empty vulnerability list could not tell a clean
// endpoint from one the scanner never reached, and the rendered statement says so
// in words too: an assessment where nothing was tested reports that rather than
// reporting zero issues.
package facts
