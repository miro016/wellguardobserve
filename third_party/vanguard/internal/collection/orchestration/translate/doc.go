// Package translate maps tool-actor result DTOs into domain events.
//
// It is the orchestration layer's anti-corruption boundary: every function here
// takes a concrete tool result (a *dnsinfo.Records, a *https.Result, a crawler
// system event, a raw HTTP response, ...) plus the identity a caller threads in
// (scanID, causationID, and where applicable a tool correlation ID) and returns
// the typed domain events that result. The functions are pure: they hold no
// state, perform no I/O, and never reach back into the orchestrator. This keeps
// the mechanical "shape one package's struct into another's event" work out of
// the orchestrator, where the scheduling, concurrency, budget, and scope logic
// lives, so each side stays readable on its own.
//
// # Source labels
//
// Each translator stamps EventMeta.Source with the producing tool's label (the
// exported Source* constants in sources.go). Those same labels double as the
// tool name the orchestrator threads into its per-call correlation IDs, so they
// are exported and shared rather than duplicated: the orchestrator references
// translate.SourceX wherever it tags a tool call, and the translator stamps the
// identical value on the event, keeping the audit join consistent.
//
// # Several tools, one endpoint vocabulary
//
// The active HTTP tools (httpprobe, webinfo, wappalyzer) each translate into the same
// HttpEndpointDiscovered plus TechnologyFingerprinted pair, keyed by the response's
// final URL, with the endpoint event as the causation of its technology events. They
// do not share code, results, or response bodies: each reports only what its own
// request observed, stamped with its own source. Overlap is resolved downstream, by
// the projections that merge technology entries by canonical product identity and
// union their metadata - not here, where a translator can only see one tool's result.
// Redirect trails use a separate shared mapping: HTTPRedirects preserves every
// followed or rejected hop as HttpRedirectObserved, stamps the producing tool and
// correlation ID, and chains each hop's causation to the previous redirect event.
// The helper performs no policy decision; it translates the decision the tool made.
//
// What does belong here is making each tool's own output well formed. A stack detector
// that returns "Microsoft-IIS/10.0" as a display string has its version split back
// into the event's Version field before the event is built, because an event is the
// audit record: claiming the version is unknown when the probe plainly saw it is
// wrong regardless of what any downstream merge does about it.
//
// CPE-producing translators also canonicalize upstream bindings here. Tool results keep
// raw CPE text for diagnostics, while domain events use CPE 2.3 formatted strings through
// valueobjects.NormalizeCPEs. Any new CPE-producing tool must use same boundary instead
// of copying provider text into event stream.
//
// # One tool event in, whole observations out
//
// Most translators take one tool result struct. GoScansEvent instead takes one
// event off a sealed tool-event interface, because that actor reports everything it
// learns as events and has no result object to read afterwards. The switch is the
// whole GoScans-to-domain contract in one place, and the seal makes it exhaustive by
// construction: a new tool event cannot reach the stream without a decision being
// made here.
// The live GoScans crawler and enumerator are structurally disabled because their
// upstream redirect loop cannot accept Vanguard's request policy, so this boundary
// deliberately has no GoScans redirect-to-domain mapping.
//
// One tool event can carry several observations. A host profile yields the profile,
// the reachability the scan proved by observing the host at all, an OS guess, the
// names the host publishes, and the addresses attributed to it - five natural units
// rather than one composite event nothing can key on. Conversely, the tool's own
// lifecycle and diagnostics translate to nothing: they belong in the tool-event log,
// which is where an operator looks to explain what a tool did.
//
// Failures are the exception to that rule. A module that could not run, timed out,
// was refused, or returned an unusable payload becomes an IssueObserved carrying a
// class prefix (dependency, timeout, remote-rejection, parser, filesystem, internal,
// coverage, cancelled, not-applicable), because "the scan did not look" and "the
// scan looked and found nothing" must never be indistinguishable downstream.
//
// # What lives here vs. the orchestrator
//
// Only pure result-to-event mapping lives here. Decisions that need orchestrator
// state - scope and budget gating, circuit breaking, coverage cross-checks, the
// reachability verdicts, seeding, and the lifecycle/issue events the orchestrator
// raises itself - stay in package orchestration. A helper that merely derives a
// value a translator needs (auth-surface classification, technology
// fingerprinting, port-name lookup, endpoint-URL normalisation) is unexported
// here because only the translators call it.
//
// The GoScans substage keeps that split too: the translator maps a discovered
// virtual host into DnsDomainNameDiscovered, and the orchestrator drops the ones the
// run's scope excludes before publishing. A hosting provider's reverse-DNS name is a
// real observation and a policy decision at the same time, and only the second half
// needs orchestrator state.
//
// Temporal provider facts are preserved at this boundary as UTC values instead of
// being replaced by translation time. EventMeta.CapturedAt remains the scan time;
// SourceObservedAt carries when a provider observed or indexed the asset,
// ValidFrom/ValidUntil carry certificate validity, LoggedAt carries CT history, and
// LiveVerifiedAt carries Vanguard's direct handshake time. Every translator also
// stamps ObservationKind, so consumers never infer acquisition semantics from Source
// names or zero timestamps.
//
// Retrieval provenance is copied, never inferred. Tool results and crawler system
// events that state where their data came from carry a plain "service" /
// "cache_embedded" string (their packages cannot import the events package);
// CrawlerEvent, CensysHosts, CorroboratedSubdomain, and CorroboratedCertificate copy
// it onto EventMeta.RetrievalSource before computing the event ID, so the value is
// part of the event's identity. EventMeta.Source is untouched and still names the
// provider, so a cached Censys observation is still sourced to "censys". Translators
// for tools that do not state a retrieval source leave the field empty, which means
// "not stated" rather than "service".
package translate
