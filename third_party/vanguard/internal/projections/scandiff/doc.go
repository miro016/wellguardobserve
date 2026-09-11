// Package scandiff compares two finished scans by folding their domain-event
// streams into per-identity verdicts, so an operator can answer "what is different
// now?" between a baseline (A) and a candidate (B) run of the same estate. It is a
// pure, offline, deterministic package over the event types, like
// internal/projections/dataquality: it takes []events.DomainEvent for each side and returns
// data. It does no I/O and has no persistence dependency; the wiring that loads the
// streams and writes the report lives in internal/projections/persistence.
// The latest ScanEnvironmentRecorded on each side is compared separately from
// target content; a change is a first-class warning because it qualifies every
// finding delta below it. The report names every changed build, runtime, snapshot,
// module, and configuration field instead of reducing that context to one boolean.
//
// # Volatile vs semantic
//
// Every event carries an EventMeta envelope. Five fields are volatile - they differ
// between any two runs by construction - and are excluded from identity and from
// payload equality: EventID, ScanID, CausationID, CapturedAt, and ToolCorrID. That
// list is not restated here as scandiff's own authority: it comes from
// events.VolatileMetaFields(), the single source of truth in the events package, so
// the two cannot drift. The rest of the envelope is semantic and retained: Severity
// (a severity change is a real change), Phase, and Category. Source (the producing
// tool) is a third case: it is excluded from the content payload and tracked
// separately as a per-side source set, except for per-provider snapshot events where
// it is deliberately part of the identity (see below). Note that not every time.Time
// is volatile: only the envelope CapturedAt is run-time, while certificate
// ValidFrom/ValidUntil/LoggedAt and registration dates are intrinsic and are
// compared.
//
// # Identity
//
// Matching events across scans needs a stable semantic identity, since no envelope
// id is shared between runs. The identity of an event is its concrete type name
// plus the normalized natural-key fields of the asset or fact it describes:
//
//	identity = TypeName + "|" + normalizedKeyFields
//
// The per-type natural keys live in a registry inside this package (identity.go),
// rather than as a method on each event type. This keeps all identity knowledge in
// one reviewable place and leaves the event package untouched; the cost is that the
// registry must track the event structs, which the registry-completeness test
// guards. A type without a registry entry falls back to type name plus its full
// normalized payload: safe but coarse, since any payload difference then reads as a
// new identity (a missing+unexpected pair) instead of a single changed entry.
//
// # Multiplicity and per-source presence
//
// The same identity can occur several times in one scan - a name found by crtsh,
// subfinder, and virustotal emits three DnsDomainNameDiscovered events with the
// same identity but different Source. Such occurrences are collapsed by identity
// into one comparable payload (field values unioned), and the set of contributing
// Sources is recorded separately (SourceDelta). This keeps "changed" about the fact
// itself, not about which tool happened to report it. Per-provider snapshot events
// (CensysHostsDiscovered and the like) instead fold Source into the identity, so
// each provider's snapshot is its own fact.
//
// # Payload equality and classification
//
// Once two events share an identity, the diff compares their semantic payload,
// modeled as an ordered set of normalized fields (payload.go): scalars use a
// single-element value list, set-valued fields (A/AAAA, NS, SANs, CPEs, headers)
// use the sorted, normalized set. Two payloads are equal exactly when their field
// lists are equal after normalization and per-field sorting. Comparison correctness
// therefore lives in normalization (normalize.go): trailing dots, case, IPv4-mapped
// IPv6, URL default ports, and whitespace are canonicalized so the same fact in two
// runs is not a spurious change. Service banner comparison additionally removes
// HTTP Date headers and nmap %D/%Time scan tokens while preserving the raw event.
// A service key carries its transport, and a provider that named none normalizes to
// "port/unknown" rather than "port/tcp": a transport that changed between two runs is
// then an added service plus a removed one, which is what it is, instead of a rename
// that no diff would show at all.
// High-value types use per-type field extraction with this normalization; the long
// tail uses a generic canonical-JSON projection,
// which is correct for the verdict but coarse (no semantic normalization).
// HttpRedirectObserved keys on producing source, normalized FromURL, and hop. Its
// destination, status, disposition, and rejection reason remain semantic payload,
// so a policy or topology change is one Changed row rather than a missing/new pair.
//
// For each identity across the union of A and B (classify.go), the diff assigns
// exactly one class: Matched (in both, equal payload), Changed (in both, different
// payload), Missing (in A only), or Unexpected (in B only). Results are sorted by
// (Type, Identity) so the output is byte-stable and golden-testable. A Changed
// event carries the field-level delta in EventDiff.Changes (delta.go): for each
// differing field, the value sets on each side plus Added (B \ A) and Removed
// (A \ B).
//
// # Coverage and findings
//
// On top of the per-event classification, two quick-insight layers answer "how
// much changed" without reading every event, both extracted directly from the event
// stream (no projection dependency):
//
//   - Entity-key coverage (coverage.go): for each entity kind (domains, ips,
//     services, endpoints, certificates, findings, netblocks) the set of keys each
//     scan covers, with the members gained and lost. Coverage(a, b) returns one
//     CoverageDelta per kind.
//   - Findings delta (findings.go): a severity-aware split of the finding
//     classification into new (in B only), resolved (in A only), and changed, with a
//     by-severity rollup for the summary line. Findings(a, b) returns it.
//
// Certificate coverage and event identity use valueobjects.CanonicalCertSerial, the
// same source-independent key as the inventory projection. Issuer text is excluded
// from identity because live TLS and CT producers spell the same issuer differently.
//
// # Report and rendering
//
// Build (report.go) assembles the classification, coverage, and findings into one
// Report, recovering each side's ScanRef from its earliest ScanStarted. It is pure:
// the operational delta (OpDelta) is passed in already folded, since the I/O that
// reads each collection's tooling.jsonl lives in projection persistence. The Report renders to
// deterministic JSON (the source of truth) and a Markdown summary (render.go) whose
// every list is sorted and capped, so both artifacts are golden-testable.
//
// Matched events are counted, not listed: a real scan matches the vast majority of
// its events, so the Report's Events slice carries only the Changed, Missing, and
// Unexpected entries by default, while Matched lives as a count in Summary and per
// type in Summary.ByType. Options.IncludeMatched (default off) keeps the matched
// entries for a full audit or debugging.
//
// # Scope
//
// Options.IncludeCategories scopes which events the event-level diff covers. The
// zero Options value diffs every category; DefaultOptions() restricts to the
// high-signal discovery and finding content. Lifecycle
// events are bucketed out, and issues are summarized as counts elsewhere (the report
// rendering) rather than diffed as content. Coverage and findings are computed over
// the full stream, independent of this scope.
//
// # Recorded decisions
//
//   - Identity location: the in-package registry (option B), not an Identity()
//     method on each event type (option A). It keeps all identity knowledge in one
//     reviewable place and leaves the event package untouched. Promote to A only if a
//     second consumer needs the same identity.
//   - Normalizers: duplicated from internal/projections/dataquality per the repo's "duplicate
//     until three instances" rule. Extract a shared internal/scannormalize package
//     only when a third consumer appears.
//   - Default category scope: discovery + finding. Issues are
//     summarized as counts (rendered by the report), not fully diffed; lifecycle is
//     excluded. The zero Options value still diffs everything, so the default is
//     opt-in, not a hard policy.
//   - Entity coverage source: extracted directly from the event stream (option B),
//     not by replaying a projection (option A). This keeps the whole comparison pure
//     over events with no projection or persistence dependency, matching the
//     arch-lint rule (scandiff depends only on domain-events and domain-valueobjects).
//   - Payload coverage: per-type field extraction for the high-value types and a
//     generic canonical-JSON fallback for the rest (per-provider host snapshots,
//     lifecycle, issues). This is a hybrid, not a single strategy.
//
// # Still open (notes, not yet decided)
//
//   - Promote a generic-fallback type to a per-type extractor when its coarse
//     whole-value deltas prove too noisy in practice.
//   - DomainRegistrationDiscovered.Contacts is not yet part of its per-type payload,
//     so a change confined to registrant contacts is not detected. Add it if contact
//     drift must be surfaced.
package scandiff
