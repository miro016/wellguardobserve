// Package projections deterministically folds domain events into Vanguard's
// live, in-memory scan view. It contains the inventory relationship graph and
// composes the findings, validation, lineage, issue, risk, and threat read
// models used during collection and replay.
//
// The package owns interpretation, not collection, persistence, or presentation.
// [Projection.ApplyDomain] accepts events from a live scan or a persisted log;
// replaying the same ordered stream rebuilds the same state.
// The entities subpackage owns the assets and assessment facets materialized by
// these folds. Collection records observations as events and never constructs
// projection entities directly.
//
// # Fold contract
//
// Live orchestration emits event values, while the event codec decodes pointers.
// Every fold normalizes with events.AsValue before its type switch, so live and
// replay forms cannot diverge silently. New folds must preserve that rule.
//
// [Projection.AnalysisAsOf] derives the single cutoff for temporal judgments
// from the stream: the collection's completion, or the latest captured
// observation for a partial stream. Projection and report code must not read the
// wall clock, because rebuilding an unchanged capture must not change a verdict.
//
// ActiveTargetApproved events reproduce authorization and scope accounting in
// [Projection.ActiveApprovals]. They do not create inventory assets; approval to
// contact a target is not evidence that the target exists.
//
// # Inventory
//
// [Inventory] is the canonical graph of domains, IP addresses, netblocks,
// services, certificates, and HTTP endpoints. Nodes use natural identities,
// edges and provenance are deduplicated, and applying an event is idempotent.
// Deterministic Sorted* accessors are the public traversal boundary for reports
// and snapshots; consumers must not depend on map iteration order. Each order is
// total over the node identity it sorts, so no two distinct nodes ever compare
// equal: a partial order would leave ties to be settled by the randomized
// iteration of the map the nodes were folded into, and the same collection would
// then project to different bytes on every rebuild.
//
// Independent observations enrich the same node without erasing provenance.
// Technology findings merge on normalized product identity, union their
// categories, CPEs, and sources, and retain distinct non-empty versions. A
// provider-only address is materialized with inferred confidence and can later
// be upgraded by direct DNS or active evidence without losing attribution.
// Wildcard certificate names remain certificate coverage and do not create
// resolvable domain nodes.
//
// HttpRedirectObserved attaches adjacency to the observed source endpoint. Its
// destination creates only a referenced domain or IP until independent evidence
// establishes an endpoint. This keeps rejected and third-party redirects visible
// without inflating the active attack surface.
//
// Active assessments fold onto the asset they describe. Service identity fields
// are enriched when empty; conflicting non-empty claims are retained in
// ServiceNode.Conflicts. Banners remain timestamped samples rather than identity
// fields. Whole host and SSH assessments replace earlier coherent snapshots
// instead of being merged field by field. TLS assessments are keyed by server
// name because one socket can present different TLS state for different names.
//
// # Composed read models
//
// [Projection] keeps target weaknesses separate from operational scan issues:
// findings are deduplicated and rolled up by the findings subpackage, while
// issues retain their structured source, class, severity, causation, payload,
// and capture time. The exploit subpackage similarly folds validation outcomes
// and indexes them by source finding.
//
// [Lineage] reconstructs event ancestry and descendants from causation IDs with
// bounded, cycle-guarded walks. [Projection.HostView] merges direct host evidence
// with Censys, Shodan, and Netlas facets while retaining confidence and source
// provenance per port and CVE. A port row is keyed by number and transport
// together, so a confirmed tcp service, a provider's udp observation, and a
// provider observation that named no transport stay three rows on one port
// number rather than one row whose transport the first reporter decided.
//
// [Projection.BuildThreats] runs pure curated rules over the read-only assetgraph
// view. It returns deterministic threat scenarios; it emits no events and performs
// no I/O.
//
// # Related projection packages
//
// The facts package folds the domain stream into the externalizable provenance
// graph. facts.Graph.View is the read-only boundary consumed by attacksurface,
// which contracts that graph into the analyst's domain, address, service, and web
// view. The dependency remains one-way:
//
//	events -> facts.Graph -> facts.View -> attacksurface.Graph -> renderers
//
// The report package renders operator-facing views from these read models. It is
// pure: where it links to a sibling artifact it states that file name as its own
// local literal, and it opens nothing.
//
// Three offline analyzers also remain pure: dataquality evaluates provider
// coverage and agreement, scandiff compares finished sessions, and toolsignals
// evaluates operational logs. factsreport and surfacereport render the two graph
// views as self-contained pages and return bytes; parityreport evaluates already
// loaded corpus comparisons and returns a report.
//
// The one package that opens a collection file or writes a projection file is
// projections/persistence. It reads one collection root, writes one destination
// root, and owns every bucket and file name a projection has, so nothing above it
// knows a path and no two writers can disagree about where an artifact lands.
package projections
