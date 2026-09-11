// Package report renders the operator-facing executive report and risk model from
// a folded projection read model.
//
// The package is deliberately separated from internal/projections (F4 of
// the architectural evolution) to decouple event-folding from report rendering.
// Consumers that only need the folded inventory or read models do not compile
// the report formatting and Markdown rendering machinery, and vice versa.
//
// # Architecture & Invariants
//
// While the report rendering now lives in its own package, it strictly preserves
// the documented invariant: the orchestrator is the single translator from tool
// output to domain events, and the projection is the single read model folded
// from those events. Package report is a pure consumer of *projections.Projection;
// it performs no I/O, invokes no tools, and mutates no state. Every output
// (Markdown string, JSON structure, or RiskModel) is a pure, deterministic
// function of the projection and the scan metadata.
//
// # Risk Model
//
// [BuildRiskModel] rolls findings up into a per-customer and per-asset risk posture.
// Each asset's base score is the sum of its findings' severity weights (an
// inferred finding is down-weighted so it cannot outrank a confirmed finding of
// equal severity), scaled by a criticality factor derived from signals in the
// projection (apex domain, auth/admin web surface, mail infrastructure for
// domains; confirmed-open live services for IPs). A known-exploited CVE is weighted
// up, and temporal relevance discounts evidence that may no longer describe the
// estate.
//
// # Executive Report & Markdown
//
// [BuildReport] combines the inventory counts, web application endpoints,
// top findings (sorted by severity with root-to-leaf discovery lineage trails),
// risk rollup, coverage gaps, tool errors, and recommended next steps into a
// structured [Report]. IssueObserved events retain structured identity, source,
// class, severity, target, message, causation, and capture time. The compact report
// shows the highest-priority rows with full counts, while [Report.IssueLedger]
// exposes every row for the standalone Markdown and JSON ledger.
// The run's ScanEnvironmentRecorded is rendered immediately after the scan
// header, before temporal claims or findings, and is also present in report JSON.
//
// It takes the analysis as-of time as an argument rather than reading a clock, and
// classifies the findings against it as a finalize pass. Every temporal word the
// report prints - current, expired, expiring, recent, stale - is relative to that
// one cutoff, which the Temporal Scope section states before any count. Passing a
// cutoff other than the stream's own is the deliberate re-evaluation path: the
// report then prints both the evidence capture time and the time it was re-judged
// against, so the original scan-time reading stays recoverable. Nothing in this
// package may call time.Now; an architecture test enforces that, because a
// wall-clock verdict would change on every rebuild of the same capture. The Attack
// Surface section keeps complete totals and decomposes them with the same six currentness
// labels as facts.json. The service total is the complete classified surface
// ([Report.ServiceCount]), including provider-reported services the active phase never
// confirmed; [Report.ServiceCountActive] carries the actively confirmed subset, which is
// also the live_verified part of the composition. Temporal Coverage reports source-dated
// claims, fallback-only
// subjects, provider evidence age, and freshness windows; it is the facts graph's own
// accounting, serialized byte-for-byte identical to the copy in facts.json so the two
// artifacts never disagree. Report-only entity-to-facts cross-checks (count mismatches
// and current-finding-on-historical-asset contradictions) are published separately under
// [Reconciliation], because they exist only where both projections are in hand.
// Historical and unknown evidence remain in the ledger and are down-weighted or labelled,
// never silently cleared. [Report.Markdown] renders this structure into an
// executive-ready Markdown document that is also persisted as JSON by the sink.
//
// The anomaly rows themselves are not in that document. One anomaly type fires once
// per subject it applies to, so inline the ledger runs to hundreds of rows and pushes
// the hosts, findings, and issues past where anyone scrolls. The report keeps the
// per-type counts; [Report.TemporalAnomalies] gathers the whole ledger - the facts
// graph's coverage anomalies and the report-only reconciliation together - into
// [TemporalAnomalies], which the sink writes beside the report as its own Markdown
// and JSON pair. Nothing is dropped by the split: it is the same rows, given a
// document where they can be read as a ledger.
//
// The threat scenarios leave the report entirely, for the same reason and by the
// same rule. A scenario is a narrative: an explanation, a severity, a reference
// list, and an evidence chain per asset, and a scan that fires twenty of them buries
// the surface, host, and finding sections a reader came for. [Report.ThreatLedger]
// gathers them into [ThreatLedger], which the sink writes beside the report as its
// own Markdown and JSON pair; the executive summary keeps the headline count and
// carries the link to it.
//
// The host table splits its port total by transport, because tcp/53 and udp/53 are
// two services on one number and a single count cannot say which of those a host
// has. The same column names the third case honestly: a passive provider that
// reported a port without ever saying which transport it saw is counted as unknown,
// not folded into tcp.
//
// Beneath the host table the report carries a service identity index
// ([Report.Services]): one row per socket in the same merged host view, so a
// provider-only service the active phase never confirmed is listed rather than
// silently dropped. Confidence is what separates the two - confirmed means the active
// phase observed the socket open, inferred means only a passive provider claimed it -
// and the sources column names every tool and provider that reported it, read from
// the observation's own provenance rather than assumed. The index is identity only:
// it states that a banner was captured without printing a byte of it, and the banner
// text, the NSE script output, the CPEs, and the certificate and algorithm detail stay
// in the service entity snapshots. The Service Assessments section below it remains
// the TLS/SSH posture index, not a second service listing. Adding the index probed
// nothing new: it renders collection the scan already performed.
//
// Within that document the instances are condensed the same way. A scenario is a
// template that fires once per matching asset, so rendering each instance as its own
// section repeated the explanation, the severity, and the reference list once per
// asset. Instances are grouped into one section per class, stating the shared half
// once and listing the assets and their own evidence beneath it. Everything a
// heading states on behalf of several assets - the scenario summary, its severity,
// and its references - is part of the grouping key, so a heading never claims of
// every asset what is true of only one.
// The count still counts scenarios, not sections.
// A web app's technologies are structured [WebTechnology] entries (name, version,
// categories, CPEs, contributing tools), which the JSON exposes in full. Markdown
// splits them: the Web Applications table shows only the compact "name version"
// labels, and a Technology Detail subsection lists the categories, CPEs, and sources
// for the apps that have them, so the table stays readable when a fingerprint tool
// returns rich metadata.
//
// # Scope Accounting & Third-party Redirects
//
// The Scope & Budget section opens with [ScopeAccounting], a deterministic ledger
// derived from the folded inventory and issue stream rather than any runtime
// counter: discovered names, in-scope names, external/referenced names, names
// skipped at scheduling scope, distinct redirect host pairs followed and rejected,
// distinct active targets approved and hard-excluded, provider-only hosts approved
// and skipped, and the number of budget caps reached.
// None of the counts infers "in scope" from a hostname suffix; they reuse the
// recorded control-plane decisions (the events.IssueClass* classes stamped by the
// scope and budget gates) and the inventory's own referenced-only marks, so a
// replay of the same events reproduces the ledger exactly. The budget events record
// a cap being hit, not a per-target verdict, so BudgetCapsReached is the truthful
// budget count the stream permits, not a count of individual rejected targets.
//
// [BuildReport] also produces [RedirectEdge] rows for the Third-party redirects
// view: one normalized (source URL, destination URL, disposition) row summarizing
// every corroborating observation, with the contributing tools and distinct policy
// reasons unioned across observations. The complete per-event evidence stays in the
// facts graph and the inventory endpoint adjacencies; this view is a summary. A
// redirect destination is a reference, not a live endpoint: it never appears under
// Web Applications unless a separate successful HttpEndpointDiscovered proves it
// responded under authorization.
//
// # Network Audit & Exclusion Verification
//
// The core inventory, findings, and risk views remain a pure function of the event
// stream. The always-rendered Network Audit & Exclusion Verification section is the
// one part that is not event-derived: it renders an explicit, immutable
// [netaudit.Model] the caller built from the completed packet captures, supplied on
// [Analysis]. Packet evidence is deterministic supplemental evidence that
// corroborates exclusion enforcement or exposes a violation; it never mutates the
// event log, becomes a target finding, or changes the target's risk score. A
// confirmed scanner-policy violation is a high-severity operator issue about the
// scan and adds an immediate next step; possible violations and incomplete capture
// coverage are review/coverage items. The section is always present so a reader can
// never mistake a missing or broken capture for a clean zero-violation result:
// every capture status (complete, absent, unreadable, parse-failed, partial,
// collection-mismatch) and every verdict is stated explicitly, and
// negative conclusions are drawn only from a complete capture while positive packet
// evidence stands even from a partial one. When the caller supplies no model (a
// library consumer with no captures) the section is omitted; the operator report
// always supplies one.
//
// # Source collection comes first
//
// The report opens with the capture manifest's collection verdict, before any count,
// risk band, or finding. A reader who treats an empty section as an all-clear must
// first know whether the scan finished looking: a degraded, failed, or interrupted
// collection makes exactly that inference unsafe, and a note further down would be
// read too late.
//
// The verdict is copied, not derived. It arrives through Analysis.SourceCollection as
// an already validated collectionhealth.Summary, because the collected manifest is the
// sole authority for it and this package reads no files and folds no tool log. A nil
// value means the caller had no manifest, and the report then says nothing about
// source completeness rather than implying the collection was clean.
//
// Collection health never becomes target risk. A lost provider query says the scan may
// not have seen something; it is not an issue, a finding, or a threat, and it changes
// no severity and no score. The report keeps the two apart deliberately: "Data view:
// complete history" describes which events were kept, and only the source-collection
// section says whether collection completed.
package report
