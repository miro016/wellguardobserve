# Vanguard projection

This directory is everything folded back out of one collection. It is written by
`vanguard-projections build`, it is rebuilt whole every time that runs, and it can be
deleted at any moment without losing anything. No file here is evidence of anything -
the collection it was built from is. This README is generated; it describes the
standard layout only and carries no scan-specific data.

The collection it came from is named in `manifest.json` beside this file, by scan id,
root, and collection times. This directory is not required to sit anywhere in
particular relative to it: a projection is written to a destination the operator
names, and it says what it was built from rather than where that lives.

## How it is produced

Collection and projection are separate commands, run on separate machines.

`vanguard-collect` runs on the scan VM. It contacts targets and providers and writes
only its collection directory (the event logs, the tool logs, the packet captures,
and the verbatim config snapshots). It renders no report, no entity snapshot, no
graph, and no decoded packet view, so a freshly downloaded collection has no
projection at all. That is not a sign anything is wrong; it means nobody has
projected it yet.

`vanguard-projections` runs on the analyst host and rebuilds this whole directory
from that collection alone, offline:

```sh
vanguard-projections build -collection <collection-dir> -destination <projection-dir>
```

Run it again whenever a projection rule changes. The build validates the collection
and writes every artifact with `manifest.json` last, so a directory without a
manifest is an unfinished build and the fix is to run it again. It never writes into
the collection, so re-projecting is free and repeatable.

Corpus-level comparisons take more than one collection and stay separate commands:

- Scan diff: `vanguard-projections diff -a <baseline-collection> -b <candidate-collection> -out <output-dir>`
  (writes `reports/diff.{md,json}`).
- Signals across a corpus: `vanguard-projections signals -root <corpus-root> -out <output-dir>`.
- Manifest-driven corpus parity: `vanguard-projections parity ... -out <output-dir>`.

## Layout

| Path | What it is |
| --- | --- |
| `entities/entity_<Kind>.json` | Snapshot of a folded read model (assets, findings, issues). |
| `reports/report.md`, `reports/report.json` | Operator report (risk, findings, threats). |
| `reports/issues.md`, `reports/issues.json` | Complete, uncapped issue ledger grouped by class and severity. |
| `reports/threat-scenarios.md`, `reports/threat-scenarios.json` | Complete threat-scenario report: every fired attack path with its explanation, severity, references, assets, and evidence. |
| `reports/data-quality.md`, `reports/data-quality.json` | Provider data-quality and tooling stats. |
| `reports/tools-health-signals.md`, `reports/tools-health-signals.json` | Tool-event capture-health signals (log integrity, target attribution, reliability, duplicate queries). |
| `reports/diff.md`, `reports/diff.json` | Scan-comparison report, present when a `diff` was run against this collection (what changed versus another scan). |
| `graphs/facts.md`, `graphs/facts.json`, `graphs/facts.html` | Complete facts graph, temporal accounting, and interactive history/state timeline. |
| `graphs/attack-surface.md`, `graphs/attack-surface.json`, `graphs/attack-surface.html` | Contracted attack surface: names, addresses, services, and web origins, with everything else folded onto them. Derived from the facts graph. |
| `netaudit/summary.md`, `netaudit/raw.jsonl` | Decoded network-audit investigation detail rebuilt from the immutable captures under the collection's `netaudit/` tree. |
| `manifest.json` | Projection manifest: when this derived tree was built, by which projector build, and from which collection. Written last, after every artifact validates. |

## Entities (`entities/`)

Indented JSON snapshots of the folded inventory and rollups, in stable sort
order, for browsing without a replay:

- `entity_DnsDomainName.json` - domains with their DNS, registration, mail security,
  including redirect-only references explicitly marked `ReferencedOnly`.
- `entity_Certificate.json` - certificates from transparency logs.
- `entity_IPAddress.json`, `entity_Netblock.json` - resolved IPs and routed
  prefixes / ASNs.
- `entity_Service.json`, `entity_Endpoint.json` - active-phase open ports and
  HTTP endpoints with fingerprinted technologies and redirect adjacency. A Location
  destination does not become an endpoint until a response event proves it.
- `entity_Finding.json` - deduplicated findings (target weaknesses).
- `entity_Issue.json` - scan issues (faults in our own collection).

These are derived views, not the source of truth: if a snapshot and the logs
disagree, the logs win.

## Reports (`reports/`)

- `report.md` / `report.json` - operator report: a source-collection verdict, a
  temporal scope header, executive
  risk summary, attack-surface counts, a unified per-host view (ports and CVEs merged
  across the active scan and the censys/shodan/netlas facets, each carrying confidence
  and provenance), riskiest assets and their contributing findings, web applications
  exposed, severity rollup, and root-to-leaf how-found trails. It states the threat
  scenario count and links to the report that holds them, rather than carrying the
  narratives itself. A pure function of the event stream plus the collection manifest's
  collection verdict.

  The `Source collection` section comes first because it decides how everything under
  it may be read: it states the collection's status, requested phases, the exact
  count of health-bearing tool events, and one row per lost `(code, tool, component)`
  identity, copied from the collection manifest and never reconstructed from the
  tool log. A degraded, failed, or interrupted collection means an absence below may be
  work the scan never finished rather than something the estate does not have. It is
  separate from target issues, tool-health signals, and packet-capture health: none of
  them changes another's severity or risk score. `Data view: complete history` describes
  event filtering only and is not a claim that collection completed.

  The Scope & Budget section opens with a deterministic scope ledger derived from the
  inventory and issue stream, not runtime counters: discovered names, in-scope names,
  external/referenced names, names skipped at scheduling scope, distinct redirect host
  pairs followed and rejected, provider-only hosts approved and skipped, and budget caps
  reached. A Third-party redirects table lists one row per normalized (source host,
  destination host, disposition) edge with its scope-rejection reason and contributing
  tools. A rejected or referenced destination was never contacted and never appears as a
  web application; the report JSON exposes the same values as the `ScopeAccounting` and
  `ThirdPartyRedirects` fields.

- `threat-scenarios.md` / `threat-scenarios.json` - the complete set of attack-path
  scenarios that fired, derived from the same folded projection as the operator
  report. A scenario is a template that fires once per matching asset, so the
  document states each class once - its explanation, severity, and references - and
  lists beneath it every asset it fired on with that asset's own evidence. It is its
  own document because the narratives would otherwise bury the surface, host, and
  finding sections of the operator report, which keeps the headline count and links
  here. Written whether or not a scenario fired, so the link is never broken.
- `issues.md` / `issues.json` - complete issue ledger derived from the same folded
  projection as the operator report. It retains every scope, budget, coverage,
  timeout, dependency, and unclassified issue with stable event identity and
  provenance. The operator report keeps full counts and only the highest-priority
  rows, linking here for the uncapped detail.

  The temporal scope header states the analysis as-of time (the latest scan
  completion in the stream, or the latest observation marked partial when a run was
  interrupted), the data view, and what "current" means. Every temporal word in the
  report is relative to that cutoff, and the cutoff comes from the stream rather than
  a clock, so rebuilding the report over the same capture reproduces it exactly. Attack
  surface totals remain complete and are decomposed as `live_verified`,
  `currently_resolved`, `valid_unverified`, `recent_passive`, `historical_only`, and
  `currentness_unknown`. The temporal-coverage section accounts for source-supplied
  times, fallback-only claims, provider evidence age, freshness windows, and anomalies.
- `data-quality.md` / `data-quality.json` - engineer report comparing what each
  provider returned for the same customer (coverage, agreement, conflicts) and
  how each performed (latency, errors, rate limits, reliability), folded partly
  from the collection's `tools/tooling.jsonl`.
- `tools-health-signals.md` / `tools-health-signals.json` - engineer report on
  capture and tooling health (not the target's posture): deterministic detectors over
  the collection's `tools/tooling.jsonl` that flag log-integrity breaks (decode, schema,
  sequence gaps, missing correlation), providers that leave events unattributed to a
  target, reliability issues (external rate limits, degradation storms, failed-call
  rate), and diagnosability/hygiene gaps (opaque provider errors, benign outcomes
  logged at warn). Also self-inflicted waste (the same target queried by overlapping
  calls, racing itself into a rate limit). The multi-scan corpus form runs via
  `vanguard-projections signals`.
- `diff.md` / `diff.json` - scan-comparison report, present only when a `diff` was
  run against this collection. Compares this scan with another (matched / changed /
  missing / unexpected events, field-value deltas inside changed events, and
  entity-key coverage deltas), to answer "what changed since last time?".

## Graphs (`graphs/`)

This bucket holds both graph views of the scan. They are one representation at two
levels of contraction and are built from a single fold of the event log, so they live
together; neither is ever built by reading the other's file.

- `facts.md` / `facts.json` / `facts.html` - the complete externalizable facts graph.
  `facts.json` retains every asset, relationship, observation, assertion, evidence item,
  finding candidate, and issue. `classified_surface` assigns every subject one primary
  currentness class without filtering it; `temporal_coverage` reconciles counts and flags
  timestamp conflicts. The HTML timeline offers "History accumulated through" and
  "State at" modes. State mode keeps every subject rendered and styles historical,
  valid-unverified, unknown, and future context separately. A `source_time_missing` flag,
  not timestamp proximity, identifies scan-time-only fallbacks.

The attack surface is the contracted analyst view of that same graph. Where
`facts.*` keeps every asset kind the scan produced, it keeps only what an analyst
attacks - one `Domain` per name, one `IPAddress` per address, one `Service` per
listening socket, one `WebSurface` per web origin - and folds everything else onto
those four: certificates become coverage facets on the names they cover, DNS records
become edges and value-carrying facets, technologies attach to what runs them,
providers and netblocks become address facets, and findings attach to the node they
concern. Nothing is discarded: every folded fact keeps the observation and evidence
ids that lead back into `graphs/facts.json`.

- `attack-surface.json` - the contracted graph, holding its nodes in one array per type
  (`domains`, `ip_addresses`, `services`, `web_surfaces`, each always present), a compact
  `source_collection` block (`status`, `health_total`) stating the same
  collection verdict the operator report explains in full, with a
  `contraction_summary` that
  accounts for every facts asset type as retained, folded, or excluded, an
  `unmapped_findings` list for any finding with no defensible target, and an
  `integrity` block stating the artifact's own structural soundness.
- `attack-surface.md` - the analyst summary: scope and cutoff, the source-collection
  verdict (a warning before the totals when collection did not complete cleanly, pointing
  at `reports/report.md` for the exact losses), counts by node type,
  edge type, and currentness, addresses with their provider attribution, exposed
  services by transport and confidence, web origins with every observed path and its
  response, findings by severity, and the contraction accounting.
- `attack-surface.html` - a self-contained interactive graph, stating the same
  source-collection verdict in its header and banner. It carries its own data
  and filters by node type, edge type, scope, currentness, minimum finding severity,
  evidence mode, confidence, and source, with search and bounded neighbor expansion.
  It has no timeline: this artifact states one analysis cutoff, and history belongs to
  `graphs/facts.html`. The counts always read "showing X of Y", so a filter can never
  look like missing data.

## Network audit (`netaudit/`)

Decoded network-audit investigation detail rebuilt from the immutable captures under
the collection's flat `netaudit/` tree: collection capture health, the deduplicated
conversations, DNS answers, and TLS SNI / HTTP Host observations. `raw.jsonl` has one
JSON record per line (`kind` = capture / conversation / dns) for grep/jq/duckdb.
Bounded audit metadata only, no packet payloads. Present when a packet capture
exists. The Network Audit & Exclusion Verification section of `reports/report.md`
holds the verdicts; this is the raw detail behind it.

## Projection manifest (`manifest.json`)

Written last, after every artifact validates, so its presence is the claim that this
tree is complete. It records when the tree was built, by which projector build, and
from which collection: the source scan id, root, collection times, status, and
collection-health summary. The source collection manifest records its phases.

Unlike the collector, the projector may record an unidentified build: an offline
rebuild of a report is worth more than a refusal to rebuild it.
