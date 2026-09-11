# Vanguard collection

This directory is the complete, event-sourced record of what one Vanguard scan
(one root domain / estate) captured from the outside world. It is the source of
truth: nothing regenerates it, and losing a file here loses data.

One directory is one collection, produced by one run. The destination had to be
missing or empty when the run claimed it, nothing here is ever deleted, renamed, or
appended to by a later run, and there is no way to reopen it: collecting again means
naming another destination. A run that failed or lost work leaves its own directory
saying so. Do not hand-edit files here or drop keepers in. This README is generated;
it describes the standard layout only and carries no scan-specific data.

Two append-only logs are the source of truth: `events/events.jsonl` (domain events)
and `tools/tooling.jsonl` (tool / system events). Both are one continuous, ordered
sequence under one `ScanID`, with the tool log's `seq` starting at zero. The
orchestrator brackets the run with a ScanStarted / ScanCompleted pair. A run that
fails before orchestration may leave no events at all; the manifest still records the
attempt and its outcome.

## Where this sits

This directory is one half of Vanguard's two-phase flow, and the difference is the
only one you need to remember:

- This directory is what was captured, plus the verbatim operator input the
  collection ran with. It is written by `vanguard-collect` on the scan VM, which
  contacts targets and providers and writes nothing else. It travels whole whenever
  a collection is downloaded.
- A projection directory is everything folded back out of this one: entity
  snapshots, reports, graphs, and the decoded packet view. It is written by
  `vanguard-projections build` into a destination the operator chooses, is absent
  until you run it, and can be deleted at any time.

Rebuild the derived tree from here, offline, with no network and no tools run:

```sh
vanguard-projections build -collection <this-directory> -destination <projection-dir>
```

There is no required place for that destination: a projection directory is never
created beside or inside a collection unless the operator names such a path. This
directory is never written by a projection.

The config snapshots live in this directory because the collector wrote them and
nothing regenerates them: a collection that cannot be paired with the exact
engagement and profile it ran with cannot be audited. They are operator input rather
than an observation, which is why they keep their own bucket.

## Layout

| Path | What it is |
| --- | --- |
| `manifest.json` | Collection manifest: scan id, root, status, the phases the run was asked to cover, UTC start and completion, config snapshot paths, collector build identity, and the health summary. Identifies the collection and its outcome without decoding the event stream. |
| `configs/engagement.yaml` | Verbatim copy of the engagement config the run used - the customer, root, scope, limits, and authorizations (audit record). |
| `configs/scan-profile.yaml` | Verbatim copy of the scan profile the run used - phases, tools, and tuning (audit record). |
| `events/events.jsonl` | Canonical, ordered, versioned domain-event log. Source of truth. |
| `events/events_<Type>.jsonl` | The same domain events split per event type (convenience). |
| `tools/tooling.jsonl` | Canonical, ordered tool/system-event log, all tools interleaved. |
| `tools/tool_<tool>.log` | Per-tool human-readable text log. |
| `netaudit/` | The run's network-audit packet capture, present when the scan runs under the netaudit wrapper (the external Linux execution platform; absent on a plain local run): `capture.pcapng.gz`/`capture.pcap.gz`, `capture.log`, `capture.meta.txt`. The wrapper gzips the capture the moment its backend stops, before the file is collected, and nothing downstream recompresses or renames it. The capture backend (ptcpdump/eBPF when available, else tcpdump) and the UTC start/stop times are recorded in `capture.meta.txt`. One immutable capture set, assessed against `configs/engagement.yaml`. The pcap is the immutable collected source of network traffic; the report's decoded packet summaries in a projection directory are rebuildable projections. Event-log-only replay can reproduce the core report but not the packet evidence once the pcap is removed. This tree is written by the external capture wrapper rather than by the scanner. |

## Collection manifest (`manifest.json`)

The one authority for what this collection is, and the provenance record: `cat` it
and you know which build collected what, when, and how it ended, without decoding a
single event. It records:

- `scanID` - the run identity, shared by every event in this directory.
- `root` - the scan root (estate). It comes from the engagement's
  `scope.domains.roots`.
- `status` - how the collection ended (below).
- `phases` - the phase set the run was asked to cover (`passive`, `active`). It
  states what was attempted; whether it finished is `status`.
- `startedAt` / `completedAt` - the UTC start, stamped before any tool ran, and the
  UTC instant the collection reached its terminal status. `completedAt` is absent
  while the collection is running.
- `engagement` / `profile` - the paths, relative to this directory, of the verbatim
  configuration snapshots the run used.
- `collector` - the build identity: a `name` (the program that ran, for example
  `vanguard-collect`) and an opaque `version` (whatever identifier the release
  process that produced the build chose).
- `health` - the collection-health summary, present only when a tool reported lost
  work.

`status` is one of:

- `running` - written before any tool starts. It means the collector is still
  running, or died without recording an outcome. Nothing repairs it later: this
  directory is claimed once, so a collection left `running` stays that way and its
  evidence is read as partial.
- `succeeded` - every phase completed cleanly and every stream was written without a
  reported error.
- `degraded` - the collection finished and wrote its streams cleanly, but a tool
  reported collection work it attempted and lost. What was collected is kept and is
  trustworthy; what is missing is described by the `health` object.
- `failed` - the collector ran to a conclusion and reported an error.
- `interrupted` - the collector was cancelled and recorded that before exiting.

A degraded, failed, or interrupted collection may carry a `health` object: a `total`
count of health-bearing tool events and the distinct `problems` behind them, each a
`code` (the producing tool's stable identity, e.g. `subfinder.provider_failed`), the
`tool`, an optional `component`, and a `count`. The rows are sorted by code, tool,
then component, so two runs that lost the same work write the same bytes. The
per-event evidence - targets, provider responses, error text - is in `tools/`, not
here.

A collection that did not succeed keeps its partial streams and its partial packet
capture, so what it did get is still explainable and projectable. Retrying means
running the collector again into a new destination, which leaves this material
exactly as its run left it. Rebuild reports separately with
`vanguard-projections build`.

An older resumable collection - one whose `manifest.json` carries an `executions`
array - is not readable by this build and is not converted. It is reported as an
unsupported format and left untouched.

The `collector` entry is exactly two fields, and nothing parses the second one:

```json
{"name":"vanguard-collect","version":"v0.21.0-6-g96205f62"}
```

`version` is opaque. It may be a release tag, a commit, or a composite string an
embedding application composed from its own release and the Vanguard release it
built against; Vanguard records and compares it verbatim and never splits,
trims, or interprets it. The rule that matters is that it is non-empty:
collection refuses to start for a build that cannot be named, because a collection
whose producer is unknown can be neither reproduced nor blamed for a defect. The
projector is held to a looser rule - a projection manifest may record an
unidentified `projector`, since an offline rebuild of a report is worth more than
a refusal to rebuild it.

Nothing else about the build lives inside `collector`. The rest of the
reproducibility record sits beside the actor in the run's `ScanEnvironmentRecorded`
event: `Runtime` (the external executables the enabled scanners resolved),
`Snapshots` (the dated or content-addressed embedded data sets in effect), `Modules`
(the build dependencies whose behavior affects results), and `ConfigSHA256` (the
digest of the exact engagement and profile the run used). The event's `Actor` is the same value as the manifest's
`collector`: the event stream is the reproducibility record, the manifest is the
identity you can read on the filesystem, and they cannot disagree.

## Domain events (`events/events.jsonl`)

Each line is a versioned envelope:

```json
{"version":1,"type":"FindingRaised","data":{ ... }}
```

`type` is the event name and drives decoding; `data` is the event. Every event
carries an EventMeta envelope:

- `EventID` - stable hash of payload + time, unique per event.
- `ScanID` - shared by every event in one run.
- `CausationID` - the EventID that triggered this one (empty for root lifecycle).
  Builds the lineage graph.
- `Source` - producing tool/component: a collection tool ("crtsh", "certspotter",
  "subfinder", "virustotal", "dnsinfo", "asn", "whois", "mailsec", "smtp",
  "portscan", "https", "httpprobe", "webinfo", "wappalyzer", "websearch", "shodan", "censys",
  "netlas") or an internal component ("orchestrator", "detector", "scope",
  "budget", "circuit-breaker").
- `Phase` - "passive" (collection) or "active" (direct interaction with target).
- `Category` - "lifecycle" | "discovery" | "finding" | "issue".
- `Severity` - 0 info, 1 low, 2 medium, 3 high, 4 critical (meaningful for
  findings/issues; info otherwise).
- `ObservationKind` - how the claim was obtained: input, historical log,
  passive snapshot, DNS answer, active probe, derived analysis, lifecycle,
  operational issue, or validation.
- `CapturedAt` - when Vanguard recorded the claim during the scan.
- `ToolCorrID` - links the event to the exact tool call that produced it (see
  Audit join).

Event types, by category:

- lifecycle: ScanStarted, ScanCompleted.
- discovery (passive and active collection):
  - names and DNS: DnsDomainNameDiscovered, DnsRecordsDiscovered,
    ZoneTransferDiscovered, DomainRegistrationDiscovered, MailSecurityDiscovered,
    MxTlsDiscovered, DomainReputationDiscovered.
  - certificates: CertificateDiscovered.
  - infrastructure: IPAddressDiscovered, NetblockDiscovered,
    IPReachabilityObserved, HostOSGuessed (inferred OS family from nmap hints).
  - active service and web: ServiceDiscovered, HttpEndpointDiscovered,
    HttpRedirectObserved, TechnologyFingerprinted, TlsPostureDiscovered,
    WebAssetsDiscovered. A redirect event proves FromURL returned a 3xx response;
    rejected ToURL destinations were not contacted.
  - third-party host and breach intel: CensysHostsDiscovered,
    ShodanHostsDiscovered, NetlasHostsDiscovered, BreachDataDiscovered.
- finding: FindingRaised (a weakness about the target). Carries Confidence
  (confirmed/inferred; a later confirmed report upgrades an inferred one) and a
  KnownExploited flag for CVEs in the bundled CISA-KEV snapshot.
- issue: IssueObserved (a fault in our own scan: out-of-scope, over-budget,
  tripped circuit breaker, or a non-fatal collection error).

`events/events_<Type>.jsonl` holds the same events split by type, without the
envelope wrapper, for quick eyeballing. `events/events.jsonl` (arrival order, all
types) is authoritative, because lineage and the read models fold in order.

## Tool / system events (`tools/tooling.jsonl`)

Operational, per-tool events (search started, query failed, HTTP status error,
rate limited). One flat envelope per line:

```json
{"version":1,"seq":1,"scanID":"...","tool":"crtsh","name":"crtsh: search started","level":"info","phase":"passive","target":"...","at":"...","attrs":{...},"corrID":"..."}
```

- `seq` - monotonic per-scan sequence (ordering, gap detection).
- `tool` - emitting tool.
- `level` - debug | info | warn | error.
- `target` - domain/host/ip/url the event concerns, when known.
- `attrs` - flattened event attributes, including raw response payloads on errors.
- `corrID` - ties together every event of one tool invocation.

`tools/tool_<tool>.log` is the same stream for a single tool as plain text, the
first stop when debugging one provider.

## Audit join (CorrID)

A domain event's `data.ToolCorrID` equals the `corrID` on the tool events of the
call that produced it. So a finding or discovery in `events/events.jsonl` joins
back to the exact provider request/response in `tools/tooling.jsonl`. It is empty
for events not derived from a single tool call (lifecycle, crawler discoveries,
root-level enumeration).

## Analysis and debugging

jq recipes (run from this directory):

```sh
# Domain events by type, most frequent first
jq -r .type events/events.jsonl | sort | uniq -c | sort -rn

# All findings: severity, asset, title
jq -r 'select(.type=="FindingRaised") | .data | "\(.Severity) \(.AssetID) \(.Title)"' events/events.jsonl

# Scan issues (what we failed to collect, and why)
jq -c 'select(.type=="IssueObserved") | .data' events/events.jsonl

# Tool errors across all providers
jq -c 'select(.level=="error")' tools/tooling.jsonl

# Everything one provider did
jq -c 'select(.tool=="crtsh")' tools/tooling.jsonl
```

duckdb recipes (run from this directory; SQL over the same logs, handy for
grouping, sorting, and joins). Mind the two shapes: in `events/events.jsonl` the
event payload is nested under `data` (reach a field as `data.Severity`), while the
per-type `events/events_<Type>.jsonl` splits carry the payload at top level (just
`Severity`). In `tools/tooling.jsonl`, `attrs` is a `MAP(VARCHAR, JSON)`, so index
it as `attrs['query']`.

```sql
-- Domain events by type, most frequent first
SELECT type, count(*) AS n FROM 'events/events.jsonl' GROUP BY type ORDER BY n DESC;

-- All findings: severity, asset, title (envelope log, nested under data)
SELECT data.Severity AS sev, data.AssetID AS asset, data.Title AS title
FROM 'events/events.jsonl' WHERE type='FindingRaised' ORDER BY sev DESC;

-- Same from the split file (no envelope, fields are top level)
SELECT Severity, AssetID, Title FROM 'events/events_FindingRaised.jsonl'
ORDER BY Severity DESC;

-- Scan issues (what we failed to collect, and why)
SELECT data.Source AS src, data.Query AS query, data.Error AS error
FROM 'events/events.jsonl' WHERE type='IssueObserved';

-- Tool errors across all providers, with the flattened attrs payload
SELECT tool, name, attrs FROM 'tools/tooling.jsonl' WHERE level='error';

-- Everything one provider did, by level
SELECT level, count(*) AS n FROM 'tools/tooling.jsonl'
WHERE tool='crtsh' GROUP BY level ORDER BY n DESC;

-- Open services rolled up across hosts (split file, top-level fields)
SELECT Port, Protocol, Service, Product, count(*) AS n
FROM 'events/events_ServiceDiscovered.jsonl' GROUP BY ALL ORDER BY n DESC;
```

Run a recipe straight from the shell with `duckdb -c "<sql>"`, or open an
interactive session with `duckdb` and paste. A bare `'file.jsonl'` in the FROM
clause auto-detects the JSON schema; use `read_json_auto('file.jsonl')` if you
need to pass options.

Join a finding to the provider call that produced it (PowerShell):

```powershell
$cid = jq -r 'select(.type=="FindingRaised") | .data.ToolCorrID' events/events.jsonl | Select-Object -First 1
jq -c --arg c $cid 'select(.corrID==$c)' tools/tooling.jsonl
```

The same join in duckdb (no shell glue; matches `data.ToolCorrID` to `corrID`):

```sql
WITH f AS (
  SELECT data.ToolCorrID AS cid, data.Title AS title FROM 'events/events.jsonl'
  WHERE type='FindingRaised' AND data.ToolCorrID<>'' LIMIT 1
)
SELECT f.title, t.tool, t.name, t.level
FROM 'tools/tooling.jsonl' t JOIN f ON t.corrID=f.cid;
```

Debugging a single tool: read `tools/tool_<tool>.log` for the readable trace, then
filter `tools/tooling.jsonl` on that tool for the structured detail (`attrs`
carries raw payloads on errors).
