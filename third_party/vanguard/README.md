# Vanguard

Vanguard is a focused reconnaissance and risk-evaluation tool for a security
analyst working one customer at a time. A scan starts from one root domain,
collects evidence about the related external surface, and computes replayable
views for risk and threat analysis. It favors depth, provenance, and
explainability over breadth.

## Two stages, one directory between them

```text
targets and providers
        |
        v
  collection  ---->  collection directory  ---->  projection
  (scan VM)          the whole contract           (analyst host)
  sends traffic      complete and movable         offline, writes elsewhere
```

The collection directory is exactly the directory its caller named: Vanguard adds no
enclosing component, so the manifest, the event streams, the config snapshots, and
the tool logs all sit directly below it. It is complete and movable on its own, and a
projection is written to a destination of its own rather than inside it.

**Collection** contacts targets and providers under one engagement and writes only
what it captured: the immutable event streams, the configuration snapshots the run
used, and a manifest recording that invocation's identity, phases, status, and
health. Every invocation requires a missing or empty destination. It
renders no report at all.

The POC's main entry point is `vm:batch`: a set of independent engagement/profile
jobs, collected serially under a new launch root. Each job produces one collection.
Future demo Web UI, Azure Storage export, and optional cache tools belong to
extensions around this contract.

**Projection** folds those streams back out into inventory, findings, risk, threat
scenarios, validation results, the facts graph, and the contracted attack surface.
It contacts nothing, so it can be re-run as often as a projection rule changes,
years after the scan, on a machine with the network switched off.

One honest exception: detection rules still run live during collection, which
persists each finding as an event. Re-projecting an old collection therefore replays
the findings that collection recorded - it does not re-evaluate a changed detection
rule against it. A rule change reaches an existing collection only by re-running
collection. Moving detector execution into the projection stage would remove the
exception; until then, treat findings in an old projection as the verdict of
the build that collected it.

Nothing is handed between them in memory. The collection directory on disk is the
entire contract, which is why the two stages can run on two machines, days apart,
and why either one can be used on its own.

## Core ideas

- **Evidence first.** A scan's output is what the tools observed and what the tools
  did, recorded as two append-only streams. Everything an analyst reads is derived
  from them and can be rebuilt from them.
- **Deterministic projection.** The same collection yields the same artifacts. A
  build writes into a destination that must be missing or empty, so a projection is
  never a mixture of two rule versions; nothing is deleted to make room, because
  choosing which bytes are disposable belongs to whoever owns them.
- **Provenance.** Every collection and every projection records the build that
  produced it, and every observation records the tool invocation it came from. A
  collection whose build cannot be named refuses to start.
- **Scope is a hard boundary.** The engagement declares excluded domains and
  excluded IP ranges, and no target-facing connection may reach them - not a scan,
  a handshake, a redirect, or a provider preflight. An
  exclusion beats an include, a prior approval, and a provider corroboration; a
  denial is auditable evidence in its own right. Passive discovery still records
  what it saw. See [`configs/README.md`](configs/README.md).
- **Authorized by configuration.** Scope, budgets, and the exceptional
  authorizations are declared per engagement and enforced by every active tool. The
  reusable scan profile decides how, never who or where.

## Using it

- [`docs/cli.md`](docs/cli.md) - the command line: running collections on a scan
  VM, batching them, and building, comparing, and health-checking projections
  locally.
- [`docs/library.md`](docs/library.md) - the Go packages `pkg/collect` and
  `pkg/projections`, for embedding either stage in another application.

## Where things are

- [`internal/README.md`](internal/README.md) - package-level architecture and the
  collection/projection boundary. Design decisions live in each package's `doc.go`;
  `.go-arch-lint.yml` is the executable authority for package relationships.
- [`tools/README.md`](tools/README.md) - operator tools that support the tasks but
  are not shipped binaries.
- [`configs/README.md`](configs/README.md) - engagement and scan-profile reference.
- [`docs/README.md`](docs/README.md) - maintained product and engineering
  documentation.
- [`docs/backlog/README.md`](docs/backlog/README.md) - proposals that are not
  confirmed defects.
- [`.todo`](.todo) - known unfinished work.

## Conventions

- Prefer new behavior as events and deterministic projections over the existing
  streams; reuse an existing event before adding one.
- Keep tools independent of domain events, projections, and persistence.
- Keep the orchestrator as the single tool-result translator.
- Keep pure projection logic separate from filesystem wiring.
- Keep changes simple and incremental.
