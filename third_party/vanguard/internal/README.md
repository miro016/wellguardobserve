# Internal architecture

The `internal` tree is organized around Vanguard's two main phases: collecting
evidence and computing deterministic views from that evidence. It is the whole
implementation: `cmd/` holds two thin executable entry points, and `pkg/` holds
the two public stage packages plus a standalone provider client. Everything here
may change without notice.

```text
internal/
  apps/          executable application wiring
  buildid/       identity of the running binary, shared by every provenance record
  collection/    tools, orchestration, the two event streams, and their filesystem
  projections/   entities, read models, analyzers, renderers, and projection filesystem
  valueobjects/  shared immutable value vocabulary
```

## Collection

`collection` owns every package that gathers evidence, whether the runtime
subphase is passive or active. Tools emit typed results and
operational events; `orchestration` is
the only package that translates results into domain events.

The immutable outputs are the domain-event stream in `collection/events` and
the tool-event stream in `collection/tooleventlog`. See
`collection/README.md` for the package map and collection boundaries.

## Projections

`projections` owns deterministic interpretation of captured streams. The root
package maintains the live inventory and related read models. Its subpackages
build the projection-owned entity model plus findings, facts, attack-surface,
risk, threat, comparison, and tool-health views. `projections/entities` contains
the assets and assessment facets materialized by those folds; collection records
their source observations as events and does not construct these entities.

Pure folds and renderers do no filesystem I/O, and neither do the corpus policy
(`parityreport`) or the page renderers (`factsreport`, `surfacereport`): they return
values and bytes. `projections/persistence` is the one
projection package that opens a collection file or writes a projection file, and it
owns every bucket and file name a projection has.

It reads one collection root and writes one destination root, both named by the
caller. A destination must be missing or empty and may not be, contain, or sit
inside its collection; nothing is deleted to make room, and the projection manifest
is written last, so a destination without one is an unfinished build.

The public `pkg/projections` package is a thin single-run wrapper over that, and
`apps/projections` is only the command line around it, plus the multi-collection
`diff`, `parity`, and `signals` features, which belong to no single build.

Collection detectors compose finding rules, and collection configuration uses
shared intelligence catalogues. Orchestration owns the live state of the current
run directly. Collection tools never depend on projections, and
no collection code path can write a derived artifact - a boundary test walks the
real import graph to keep it that way.

## Batch

The batch runner is not here. It is an operator tool that schedules collections
rather than part of either phase. It reads collection configuration and persistence
contracts while starting collectors as subprocesses. Nothing imports it, so it lives
whole in `tools/batch` - manifest schema, runner, and
entry point in one package. See `tools/README.md`.

## Shared and bridge packages

`valueobjects` and `buildid` are dependency leaves shared across the two phases.
`buildid` is the one place that answers "which build
produced this": the collection manifest, the projection manifest, and the
`ScanEnvironmentRecorded` event all take their identity from it, so one execution
cannot describe itself two ways, and a build nameable by neither a release version
nor a Git commit fails before it collects anything. `apps` is the outer composition
layer that wires commands to the two phases.

## Who writes which directory

Each phase owns its own filesystem, and neither writes the other's.

`collection/persistence` owns a collection directory: the manifest, the domain-event
streams, the configuration snapshots, the tool logs, and the fresh-destination rules
that decide whether a destination may be written at all. The collection's packages
supply the format - `collection/config` parses and validates the operator documents,
`collection/tooleventlog` owns the tool-event envelope and the folds over it - and
neither of them joins a path or opens a file. It imports no projection package, which
its own boundary test enforces.

`projections/persistence` owns a projection directory, reads the collection format
through `collection/persistence`, and never writes into a collection. A config is
operator input rather than an observation, so it keeps its own bucket inside the
collection, but it shares that collection's lifetime because the collection wrote it
and nothing regenerates it - which is what makes a collection directory a complete
projection input on its own.

Nothing inserts an enclosing path component on either side: both directories are
exactly what their caller named. The folders are persistence concerns and do not
define the source package structure.

Folder placement communicates ownership; `.go-arch-lint.yml` remains the
executable authority for allowed dependencies.
