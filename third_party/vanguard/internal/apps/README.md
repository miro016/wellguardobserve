# Applications

This folder contains the application-layer wiring behind Vanguard's commands.
It is a navigation folder, not a Go package.

Vanguard's two phases are two binaries on two machines, and this folder is where
that split is wired. Neither stage is implemented here: `collect` and `projections`
are process adaptations of the public `pkg/collect` and `pkg/projections` packages,
and everything they add is what a command line is for - flag parsing, reading the
named files, taking credentials from the environment, choosing a process stream for
progress, turning SIGINT and SIGTERM into a cancelled run, and mapping an error onto
an exit code. The same stage is available to an embedding application without any of
that.

- `collect` is the scan VM's command (`cmd/vanguard-collect`). It reads the
  engagement and profile the operator named and runs one collection over them; the
  library requires a fresh destination for each invocation and owns
  everything a capture records. It links no projection filesystem adapter, so no
  collection code path can write a derived artifact even by mistake; a boundary
  test walks the real import graph to keep it that way.
- `projections` is the analyst host's command (`cmd/vanguard-projections`). Its
  `build` subcommand selects captures and runs one library builder per capture,
  which is the same path an embedding application takes. It also hosts the
  corpus-level commands `diff`, `parity`, and `signals`, which stay here because
  each spans more than one capture and so belongs to no single derived tree. It
  links no collection tool and no orchestration, which is the executable form of "a
  projection contacts nothing".
- `scankit` supplies collection runtime resolution, sink wiring, configuration
  snapshots, manifest transitions, and provenance to `pkg/collect`.

The batch runner is deliberately not here. It starts every scan on a VM, but it
schedules rather than collects and reads collection configuration and persistence
contracts, so it lives in `tools/batch` as a self-contained operator tool
rather than as application wiring for a shipped binary.

Applications may compose collection, persistence, and projection adapters. They
do not own collection algorithms or projection logic.

Orchestration owns current-run targets, scope, provider corroboration, and terminal
planning state. Every report, graph, and decoded packet view is built later, on the
analyst host, from the downloaded collection.
