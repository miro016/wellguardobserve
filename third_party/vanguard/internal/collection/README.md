# Collection

`collection` is Vanguard's write side. It groups the stream contracts, every
package that gathers evidence, and the orchestration that coordinates them. The
folder itself is not a Go package.

## Runtime subphases

Both runtime subphases collect evidence:

- `tools/reconpassive/` queries public records and third-party providers.
- `tools/reconactive/` directly probes approved targets.

The subphases differ in intrusiveness and gating. Their enablement, ordering,
scope, and budgets belong to `config` and `orchestration`.

## Outputs

Collection writes into the exact directory its caller named. Nothing inserts an
enclosing component, so a collection directory is complete and movable on its own,
and a projection is written to a destination of its own. A fresh collection accepts
only a missing or empty destination and deletes nothing. Each invocation writes one
manifest with its own status, phases, configuration snapshots, and health summary.
`persistence` owns that contract; another collection requires another destination.

Collection produces two append-only streams:

1. `events.DomainEvent` records tool-neutral observations about the target.
   `EventMeta` carries scan identity, source, phase, causation, capture time, and
   tool correlation.
2. `tooleventlog.Event` records what a tool did, including attempts, failures,
   retries, limits, and duration.

Together they distinguish "nothing was observed" from "the tool did not
complete". Events are immutable; a correction is another event.

A tool event that proves attempted work was lost also implements
`tooleventlog.HealthEvent` and reports a stable, bounded `HealthProblem`. The
`health` package folds those as they are emitted, so a degraded run says so while
it is still running instead of only in whatever a reader later makes of the logs.

## Boundaries

Tools emit their own operational events and return typed results. They never
construct domain events, publish to a domain-event sink, or persist output.

`orchestration` is the single translator and metadata authority. Pure mappings
live in `orchestration/translate`; the orchestrator owns scheduling, policy, and
causation.

Projection packages consume the streams. No package under `collection/tools`
may depend on a projection. The few deliberate collection-to-projection edges
belong to detector composition and intelligence catalogues and are listed in
`.go-arch-lint.yml`.

## Package map

- `config` - phases, tool settings, scope, and budgets.
- `events` - domain-event vocabulary and metadata.
- `tooleventlog` - operational event vocabulary, sinks, and the folds over a
  persisted stream. It owns the envelope format and no path at all.
- `persistence` - the collection phase's filesystem: the collection directory
  contract and its missing-or-empty destination rule, the manifest, the domain-event
  codec and sink, the config snapshots, and the tool-log streams. It imports no
  projection package.
- `health` - folds the health-bearing tool events of one live run into a single
  bounded assessment.
- `orchestration` - scheduling, policy, translation, and composition.
- `tools/` - passive, active, detection, and validation actors plus shared
  low-level helpers.
