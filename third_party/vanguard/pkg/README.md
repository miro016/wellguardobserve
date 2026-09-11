# pkg/

The packages another Go module may import. Everything else in this repository is
under `internal/` and may change without notice.

- `collect/` - the collection stage as a library: run one collection against an
  engagement and a scan profile, and run the collection-runtime preflight. The
  embeddable form of the `vanguard-collect` command.
- `projections/` - the projection stage as a library: rebuild one collection's
  complete set of artifacts into a destination it names, offline. The embeddable form of
  `vanguard-projections build`.
- `netlas/` - a low-level client for the Netlas provider API. It is a provider
  client, not a Vanguard workflow, and is public because it is useful on its own.

`collect` and `projections` never import each other. A collection directory on disk
is the whole contract between the two stages, which is what lets a collection run
on a scan VM and a projection run on an analyst host with no shared process and no
shared Go type. Each package's `doc.go` states its ownership rules, its provenance
rules, and what it deliberately does not expose.

These APIs are experimental. Pin a module version or a commit.
