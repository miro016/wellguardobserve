# Vanguard source snapshot

This directory contains the runtime source needed to build `vanguard-collect` and
`vanguard-projections` for Wellguard Observe.

- Upstream: `https://github.com/Velgard-SK/vanguard`
- Pinned commit: `d9e2b785b973bd5a44af8ec86766808542ae8cb6`
- Imported: 2026-09-12

The snapshot is used instead of a private Git submodule so unattended container
builds do not require a second repository credential. Test files and operator-only
material are omitted; upstream production source, embedded data, `go.mod`, and
`go.sum` are retained without modification.

To update it, review the upstream changes, replace the snapshot, update the pinned
commit above and in `agent/tool-catalog.ts`, then run both Vanguard's upstream test
suite and Wellguard's complete check before deployment.
