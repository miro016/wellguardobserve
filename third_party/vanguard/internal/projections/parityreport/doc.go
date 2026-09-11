// Package parityreport compares two collection corpora according to a checked-in
// scenario manifest. It is the pure corpus policy above scandiff: each already-loaded
// baseline/candidate pair carries a semantic diff and a structural audit, which are
// checked against explicit phase, lifecycle, provider-gate, and coverage expectations.
//
// [ParseManifest] accepts bytes and [Build] accepts values. Both return values and
// perform no filesystem I/O. Loading collections and the manifest, reconciling the
// canonical streams with their per-type splits, rendering the report, and choosing
// where it lands belong to internal/projections/persistence.
//
// The per-pair diff and split reconciliation arrive in [ScenarioInput]. Which files
// contain those values is not a decision this policy makes, keeping the dependency
// arrow one-way from projection persistence to this package.
//
// Provider failures configured in the manifest make a scenario inconclusive instead
// of passing or failing content checks; stream integrity, root, phase, and
// required-event checks still run and can fail.
//
// This package runs no scanners, opens no files, and contacts no providers. The same
// inputs always produce the same result.
package parityreport
