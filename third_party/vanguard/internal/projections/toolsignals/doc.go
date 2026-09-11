// Package toolsignals is a pure, deterministic analyzer over the persisted
// tool-event logs of one or more finished scans. It detects issues with the
// captures themselves - the tool/log health, not the target's security posture -
// and turns the ad-hoc capture-quality checks an engineer runs by hand into a
// reproducible signal set.
//
// # What it judges
//
// Each detector is a pure predicate over one scan's folded tool-event state. A
// detector never does I/O, never reads the clock or network, and never looks at
// another scan, so it is trivially testable on a hand-built fixture. The catalogue
// (catalogue.go) is fixed and grounded: every signal id corresponds to a concrete
// class of defect seen in real captures (a provider log carrying no target, a
// double-queried provider racing itself into a self-inflicted rate-limit, a
// corrupt or gap-riddled log).
//
// # The UDP pass
//
// One family (udp/*, udp.go) is protocol-aware, because the UDP portscan pass is
// the one call whose honest result reads like a broken one. It reports a verdict
// for every port it probed and, on a healthy host, none of those verdicts is
// "open": a zero-service pass covered its work and found nothing listening, which
// is coverage, not failure. So the UDP detectors never judge a pass by what it
// found. They judge whether its own record of itself is consistent: that a started
// pass settled exactly once, that the per-state port counts reconcile with what it
// says it accounted for, that a partial result is accompanied by the error naming
// what it lost, and that a pass which failed does not also claim full coverage.
//
// The sequential TCP and UDP passes on one host are two calls on purpose - separate
// correlation ids, separate targets - so the duplicate-concurrent-query detector
// sees two deliberate calls rather than one tool racing itself.
//
// # The two stages
//
//   - Per-scan fold: Fold streams one scan's tool-event log (an io.Reader over the
//     canonical tooling.jsonl) into a ScanData - the extra per-envelope aggregates
//     the detectors need (target attribution per tool, correlated call spans per
//     (tool,target), sequence and schema integrity, call-boundary correlation),
//     plus the operational rollup reused from internal/collection/tooleventlog attached
//     by the caller. The fold is bounded memory: raw envelopes are folded and
//     dropped.
//   - Cross-scan aggregation: Build runs the detector registry over every scan's
//     ScanData, groups identical findings by (id, tool, target), and emits corpus
//     Signals. A group seen in one scan is a one-off (scope "scan"); a group seen in
//     a strong majority of scans is systemic (scope "corpus") and has its severity
//     escalated one step, because a defect in every scan is worse than a flake in
//     one. It also compares metrics that carry a value per scan (target-attribution
//     ratio, rate-limit count, failed-call rate) along the corpus order and raises a
//     trend signal when one regresses - a monotonic worsening or a good-to-bad
//     threshold crossing - which is how a value swinging across reruns (crtsh
//     attribution 100%->0%) is caught.
//
// # Determinism
//
// Given the same corpus and the same Config, Build produces identical bytes: every
// number is folded from the persisted stream, every threshold and curated list
// comes from Config, and every ordering is an explicit sort over data-derived keys.
// No map iteration, wall-clock, or filesystem-enumeration order reaches the output.
//
// # Boundary
//
// This package is pure: the filesystem discovery of scan directories, the opening
// of each tooling.jsonl, and the writing of the report artifacts live one layer up
// in internal/projections/persistence, the same way internal/projections/dataquality
// stays free of its filesystem adapter.
package toolsignals
