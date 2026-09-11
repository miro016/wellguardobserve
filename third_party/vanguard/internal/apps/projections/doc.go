// Package projections implements the vanguard-projections command: the offline
// composition root of the projection phase.
//
// It runs on the analyst's host, against collections downloaded from a scan VM, and
// it exists so that changing projection code never requires another scan. Every input
// it reads comes from a collection directory; it contacts no target and no provider,
// starts no collection tool, and imports neither the tool packages nor the
// orchestrator. A build can therefore be repeated as often as a projection rule
// changes, on a machine with the network switched off.
//
// # Commands
//
//	vanguard-projections build -collection <dir> -destination <dir>
//	vanguard-projections build -collection-root <dir> -destination-root <dir>
//	vanguard-projections diff -a <baseline> -b <candidate> (-out <dir> | -stdout)
//	vanguard-projections parity -a-root <a> -b-root <b> -manifest <file> [-out <dir>]
//	vanguard-projections signals (-root <dir> | -scans <a,b,...>) [-out <dir>] [-stdout]
//
// [Run] dispatches on the subcommand. "build" is the single regeneration path for one
// collection's artifacts; there are deliberately no per-artifact commands, since a
// destination assembled one artifact at a time can end up describing several
// different versions of the projection code at once. "diff", "parity", and "signals"
// remain separate because each spans more than one collection and so belongs to no
// single build.
//
// # Both sides are always named
//
// Every mode names its input and its output. A command that derived a destination
// from an input would be choosing which local tree gets overwritten on the operator's
// behalf, and the first time that choice is wrong the evidence it overwrote is
// already gone. In corpus mode each collection under -collection-root is written to a
// child of -destination-root with the same name: that mapping is this command's
// iteration policy, not a layout anything persists, and once resolved the pairs are
// ordinary independent directories.
//
// A destination must be missing or empty, and it may not be, contain, or sit inside
// its collection. Those rules belong to the projection package; this command simply
// passes the two paths through and reports what it refused.
//
// # Which build projected
//
// The version a projection manifest records is this command's own, not something the
// projection library resolves. cmd/vanguard-projections owns a link-time variable,
// [Run] receives it as an ordinary argument, and internal/apps/buildversion turns it
// - or the Go build information behind it - into one identifier that goes into
// projections.Options.Version. It is resolved once per corpus build, so every
// collection in one run is attributed to the same projector, and an empty result is
// recorded rather than refused: an offline rebuild invents no evidence. Only "build"
// takes the value; "diff", "parity", and "signals" write no stage provenance.
//
// That policy lives here because it is a command-line decision. An application that
// embeds pkg/projections has its own releases and supplies the finished string itself.
//
// # What build produces
//
// One build writes every artifact a collection determines: the entity snapshots, the
// operator report and its issue, temporal-anomaly, and threat-scenario ledgers, the
// data-quality report, the tool-health signals, the facts graph, the contracted
// attack surface, the decoded network-audit summary and raw log, the generated
// README, and finally the projection manifest.
//
// The build itself is not implemented here. It belongs to the public projection
// package, github.com/velgard-sk/vanguard/pkg/projections, and this command runs it
// the same way an embedding application does: one builder per collection, named by
// this command's own binary name so the projection manifest records who projected.
// That keeps one implementation for both callers, and makes the command a witness
// that the public package is complete enough to project a collection on its own.
//
// # What stays here
//
// Everything that is a command line rather than a build: flag parsing, the two
// mutually exclusive modes, collection discovery under a corpus root, the
// per-collection result lines and exit codes, and turning an interrupt into a
// cancelled build rather than a killed one. A corpus build reports each collection on
// its own line and continues past a broken one, because one bad collection must not
// cost an analyst every other rebuild; an interrupt does stop the corpus, because
// that is what the operator asked for.
//
// The multi-collection features stay here too. "diff", "parity", and "signals" each
// span more than one collection and so belong to no single build. They are
// deliberately absent from the public package's API in this cut rather than pending
// there: an embedding application that wants a corpus comparison composes it from
// per-collection builds and its own iteration policy, which is the decision this
// command has already made for an analyst at a terminal.
//
// Cancellation is installed where it can be acted on. "build" turns SIGINT and
// SIGTERM into a cancelled build, which stops the corpus and leaves every finished
// destination intact; the three analyzers fold files that are already on disk in one
// short pass and take no context, so an interrupt ends them the way it ends any other
// short command.
//
// # Nothing in a collection is ever written
//
// A collection is immutable input: a projection that could edit its own source would
// make a rebuild unrepeatable, and would put the one irreplaceable half of the
// evidence at risk of a projection bug. That is why a destination that overlaps its
// collection is refused rather than accommodated, and why a build that fails leaves
// its destination without the manifest that would have claimed it complete.
package projections
