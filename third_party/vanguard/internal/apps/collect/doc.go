// Package collect provides the command-line front end for the collection phase,
// and the only one: Vanguard collects from the managed VMs described in
// taskfile/vm.config.ps1, where nothing is interactive. It prints plain-text
// progress to stdout, which the batch runner persists as that engagement's log file
// beside the batch state.
//
// # A command-line wrapper, and nothing more
//
// The collection itself is the public collection stage (pkg/collect). This package
// contributes only what a command line is for: it reads the two configuration files
// an operator named, takes the provider API keys from the environment, points
// progress at stdout, turns SIGINT and SIGTERM into a cancellation context, and maps
// an error onto an exit code (0 complete, 3 degraded, 1 broken). Everything a
// collection records - the destination decision, collector provenance, config
// snapshots, sink and tool lifecycle, and the terminal manifest status - belongs to
// that package and is documented there.
//
// The split is what makes the stage embeddable. An application that holds its
// engagement in a database and its secrets in a vault runs the same collection this
// command runs, without a temporary file, an environment variable, or output on a
// process stream it did not ask for.
//
// # What a collection run does, and what it deliberately does not
//
// A run contacts targets and providers and writes exactly two kinds of thing: the
// immutable source streams, and the collection metadata that makes
// the directory readable and attributable. It renders no report, no entity
// snapshot, no graph, no data-quality or tool-health result, and no decoded
// network-audit view. It writes no derived artifact at all.
//
// That is the point of the split. Derived artifacts change whenever a projection
// rule changes; source material does not. Keeping them apart means a projection can
// be re-evaluated against a downloaded capture as often as an analyst likes, without
// another remote scan, and means a scan VM needs no projector installed. An operator
// rebuilds the derived tree locally with the host projections binary.
//
// # Commands
//
//	vanguard-collect run -engagement <yaml> -profile <yaml> -destination <collection-dir>
//	vanguard-collect preflight -profile <yaml>
//
// [Run] dispatches on the subcommand. "run" reads both configuration files and hands
// them to [ExecuteCollection], which runs one collection and prints lifecycle
// transitions, notable discoveries, and a final summary as they happen, suitable for
// log capture in an automated pipeline. The scan root comes from the engagement
// (scope.domains.roots), so there is no separate -domain argument. The destination
// must be missing or empty: one directory holds one collection, and collecting again
// means naming another one.
//
// "preflight" reports the identity this build would collect under and runs the same
// external-runtime checks a run performs at startup - the nmap binary and its forced
// NSE scripts, the interpreter, the pinned SSLyze, and the resolved CA bundle. It
// writes nothing, installs nothing, and never contacts an engagement target. Profiles
// without UDP enabled send no probe traffic; an enabled UDP pass adds one bounded
// nmap capability probe against 127.0.0.1:53. A build whose version resolves to
// nothing fails there, so a deploy that would produce a collector unable to name
// itself learns it at deploy time rather than after a scan has already spent an hour
// contacting targets.
//
// # Which build collected
//
// The version a capture records is this command's own, not something the collection
// library resolves. cmd/vanguard-collect owns a link-time variable, [Run] receives it
// as an ordinary argument, and internal/apps/buildversion turns it - or the Go build
// information behind it - into one identifier that goes into collect.Options.Version.
// Preflight and a real run use the same construction, so the identity a deployment
// prints is the identity its captures will carry.
//
// That policy lives here because it is a command-line decision. An application that
// embeds pkg/collect has its own releases and its own idea of what identifies a
// build, and supplies the finished string itself.
package collect
