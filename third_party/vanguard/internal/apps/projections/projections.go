package projections

import (
	"fmt"
	"os"
	"path/filepath"
)

// ProjectorBinary is the command name recorded as the projector in every projection
// manifest this front-end writes. It is a constant rather than os.Args[0] so a
// renamed or symlinked executable still reports the command it implements.
const ProjectorBinary = "vanguard-projections"

// Exit codes. 0 is success, 1 is an operational error, 2 is a usage error, and 3 is
// reserved for the signals gate so a CI capture gate can tell "the tool broke" from
// "the tool found a gating problem".
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitGateHit = 3
)

// cleanDirArg normalises a directory typed on the command line. Shell completion
// hands directories back with a trailing separator, and on Windows a path in that
// shape is rejected by the filesystem call behind os.Stat, so an operator who
// tab-completed the capture would be told a perfectly good capture is not readable.
// Cleaning the argument keeps the completed form working.
func cleanDirArg(v string) string {
	if v == "" {
		return v
	}
	return filepath.Clean(v)
}

// Run dispatches the projection subcommands. The first argument selects the
// feature; the remainder is that feature's own flag set. With no arguments it
// prints usage to stderr and returns 2; an explicit help request returns 0.
//
// release is the command's own link-time version, empty for a developer build. It
// is passed in from the command's main package rather than read from a shared
// global, and [buildversion.Resolve] turns it into the identifier a build records
// as its projector. Only the build subcommand writes provenance, so only it takes
// the value.
func Run(args []string, release string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "build":
		return runBuild(args[1:], release)
	case "diff":
		return runDiff(args[1:])
	case "parity":
		return runParity(args[1:])
	case "signals":
		return runSignals(args[1:])
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", args[0])
		usage()
		return exitUsage
	}
}

// usage prints the command synopsis to stderr.
func usage() {
	fmt.Fprint(os.Stderr, `vanguard-projections - rebuild derived views from downloaded collections, offline

Usage:
  vanguard-projections build   -collection <dir> -destination <dir>
  vanguard-projections build   -collection-root <dir> -destination-root <dir>
  vanguard-projections diff    -a <baselineDir> -b <candidateDir> (-out <dir> | -stdout)
  vanguard-projections parity  -a-root <baselineCorpus> -b-root <candidateCorpus> -manifest <file> (-out <dir> | -stdout)
  vanguard-projections signals -root <dir> (-out <dir> | -stdout) [-min-severity L] [-fail-on L]
  vanguard-projections signals -scans <a,b,...> (-out <dir> | -stdout) [-min-severity L] [-fail-on L]
  vanguard-projections help

Subcommands:
  build    Write one collection's complete set of artifacts into a destination you
           name. This is the only regeneration path: there are no per-artifact
           commands. In corpus mode each collection under -collection-root is written
           to a child of -destination-root with the same name.
  diff     Comparison report between two collections.
  parity   Manifest-driven comparison of two collection corpora.
  signals  Tool-event health signals across one or more collections.

Every subcommand is offline: no target, provider, or VM is contacted, and nothing in
a collection is ever written. Every destination must be missing or empty, and none
may sit inside a collection.
`)
}
