package collect

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/velgard-sk/vanguard/internal/apps/buildversion"
	"github.com/velgard-sk/vanguard/pkg/collect"
)

// CollectorBinary is the command name recorded as the collector in every capture
// manifest and ScanEnvironmentRecorded event this front-end writes. It is a
// constant rather than os.Args[0] so a renamed or symlinked executable still
// reports the command it implements.
const CollectorBinary = "vanguard-collect"

// Run parses the command line and dispatches to a subcommand. It is aimed at
// automation: plain-text progress on stdout, no interactive UI, because collection
// runs unattended on a VM.
//
// release is the command's own link-time version, empty for a developer build. It
// is passed in from the command's main package rather than read from a shared
// global, and [buildversion.Resolve] turns it into the one identifier this command
// records as its provenance.
func Run(args []string, release string) int {
	if len(args) == 0 {
		usage()
		return 1
	}
	switch args[0] {
	case "run":
		return runCollect(args[1:], release)
	case "preflight":
		return runPreflight(args[1:], release)
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", args[0])
		usage()
		return 1
	}
}

// usage prints the command surface. It is deliberately short: this binary does two
// things, and everything derived from a capture is rebuilt by the host projections
// binary instead.
func usage() {
	fmt.Fprint(os.Stderr, `vanguard-collect - run a collection on a scan VM

  vanguard-collect run -engagement <yaml> -profile <yaml> -destination <collection-dir>
      Contact targets and providers and write the collected streams and collection
      metadata directly under <collection-dir>. Writes no derived artifacts.
      The destination must be missing or empty, and nothing already there is ever
      deleted or overwritten: collecting again means naming a new destination.

  vanguard-collect preflight -profile <yaml>
      Print the identity this build would collect under, verify the external runtime
      the profile needs, and print what it resolved. Sends no traffic and writes
      nothing.

Rebuild the derived tree from a downloaded collection on the analyst host with
'vanguard-projections build'.
`)
}

// runCollect parses the collection flags and executes one collection run.
func runCollect(args []string, release string) int {
	fs := flag.NewFlagSet("vanguard-collect run", flag.ContinueOnError)
	engagement := fs.String("engagement", "", "Path to the customer engagement file (YAML); supplies the scan root")
	profile := fs.String("profile", "", "Path to the reusable scan profile file (YAML)")
	destination := fs.String("destination", "",
		"Collection directory to write; it is the root of the collection, not a parent of one")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	// The scan root is owned by the engagement file, so all three inputs are
	// mandatory.
	if *destination == "" || *engagement == "" || *profile == "" {
		fmt.Fprintln(os.Stderr, "Error: -engagement, -profile, and -destination are mandatory")
		fs.Usage()
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return report(os.Stderr, ExecuteCollection(ctx, *engagement, *profile, *destination, buildversion.Resolve(release)))
}

// Exit codes this command returns. They exist so a batch runner can tell a run
// that collected everything from one that collected something from one that
// collected nothing it can trust, without parsing text.
const (
	// ExitOK is a completed collection.
	ExitOK = 0
	// ExitError is any failure: a bad configuration, a cancelled run, a broken
	// output stream, or an unwritable capture.
	ExitError = 1
	// ExitDegraded is a completed collection whose capture is missing work a tool
	// attempted and lost. The capture is written and its manifest says degraded; the
	// lost work is picked up by collecting again into a new destination.
	ExitDegraded = 3
)

// report writes the outcome for an operator and returns this command's exit code.
// Degradation gets its own code because it is neither a success nor a failure: the
// capture is sound and worth keeping, and whether that is acceptable is a decision
// the workflow around this command owns.
//
// A run that is degraded and also broken is reported as broken. The two are not
// alternatives - a failed run says nothing reliable about how much it lost - so a
// joined error containing anything ordinary is an ordinary failure.
func report(w io.Writer, err error) int {
	if err == nil {
		return ExitOK
	}
	degraded, only := degradedOnly(err)
	if !only {
		_, _ = fmt.Fprintln(w, "error:", err)
		return ExitError
	}
	summary := degraded.Summary()
	_, _ = fmt.Fprintf(w, "degraded: %d collection problems across %d identities\n",
		summary.Total, len(summary.Problems))
	for _, problem := range summary.Problems {
		where := problem.Tool
		if problem.Component != "" {
			where += "/" + problem.Component
		}
		_, _ = fmt.Fprintf(w, "  %s [%s] x%d\n", problem.Code, where, problem.Count)
	}
	return ExitDegraded
}

// degradedOnly reports whether err is degradation and nothing else, returning the
// degraded error it found. It walks a joined error rather than using errors.As
// alone, because errors.As would happily find a degraded error sitting beside a
// persistence failure and let the command claim the capture is merely incomplete.
func degradedOnly(err error) (*collect.DegradedError, bool) {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var found *collect.DegradedError
		for _, sub := range joined.Unwrap() {
			degraded, only := degradedOnly(sub)
			if !only {
				return nil, false
			}
			if found == nil {
				found = degraded
			}
		}
		return found, found != nil
	}
	var degraded *collect.DegradedError
	if errors.As(err, &degraded) {
		return degraded, true
	}
	return nil, false
}

// runPreflight prints this build's identity, verifies the external runtime a
// profile needs, and prints what it resolved. It writes no capture directory,
// installs nothing, and never contacts an engagement target. Profiles without UDP
// enabled send no probe traffic; an enabled UDP pass adds one bounded nmap
// capability probe against 127.0.0.1:53.
//
// The identity it reports is this command's own: the version comes from the
// command's link-time value through the same construction a collection run uses,
// and the library only echoes it back. A build that resolves to nothing fails here,
// the same check a collection performs before it opens a sink, so a deploy that
// would produce a collector unable to name itself learns it at deploy time rather
// than after a scan has already spent an hour contacting targets.
func runPreflight(args []string, release string) int {
	fs := flag.NewFlagSet("vanguard-collect preflight", flag.ContinueOnError)
	profile := fs.String("profile", "", "Path to the scan profile file (YAML)")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *profile == "" {
		fmt.Fprintln(os.Stderr, "Error: -profile is mandatory for preflight")
		fs.Usage()
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	profileYAML, err := os.ReadFile(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	report, err := collect.Preflight(ctx, collect.PreflightOptions{
		ProfileYAML:     profileYAML,
		ApplicationName: CollectorBinary,
		Version:         buildversion.Resolve(release),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Print(report.String())
	return 0
}

// ExecuteCollection reads the engagement and scan profile the operator named and
// runs one collection over them. The two files are the command's only contribution:
// the stage itself is the public collection library (pkg/collect), which owns
// everything a collection records.
//
// Everything this function adds is a command-line concern - reading the named files,
// taking the API keys from the environment, and sending progress to stdout for the
// batch runner to capture - so the same collection is available to an embedding
// application without a file, an environment variable, or a process stream.
//
// version is the identifier this command records as its provenance, already
// constructed by [buildversion.Resolve]. An empty one is refused by the library
// before anything is contacted, which is what keeps an unattributable collection from
// being written.
func ExecuteCollection(ctx context.Context, engagementPath, profilePath, destinationDir, version string) error {
	engagementYAML, err := os.ReadFile(engagementPath)
	if err != nil {
		return fmt.Errorf("read engagement %s: %w", engagementPath, err)
	}
	profileYAML, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("read profile %s: %w", profilePath, err)
	}
	collector, err := collect.New(collect.Options{
		EngagementYAML:  engagementYAML,
		ProfileYAML:     profileYAML,
		Credentials:     collect.CredentialsFromEnv(),
		DestinationDir:  destinationDir,
		ApplicationName: CollectorBinary,
		Version:         version,
		Progress:        os.Stdout,
	})
	if err != nil {
		return err
	}
	return collector.Run(ctx)
}
