package projections

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/velgard-sk/vanguard/internal/projections/persistence"
	"github.com/velgard-sk/vanguard/internal/projections/toolsignals"
)

// Exit codes for the signals subcommand. They extend datainsights.Run's scheme (0
// success, 1 operational error, 2 usage error) with a distinct gate-breach code so a
// CI capture gate can tell "the tool broke" from "the tool found a gating problem".
const (
	signalsExitOK      = 0
	signalsExitError   = 1
	signalsExitUsage   = 2
	signalsExitGateHit = 3
)

// runSignals parses the signals flags and produces the multi-collection tool-event
// signal report. With -stdout it prints the Markdown report and writes nothing;
// otherwise it writes tools-health-signals.md and tools-health-signals.json into the
// directory named by -out. With -fail-on it gates: exit 3 when a signal at or above
// the gate was found.
//
// A corpus report belongs to every collection it read and to none of them, so -out is
// named by the operator rather than defaulted into an input: writing it back into the
// corpus it summarises would make the next run read its own previous output.
func runSignals(args []string) int {
	fs := flag.NewFlagSet("signals", flag.ContinueOnError)
	root := fs.String("root", "", "Corpus root whose immediate subdirectories are collections")
	scansCSV := fs.String("scans", "", "Comma-separated explicit list of collection directories (argument order preserved)")
	out := fs.String("out", "", "Directory to write tools-health-signals.md and .json into; required unless -stdout")
	toStdout := fs.Bool("stdout", false, "Print the Markdown report to stdout instead of writing files")
	minSeverity := fs.String("min-severity", "info", "Drop signals below this level from both outputs: high|medium|low|info")
	configPath := fs.String("config", "", "Override the baked-in detector config with a JSON file")
	failOn := fs.String("fail-on", "", "CI gate: exit 3 when a signal at or above this level is found: high|medium|low|info")

	if err := fs.Parse(args); err != nil {
		return signalsExitUsage
	}

	*root, *out = cleanDirArg(*root), cleanDirArg(*out)
	scans := splitScans(*scansCSV)
	if err := validateSignals(*root, scans, *out, *toStdout, *minSeverity, *failOn); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fs.Usage()
		return signalsExitUsage
	}

	report, err := persistence.BuildSignals(persistence.SignalsInputs{
		Root: *root, Scans: scans, MinSeverity: *minSeverity, ConfigPath: *configPath,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return signalsExitError
	}

	if *toStdout {
		fmt.Print(report.Markdown())
	} else {
		sources := scans
		if *root != "" {
			sources = []string{*root}
		}
		written, err := persistence.WriteCorpusSignals(*out, sources, &report)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return signalsExitError
		}
		fmt.Printf("signals report written to %s\n", written)
	}

	if report.GateBreached(toolsignals.Severity(*failOn)) {
		fmt.Fprintf(os.Stderr, "gate breach: a signal at or above %q was found (top severity %q)\n",
			*failOn, report.Corpus.TopSeverity)
		return signalsExitGateHit
	}
	return signalsExitOK
}

// validateSignals enforces the mutually-exclusive input modes, the severity ranges,
// and the mutually-exclusive output modes, failing fast before any I/O.
func validateSignals(root string, scans []string, out string, toStdout bool, minSeverity, failOn string) error {
	if (root == "") == (len(scans) == 0) {
		return fmt.Errorf("exactly one of -root or -scans is required")
	}
	if _, err := toolsignals.ParseSeverity(minSeverity, false); err != nil {
		return fmt.Errorf("-min-severity: %w", err)
	}
	if _, err := toolsignals.ParseSeverity(failOn, true); err != nil {
		return fmt.Errorf("-fail-on: %w", err)
	}
	if (out == "") != toStdout {
		return fmt.Errorf("exactly one of -out or -stdout is required")
	}
	return nil
}

// splitScans parses the comma-separated -scans value into a trimmed, non-empty list.
func splitScans(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, cleanDirArg(t))
		}
	}
	return out
}
