package projections

import (
	"flag"
	"fmt"
	"os"

	"github.com/velgard-sk/vanguard/internal/projections/persistence"
)

// runDiff parses the diff flags and produces the comparison between two collections.
// With -stdout it prints the Markdown summary and writes nothing; otherwise it writes
// diff.md and diff.json into the directory named by -out.
//
// A diff belongs to a pair of collections, so no single collection can be asked where
// it goes. There is deliberately no default and no "write it beside one of the
// inputs": the operator names the destination, or asks for stdout.
func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	baseline := fs.String("a", "", "Baseline collection directory (the 'before' / reference)")
	candidate := fs.String("b", "", "Candidate collection directory (the 'after' / inspected)")
	out := fs.String("out", "", "Directory to write the diff into; required unless -stdout")
	toStdout := fs.Bool("stdout", false, "Print the Markdown summary to stdout instead of writing files")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *baseline == "" || *candidate == "" {
		fmt.Fprintln(os.Stderr, "Error: -a and -b are mandatory")
		fs.Usage()
		return 1
	}
	*baseline, *candidate, *out = cleanDirArg(*baseline), cleanDirArg(*candidate), cleanDirArg(*out)
	if (*out == "") != *toStdout {
		fmt.Fprintln(os.Stderr, "Error: exactly one of -out or -stdout is required")
		fs.Usage()
		return 1
	}

	report, err := persistence.BuildDiff(*baseline, *candidate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *toStdout {
		fmt.Print(report.Markdown())
		return 0
	}
	written, err := persistence.WriteDiff(*out, *baseline, *candidate, &report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("scan diff written to %s\n", written)
	return 0
}
