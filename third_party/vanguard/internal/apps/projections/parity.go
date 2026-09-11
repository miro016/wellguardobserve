package projections

import (
	"flag"
	"fmt"
	"os"

	"github.com/velgard-sk/vanguard/internal/projections/persistence"
)

// runParity compares two collection corpus roots according to an explicit manifest.
// With -stdout it prints the Markdown report and writes nothing; otherwise it writes
// capture-parity.md and capture-parity.json into the directory named by -out.
//
// A parity report belongs to a pair of corpora, so neither of them can be asked where
// it goes. There is deliberately no default and no "write it beside one of the
// inputs": the operator names the destination, or asks for stdout.
func runParity(args []string) int {
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	baselineRoot := fs.String("a-root", "", "Baseline corpus root whose child directories are scans")
	candidateRoot := fs.String("b-root", "", "Candidate corpus root whose child directories are scans")
	manifest := fs.String("manifest", "", "JSON capture-parity manifest")
	out := fs.String("out", "", "Directory to write capture-parity.md and capture-parity.json into; required unless -stdout")
	toStdout := fs.Bool("stdout", false, "Print the Markdown report to stdout instead of writing files")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *baselineRoot == "" || *candidateRoot == "" || *manifest == "" {
		fmt.Fprintln(os.Stderr, "Error: -a-root, -b-root, and -manifest are mandatory")
		fs.Usage()
		return 2
	}
	*baselineRoot, *candidateRoot, *out = cleanDirArg(*baselineRoot), cleanDirArg(*candidateRoot), cleanDirArg(*out)
	if (*out == "") != *toStdout {
		fmt.Fprintln(os.Stderr, "Error: exactly one of -out or -stdout is required")
		fs.Usage()
		return 2
	}

	report, err := persistence.BuildParity(*baselineRoot, *candidateRoot, *manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *toStdout {
		fmt.Print(report.Markdown())
		return 0
	}
	written, err := persistence.WriteParity(*out, *baselineRoot, *candidateRoot, &report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("capture parity report written to %s\n", written)
	return 0
}
