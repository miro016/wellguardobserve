package projections

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/velgard-sk/vanguard/internal/apps/buildversion"
	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/pkg/projections"
)

// collectionFlag collects repeatable -collection values in argument order.
type collectionFlag []string

func (c *collectionFlag) String() string { return fmt.Sprint(*c) }

func (c *collectionFlag) Set(v string) error {
	if v == "" {
		return errors.New("a collection directory may not be empty")
	}
	*c = append(*c, cleanDirArg(v))
	return nil
}

// job is one collection and the exact destination its artifacts go into. The pairing
// is resolved once, up front, so the build loop never derives an output path from an
// input path.
type job struct {
	collection  string
	destination string
}

// runBuild parses the build flags and builds each selected collection into the
// destination the operator named for it. The two modes are mutually exclusive and
// each names both sides: one collection with its destination, or a collection root
// with a destination root whose children are mapped by name.
//
// The build itself belongs to the public projection package; what stays here is the
// command line around it: flag parsing, collection discovery, the per-collection
// report, the exit code, and the interrupt handling that turns Ctrl-C into a
// cancelled build rather than a killed one.
func runBuild(args []string, release string) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	var collections collectionFlag
	fs.Var(&collections, "collection", "Collection directory to project; repeatable")
	destination := fs.String("destination", "", "Directory the artifacts are written into; required with -collection")
	root := fs.String("collection-root", "", "Directory whose immediate subdirectories are collections")
	destinationRoot := fs.String("destination-root", "", "Directory each collection's artifacts are written under, by that collection's own name")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	jobs, code := planJobs(collections, cleanDirArg(*destination), cleanDirArg(*root), cleanDirArg(*destinationRoot), fs)
	if code != exitOK {
		return code
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Resolved once, so every collection in a corpus build is attributed to the same
	// projector even if the build spans a long run.
	version := buildversion.Resolve(release)

	// Each collection is built in turn and reported on its own line, so a corpus build
	// says exactly which ones were written and which failed. A failure does not stop
	// the others: one broken collection in a corpus must not cost an analyst every
	// other rebuild. An interrupt does stop them, because the operator asked for that
	// rather than for the corpus to be judged.
	failed := 0
	for _, j := range jobs {
		if err := buildOne(ctx, j, version); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			failed++
			if ctx.Err() != nil {
				break
			}
			continue
		}
		fmt.Printf("projected %s\n", j.destination)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d collection(s) failed to project\n", failed, len(jobs))
		return exitError
	}
	return exitOK
}

// planJobs resolves the flags into the exact collection/destination pairs this run
// will build, or reports why it cannot. Both modes require both sides: an operator
// who named only an input has not said where the output goes, and this command will
// not decide that for them.
//
// In corpus mode each collection is mapped to a child of the destination root with
// the same name. That is this application's iteration policy rather than a layout
// anything persists: once resolved, the pairs are ordinary independent directories.
func planJobs(collections []string, destination, root, destinationRoot string, fs *flag.FlagSet) (jobs []job, exit int) {
	single := len(collections) > 0
	corpus := root != "" || destinationRoot != ""
	if single == corpus {
		fmt.Fprintln(os.Stderr, "Error: use either -collection with -destination, or -collection-root with -destination-root")
		fs.Usage()
		return nil, exitUsage
	}

	if single {
		if destination == "" {
			fmt.Fprintln(os.Stderr, "Error: -destination is required with -collection")
			fs.Usage()
			return nil, exitUsage
		}
		if len(collections) > 1 {
			fmt.Fprintln(os.Stderr, "Error: -destination takes one collection; use -collection-root and -destination-root for several")
			fs.Usage()
			return nil, exitUsage
		}
		return []job{{collection: collections[0], destination: destination}}, exitOK
	}

	if root == "" || destinationRoot == "" {
		fmt.Fprintln(os.Stderr, "Error: -collection-root and -destination-root are required together")
		fs.Usage()
		return nil, exitUsage
	}
	dirs, err := discoverCollections(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return nil, exitError
	}
	if len(dirs) == 0 {
		fmt.Fprintf(os.Stderr, "error: no directory under %s holds a collection manifest\n", root)
		return nil, exitError
	}
	jobs = make([]job, 0, len(dirs))
	for _, dir := range dirs {
		jobs = append(jobs, job{collection: dir, destination: filepath.Join(destinationRoot, filepath.Base(dir))})
	}
	return jobs, exitOK
}

// buildOne builds one collection through the public projection package, which is the
// same path an embedding application takes. The projector recorded in the manifest
// is this command, named by a constant rather than by os.Args[0], and identified by
// the version its caller resolved once for the whole corpus build.
//
// An empty version is not an error here. A rebuild folds material the collection
// already holds, so a projector built by "go run" - which stamps nothing - records
// itself as unidentified rather than refusing an analyst their report. Demanding an
// identified projector is an operator-layer policy instead: the routine rebuild path
// links a local git identity in and then refuses a manifest that names no build,
// while a direct invocation stays available for a rebuild worth more than its
// provenance.
func buildOne(ctx context.Context, j job, version string) error {
	builder, err := projections.New(projections.Options{
		CollectionDir:   j.collection,
		DestinationDir:  j.destination,
		ApplicationName: ProjectorBinary,
		Version:         version,
	})
	if err != nil {
		return err
	}
	return builder.Run(ctx)
}

// discoverCollections returns the immediate subdirectories of root that hold a
// collection manifest, in lexical order. Ordering is by name rather than by
// filesystem enumeration so a corpus build is reproducible and its output diffable.
//
// A subdirectory without a manifest is skipped silently: a corpus root routinely
// holds notes, exports, and half-downloaded scratch directories, and refusing to
// build the real collections because of one of them would be unhelpful.
func discoverCollections(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read collection root %s: %w", root, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		// A malformed manifest still counts as a collection: the per-collection build
		// reports exactly what is wrong with it, which is more useful than skipping it
		// silently.
		if _, existed, _ := collection.LoadManifest(dir); !existed {
			continue
		}
		out = append(out, dir)
	}
	sort.Strings(out)
	return out, nil
}
