package persistence

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/velgard-sk/vanguard/internal/projections/attacksurface"
	"github.com/velgard-sk/vanguard/internal/projections/dataquality"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
	"github.com/velgard-sk/vanguard/internal/projections/factsreport"
	"github.com/velgard-sk/vanguard/internal/projections/parityreport"
	"github.com/velgard-sk/vanguard/internal/projections/scandiff"
	"github.com/velgard-sk/vanguard/internal/projections/surfacereport"
	"github.com/velgard-sk/vanguard/internal/projections/toolsignals"
)

// The projection's buckets and file names. Every one of them lives here, in the one
// package that writes them: an adapter that also knew a file name would be a second
// authority on where an artifact lands, and the first rename would leave a reader
// looking for a file nobody writes any more.
//
// A caller supplies the destination root and nothing else. There is no exported path
// helper, because a caller that rebuilt a path would become that second authority by
// another route.
const (
	// entitiesBucket holds the folded read-model snapshots. It is named for its
	// contents rather than for the projection machinery that fills it.
	entitiesBucket = "entities"
	// reportsBucket holds the operator report and every ledger beside it.
	reportsBucket = "reports"
	// graphsBucket holds both graph families: the complete facts graph and its
	// contracted attack-surface view.
	graphsBucket = "graphs"
	// netauditBucket holds the decoded packet evidence. The packets themselves stay
	// in the collection; this is the rebuildable view of them.
	netauditBucket = "netaudit"

	readmeName = "README.md"

	// reportMD and reportJSON are the compact operator report in both renderings.
	reportMD   = "report.md"
	reportJSON = "report.json"
	// issuesMD and issuesJSON are the complete issue ledger the compact report links
	// to whenever it omits lower-priority rows.
	issuesMD   = "issues.md"
	issuesJSON = "issues.json"
	// anomaliesMD and anomaliesJSON are the complete temporal-anomaly ledger. It is
	// separate from the operator report because one anomaly type fires once per
	// subject, so the ledger runs to hundreds of rows.
	anomaliesMD   = "temporal-anomalies.md"
	anomaliesJSON = "temporal-anomalies.json"
	// threatsMD and threatsJSON are the complete threat-scenario report. It is
	// separate from the operator report because a scenario is a narrative with its
	// own evidence chain per asset, and a scan that fired twenty of them would bury
	// the surface, host, and finding sections a reader came for.
	threatsMD   = "threat-scenarios.md"
	threatsJSON = "threat-scenarios.json"
	// dataQualityMD and dataQualityJSON are the content-and-operations quality report.
	dataQualityMD   = "data-quality.md"
	dataQualityJSON = "data-quality.json"
	// signalsMD and signalsJSON are the tool-health signal report.
	signalsMD   = "tools-health-signals.md"
	signalsJSON = "tools-health-signals.json"
	// diffMD and diffJSON compare two collections. They belong to a pair rather than
	// to one build, so they are written on their own into a destination the caller
	// names.
	diffMD   = "diff.md"
	diffJSON = "diff.json"
	// parityMD and parityJSON are the corpus parity report, likewise written on its
	// own into a caller-named destination.
	parityMD   = "capture-parity.md"
	parityJSON = "capture-parity.json"

	// The three renderings of the complete facts graph. The HTML page fetches the
	// JSON from beside itself when its embedded copy is unavailable, so the two names
	// have to stay together.
	factsMD   = "facts.md"
	factsJSON = "facts.json"
	factsHTML = "facts.html"
	// The three renderings of the contracted attack surface, beside the facts graph
	// they were contracted from.
	surfaceMD   = "attack-surface.md"
	surfaceJSON = "attack-surface.json"
	surfaceHTML = "attack-surface.html"

	// netauditSummaryMD is the human-readable decoded packet summary and
	// netauditRawJSONL the machine-readable log behind it: one JSON record per line,
	// holding bounded audit metadata and never packet payloads.
	netauditSummaryMD = "summary.md"
	netauditRawJSONL  = "raw.jsonl"
)

// projectionReadme documents the projection's layout and the command that rebuilds
// it. It is static - no scan-specific data - so it is written from this build's
// embedded copy rather than inherited from whatever was in the destination.
//
//go:embed projection_readme.md
var projectionReadme string

// WriteReadme explains the destination to whoever opens it later.
func WriteReadme(dst string) error {
	return writeFile(dst, "", readmeName, []byte(projectionReadme))
}

// WriteDataQuality writes the data-quality report into the reports bucket.
func WriteDataQuality(dst string, r *dataquality.Report) error {
	j, err := r.JSON()
	if err != nil {
		return fmt.Errorf("render %s: %w", dataQualityJSON, err)
	}
	if err := writeFile(dst, reportsBucket, dataQualityMD, []byte(r.Markdown())); err != nil {
		return err
	}
	return writeFile(dst, reportsBucket, dataQualityJSON, j)
}

// WriteSignals writes the tool-health signal report into the reports bucket.
func WriteSignals(dst string, r *toolsignals.Report) error {
	j, err := r.JSON()
	if err != nil {
		return fmt.Errorf("render %s: %w", signalsJSON, err)
	}
	if err := writeFile(dst, reportsBucket, signalsMD, []byte(r.Markdown())); err != nil {
		return err
	}
	return writeFile(dst, reportsBucket, signalsJSON, j)
}

// WriteFacts writes the three renderings of the complete facts graph into the graphs
// bucket.
//
// It validates the graph's structure before writing anything. A dangling edge, a
// duplicate identity, or an accidentally isolated asset would make the HTML view
// disagree with its own JSON - the viewer can only drop an edge whose endpoint is not
// a node - so the whole write fails with the offending subjects named instead of
// leaving a quietly wrong report behind. The event log is untouched, so a fixed
// normalizer regenerates from it.
func WriteFacts(dst string, g *facts.Graph) error {
	if err := g.Integrity().Err(); err != nil {
		return fmt.Errorf("facts report: %w", err)
	}
	j, err := g.JSON()
	if err != nil {
		return fmt.Errorf("render %s: %w", factsJSON, err)
	}
	page, err := factsreport.RenderHTML(j)
	if err != nil {
		return err
	}
	if err := writeFile(dst, graphsBucket, factsMD, []byte(g.Markdown())); err != nil {
		return err
	}
	if err := writeFile(dst, graphsBucket, factsJSON, j); err != nil {
		return err
	}
	return writeFile(dst, graphsBucket, factsHTML, page)
}

// WriteSurface writes the three renderings of the contracted attack surface into the
// graphs bucket, beside the facts graph they came from.
//
// It validates the contracted graph before writing anything, for the same reason
// [WriteFacts] does: an artifact that disagrees with itself, or that silently dropped
// something the scan collected, is worse than a failed write an operator can repeat.
func WriteSurface(dst string, g *attacksurface.Graph) error {
	if err := g.Err(); err != nil {
		return fmt.Errorf("attack surface: %w", err)
	}
	j, err := g.JSON()
	if err != nil {
		return fmt.Errorf("render %s: %w", surfaceJSON, err)
	}
	page, err := surfacereport.RenderHTML(j)
	if err != nil {
		return err
	}
	if err := writeFile(dst, graphsBucket, surfaceMD, []byte(g.Markdown())); err != nil {
		return err
	}
	if err := writeFile(dst, graphsBucket, surfaceJSON, j); err != nil {
		return err
	}
	return writeFile(dst, graphsBucket, surfaceHTML, page)
}

// WriteDiff prepares the explicit destination, writes the comparison of two
// collections into its reports bucket, and returns the path of the Markdown summary
// so the caller can report where it landed without knowing this package's file names.
//
// A diff belongs to a pair of collections and no single build produces it, so its
// destination is always chosen explicitly rather than derived from either side.
func WriteDiff(dst, baselineDir, candidateDir string, r *scandiff.Report) (string, error) {
	dst, err := prepareOutput(dst, baselineDir, candidateDir)
	if err != nil {
		return "", err
	}
	j, err := r.JSON()
	if err != nil {
		return "", fmt.Errorf("render %s: %w", diffJSON, err)
	}
	if err := writeFile(dst, reportsBucket, diffMD, []byte(r.Markdown())); err != nil {
		return "", err
	}
	if err := writeFile(dst, reportsBucket, diffJSON, j); err != nil {
		return "", err
	}
	return filepath.Join(dst, reportsBucket, diffMD), nil
}

// WriteParity prepares the explicit destination, writes the corpus parity report,
// and returns the path of the Markdown summary. Like a diff it belongs to a pair of
// corpora rather than to any one build.
func WriteParity(dst, baselineRoot, candidateRoot string, r *parityreport.Report) (string, error) {
	dst, err := prepareOutput(dst, baselineRoot, candidateRoot)
	if err != nil {
		return "", err
	}
	j, err := r.JSON()
	if err != nil {
		return "", fmt.Errorf("render %s: %w", parityJSON, err)
	}
	if err := writeFile(dst, "", parityMD, []byte(r.Markdown())); err != nil {
		return "", err
	}
	if err := writeFile(dst, "", parityJSON, j); err != nil {
		return "", err
	}
	return filepath.Join(dst, parityMD), nil
}

// WriteCorpusSignals prepares the explicit destination and writes a multi-collection
// tool-health signal report directly into it. It is not filed in a reports bucket: a
// corpus report has no single owning collection, so there is no build for it to belong to.
func WriteCorpusSignals(dst string, sources []string, r *toolsignals.Report) (string, error) {
	dst, err := prepareOutput(dst, sources...)
	if err != nil {
		return "", err
	}
	j, err := r.JSON()
	if err != nil {
		return "", fmt.Errorf("render %s: %w", signalsJSON, err)
	}
	if err := writeFile(dst, "", signalsMD, []byte(r.Markdown())); err != nil {
		return "", err
	}
	if err := writeFile(dst, "", signalsJSON, j); err != nil {
		return "", err
	}
	return filepath.Join(dst, signalsMD), nil
}

// writeFile writes one artifact into a bucket of the destination, creating the
// bucket first. An empty bucket writes at the destination root.
//
// Each writer creates the bucket it writes into and no other, so an empty bucket in a
// finished projection means the writer that owns it ran and produced nothing, rather
// than that the shape was laid out in advance.
func writeFile(dst, bucket, name string, content []byte) error {
	dir := dst
	if bucket != "" {
		dir = filepath.Join(dst, bucket)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s dir: %w", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeJSON marshals v with the indentation every JSON artifact here uses and writes
// it, so one rendering decision covers all of them.
func writeJSON(dst, bucket, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	return writeFile(dst, bucket, name, b)
}
