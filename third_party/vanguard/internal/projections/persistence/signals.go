package persistence

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/projections/toolsignals"
)

// SignalsInputs names the collection inputs and optional detector configuration
// for one tool-health signals report. Exactly one of Root or Scans must be set.
type SignalsInputs struct {
	// Root is a directory whose immediate subdirectories are candidate collections.
	Root string
	// Scans is an explicit, ordered list of collection directories.
	Scans []string
	// MinSeverity is the display floor ("high"|"medium"|"low"|"info" or empty
	// for info).
	MinSeverity string
	// ConfigPath optionally overrides the baked-in detector config with a JSON file.
	ConfigPath string
}

// BuildSignals loads the named collection tool-event streams and returns their
// ranked report. It writes nothing; [WriteCorpusSignals] owns the output files.
func BuildSignals(in SignalsInputs) (toolsignals.Report, error) {
	cfg, err := loadSignalsConfig(in.ConfigPath)
	if err != nil {
		return toolsignals.Report{}, err
	}
	minSeverity, err := toolsignals.ParseSeverity(in.MinSeverity, true)
	if err != nil {
		return toolsignals.Report{}, err
	}

	switch {
	case in.Root != "" && len(in.Scans) > 0:
		return toolsignals.Report{}, errors.New("exactly one of root or scans may be set, not both")
	case in.Root != "":
		scans, skipped, err := loadSignalsRoot(in.Root)
		if err != nil {
			return toolsignals.Report{}, err
		}
		return toolsignals.Build(toolsignals.Input{
			Mode: "root", Scans: scans, Skipped: skipped, MinSeverity: minSeverity,
		}, cfg), nil
	case len(in.Scans) > 0:
		scans, err := loadSignalScans(in.Scans)
		if err != nil {
			return toolsignals.Report{}, err
		}
		return toolsignals.Build(toolsignals.Input{
			Mode: "scans", Scans: scans, MinSeverity: minSeverity,
		}, cfg), nil
	default:
		return toolsignals.Report{}, errors.New("one of root or scans is required")
	}
}

// loadSignalsRoot discovers collections under root. A child with no tool-event log
// is skipped and recorded; a present but unreadable log is a broken input and fails
// the report.
func loadSignalsRoot(root string) (scans []toolsignals.ScanData, skipped []string, err error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, fmt.Errorf("read root: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		scan, found, loadErr := loadSignalScan(entry.Name(), dir)
		if loadErr != nil {
			return nil, nil, loadErr
		}
		if !found {
			skipped = append(skipped, dir)
			continue
		}
		scans = append(scans, scan)
	}
	sort.SliceStable(scans, func(i, j int) bool {
		if !scans[i].EarliestAt.Equal(scans[j].EarliestAt) {
			return scans[i].EarliestAt.Before(scans[j].EarliestAt)
		}
		return scans[i].Label < scans[j].Label
	})
	sort.Strings(skipped)
	return scans, skipped, nil
}

// loadSignalScans loads an explicit list in argument order. A named collection
// missing its tool-event log is an error because the caller asserted it was input.
func loadSignalScans(dirs []string) ([]toolsignals.ScanData, error) {
	scans := make([]toolsignals.ScanData, 0, len(dirs))
	for _, dir := range dirs {
		scan, found, err := loadSignalScan(filepath.Base(dir), dir)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("scan %q has no tooling log at %s", dir, collection.ToolLogPath(dir))
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

// loadSignalScan folds one collection's tool-event log and attaches its operational
// rollup. found is false only when the optional stream is absent.
func loadSignalScan(label, dir string) (scan toolsignals.ScanData, found bool, err error) {
	f, found, err := collection.ReadToolLog(dir)
	if err != nil {
		return toolsignals.ScanData{}, false, fmt.Errorf("open tooling log for %s: %w", label, err)
	}
	if !found {
		return toolsignals.ScanData{}, false, nil
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close tooling log for %s: %w", label, closeErr))
		}
	}()

	scan, err = toolsignals.Fold(label, f)
	if err != nil {
		return scan, true, fmt.Errorf("fold %s: %w", label, err)
	}
	if scan.Status != toolsignals.LoadOK {
		return scan, true, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return scan, true, fmt.Errorf("rewind tooling log for %s: %w", label, err)
	}
	stats, err := tooleventlog.ReplayTooling(f)
	if err != nil {
		return scan, true, fmt.Errorf("replay tooling log for %s: %w", label, err)
	}
	scan.Stats = stats
	return scan, true, nil
}

// hasToolingLog distinguishes a quiet collection from an invalid optional stream.
func hasToolingLog(dir string) (bool, error) {
	f, found, err := collection.ReadToolLog(dir)
	if f != nil {
		if closeErr := f.Close(); closeErr != nil {
			return false, fmt.Errorf("close tooling log for %s: %w", dir, closeErr)
		}
	}
	return found, err
}

// loadSignalsConfig returns the default config, overlaid with the JSON at path when
// set. An unreadable or malformed override fails before collection streams are read.
func loadSignalsConfig(path string) (toolsignals.Config, error) {
	cfg := toolsignals.DefaultConfig()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
