package persistence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/projections/parityreport"
)

// BuildParity loads a parity manifest and every collection pair it names, then
// returns the deterministic policy report. A malformed manifest or undecodable
// canonical stream is an operational error. Split reconciliation defects are kept
// in the report so all pairs can still be assessed in one run.
func BuildParity(baselineRoot, candidateRoot, manifestPath string) (parityreport.Report, error) {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return parityreport.Report{}, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := parityreport.ParseManifest(b)
	if err != nil {
		return parityreport.Report{}, err
	}

	scenarios := make([]parityreport.ScenarioInput, 0, len(manifest.Scenarios))
	for _, spec := range manifest.Scenarios {
		baselineDir := filepath.Join(baselineRoot, spec.Name)
		candidateDir := filepath.Join(candidateRoot, spec.Name)
		baseline, err := auditParityCollection(baselineDir)
		if err != nil {
			return parityreport.Report{}, fmt.Errorf("scenario %s: load baseline: %w", spec.Name, err)
		}
		candidate, err := auditParityCollection(candidateDir)
		if err != nil {
			return parityreport.Report{}, fmt.Errorf("scenario %s: load candidate: %w", spec.Name, err)
		}
		diff, err := BuildDiff(baselineDir, candidateDir)
		if err != nil {
			return parityreport.Report{}, fmt.Errorf("scenario %s: %w", spec.Name, err)
		}
		scenarios = append(scenarios, parityreport.ScenarioInput{
			Spec: spec, Baseline: baseline, Candidate: candidate, Diff: diff,
		})
	}
	return parityreport.Build(baselineRoot, candidateRoot, manifestPath, scenarios), nil
}

// auditParityCollection decodes the canonical stream, derives phase/type indexes,
// and retains split reconciliation as a check result rather than a fatal load error.
func auditParityCollection(dir string) (parityreport.ScanAudit, error) {
	eventsInCollection, err := collection.LoadEvents(dir)
	if err != nil {
		return parityreport.ScanAudit{}, err
	}
	phases := map[string]struct{}{}
	counts := make(map[string]int)
	for _, event := range eventsInCollection {
		if phase := string(event.Meta().Phase); phase != "" {
			phases[phase] = struct{}{}
		}
		counts[events.TypeName(event)]++
	}
	return parityreport.ScanAudit{
		Phases: sortedStringSet(phases), EventCounts: counts,
		SplitError: reconcileEventSplits(dir, eventsInCollection),
	}, nil
}

// reconcileEventSplits verifies that every per-type event sequence exactly matches
// the corresponding subsequence of the canonical stream.
func reconcileEventSplits(dir string, canonical []events.DomainEvent) error {
	expected := make(map[string][][]byte)
	for _, event := range canonical {
		typeName := events.TypeName(event)
		raw, err := json.Marshal(events.AsValue(event))
		if err != nil {
			return fmt.Errorf("marshal canonical %s: %w", typeName, err)
		}
		expected[typeName] = append(expected[typeName], raw)
	}

	eventsDir := collection.EventsDir(dir)
	entries, err := os.ReadDir(eventsDir)
	if err != nil {
		return fmt.Errorf("read event splits: %w", err)
	}
	splits := make(map[string][][]byte)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "events_") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		typeName := strings.TrimSuffix(strings.TrimPrefix(name, "events_"), ".jsonl")
		lines, err := readJSONLines(filepath.Join(eventsDir, name))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		splits[typeName] = lines
	}
	for _, typeName := range sortedStringMapKeys(expected) {
		want := expected[typeName]
		got, ok := splits[typeName]
		if !ok {
			return fmt.Errorf("missing split for %s", typeName)
		}
		if len(got) != len(want) {
			return fmt.Errorf("split %s count=%d canonical=%d", typeName, len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				return fmt.Errorf("split %s event %d differs from canonical stream", typeName, i+1)
			}
		}
	}
	for _, typeName := range sortedStringMapKeys(splits) {
		got := splits[typeName]
		if len(got) != len(expected[typeName]) {
			return fmt.Errorf("split %s count=%d canonical=%d", typeName, len(got), len(expected[typeName]))
		}
	}
	return nil
}

// readJSONLines returns trimmed, validated JSON records in file order.
func readJSONLines(path string) (lines [][]byte, resultErr error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close: %w", err))
		}
	}()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("line %d is not valid JSON", len(lines)+1)
		}
		lines = append(lines, bytes.Clone(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedStringMapKeys[V any](values map[string]V) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
