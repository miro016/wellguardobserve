package persistence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/velgard-sk/vanguard/internal/buildid"
	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/projections/collectionhealth"
)

// projectionManifestName is the completion record at the projection destination's
// root. A collection carries a different manifest at its own independent root.
const projectionManifestName = "manifest.json"

// ProjectionFormatVersion is the structure version written into every projection
// manifest. It is a traceability field rather than a negotiation mechanism: a
// projected tree is disposable, so a version this build does not recognize is
// rebuilt, never migrated.
// Version 4 describes a source collection directly - one start, one completion, one
// status - after the resumable multi-execution collection format was removed.
const ProjectionFormatVersion = 4

// ProjectionManifest is manifest.json at a projection root: the completion record
// of one build. Its presence is the claim that the whole build succeeded, which is
// why the projector writes it last, after every other artifact has been written and
// validated. A projected tree without it is an unfinished or abandoned one.
//
// It answers the two questions a derived artifact cannot answer about itself: which
// build produced it, and which collection it was produced from. Both matter because
// the tree is rebuilt whenever a projection rule changes, and a report whose
// projector is unknown cannot be compared with one built by a different projector.
type ProjectionManifest struct {
	// FormatVersion is the structure version, always ProjectionFormatVersion when
	// written.
	FormatVersion int `json:"formatVersion"`
	// ProjectedAt is the UTC instant this build completed.
	ProjectedAt time.Time `json:"projectedAt"`
	// Projector is the identity of the program that built the tree: its name and the
	// one opaque version identifier its caller chose. It is the same kind of value
	// the capture manifest records for the collector, so a capture and its projection
	// can be attributed with one vocabulary.
	//
	// Unlike a collector, a projector may carry no version: a rebuild folds material
	// the capture already holds, so the honest record is worth more than a refused
	// build.
	Projector buildid.Identity `json:"projector"`
	// Source identifies the collection this tree was built from.
	Source ProjectionSource `json:"source"`
}

// ProjectionSource is the source collection's identity, copied from the collection
// manifest at build time. It is copied rather than referenced so a projected tree
// moved away from its collection still says what it came from.
type ProjectionSource struct {
	// ScanID is the collection's run identity.
	ScanID string `json:"scanID"`
	// Root is the collection's scan root (estate).
	Root string `json:"root"`
	// StartedAt is the UTC start of the collection.
	StartedAt time.Time `json:"startedAt"`
	// CompletedAt is the UTC instant the collection reached its terminal status. It
	// is absent for a collection still recorded as running, which is what a tree
	// projected from partial evidence says about its source.
	CompletedAt time.Time `json:"completedAt,omitzero"`
	// Status is the collection's recorded outcome, copied verbatim from the
	// collection manifest. It is the machine-readable half of the same verdict the
	// operator report renders, so automation can reject or qualify a projection built
	// from a degraded collection without parsing prose.
	Status string `json:"status,omitempty"`
	// Health is the exact collection-health summary: the total and the sorted problem
	// rows. It is absent when the collection lost nothing.
	Health *ProjectionSourceHealth `json:"health,omitempty"`
}

// ProjectionSourceHealth is the collected manifest's health summary as written into
// a projection manifest. It is a copy of the source verdict, field for field, and
// carries no targets, error text, or credentials.
type ProjectionSourceHealth struct {
	// Total is the number of health-bearing tool events the collection observed.
	Total int `json:"total"`
	// Problems are the distinct problem identities and counts, in the collected
	// manifest's canonical order.
	Problems []collection.HealthProblemCount `json:"problems"`
}

// NewProjectionManifest builds the completion record for a build of src by
// projector, completed at the given instant.
// health is the same collection-health value every other artifact of this build was
// written from, so the manifest cannot disagree with the report beside it. It is nil
// only for a caller that mapped none, and the source block then carries identity and
// timing without a verdict.
func NewProjectionManifest(src *collection.Manifest, projector buildid.Identity, at time.Time,
	health *collectionhealth.Summary) ProjectionManifest {
	source := ProjectionSource{
		ScanID:      src.ScanID,
		Root:        src.Root,
		StartedAt:   src.StartedAt,
		CompletedAt: src.CompletedAt,
	}
	if health != nil {
		source.Status = string(health.Status)
		if health.Total > 0 {
			problems := make([]collection.HealthProblemCount, 0, len(health.Problems))
			for _, p := range health.Problems {
				problems = append(problems, collection.HealthProblemCount{
					Code: p.Code, Tool: p.Tool, Component: p.Component, Count: p.Count,
				})
			}
			source.Health = &ProjectionSourceHealth{Total: health.Total, Problems: problems}
		}
	}
	return ProjectionManifest{
		FormatVersion: ProjectionFormatVersion,
		ProjectedAt:   at.UTC(),
		Projector:     projector,
		Source:        source,
	}
}

// WriteProjectionManifest writes the completion record into a projection root. It
// is the last write of a build, so an interrupted or failed build leaves its
// destination with no manifest.
func WriteProjectionManifest(destination string, m ProjectionManifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal projection manifest: %w", err)
	}
	path := filepath.Join(destination, projectionManifestName)
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write projection manifest: %w", err)
	}
	return nil
}
