package surfacereport

import (
	"bytes"
	"fmt"

	"github.com/velgard-sk/vanguard/internal/projections/attacksurface"
	"github.com/velgard-sk/vanguard/internal/projections/collectionhealth"
	"github.com/velgard-sk/vanguard/internal/projections/facts"
)

// surfaceJSONPlaceholder is the marker the HTML template carries where the contracted
// graph is embedded. It sits inside a JavaScript comment so the template is valid on its
// own, and the write fails if it is ever missing rather than shipping a page that can
// only fall back to fetching a sibling file.
const surfaceJSONPlaceholder = "/* {{SURFACE_JSON}} */"

// Contract contracts an already folded facts graph. There is deliberately no
// stream-loading entry point beside it: the projector folds a capture's event log
// once and hands the same graph to the facts writer and to this contraction, so the
// two artifacts can never be built from two different folds of the same capture.
//
// It refuses to contract a facts graph that fails its own integrity check. The surface
// is a lossy view of the facts graph, so contracting a graph with a dangling asset,
// finding, or evidence reference would either hide the defect behind a contraction
// rule or carry it forward into a second artifact.
func Contract(fg *facts.Graph, health *collectionhealth.Summary) (*attacksurface.Graph, error) {
	if err := fg.Integrity().Err(); err != nil {
		return nil, fmt.Errorf("attack surface: %w", err)
	}
	return attacksurface.Build(fg.View(), sourceCollection(health)), nil
}

// sourceCollection compacts the projector's one collection-health value for the
// surface artifacts. The exact problem rows stay in the operator report: this
// artifact states the same verdict, not a second copy of the ledger behind it.
func sourceCollection(health *collectionhealth.Summary) *attacksurface.SourceCollection {
	if health == nil {
		return nil
	}
	return &attacksurface.SourceCollection{
		Status:      string(health.Status),
		HealthTotal: health.Total,
	}
}

// RenderHTML returns the self-contained attack-surface page with graphJSON embedded
// in it, so the page opens straight from disk; fetching the sibling
// attack-surface.json is only a fallback for a page whose embedded block was
// stripped.
//
// It returns bytes rather than writing a file: this package owns the page and the
// contraction behind it, and where a page lands is
// internal/projections/persistence's business.
func RenderHTML(graphJSON []byte) ([]byte, error) {
	if !bytes.Contains(surfaceHTMLTemplate, []byte(surfaceJSONPlaceholder)) {
		return nil, fmt.Errorf("attack surface: the page template has no %s placeholder to embed the graph in",
			surfaceJSONPlaceholder)
	}
	return bytes.Replace(surfaceHTMLTemplate, []byte(surfaceJSONPlaceholder), graphJSON, 1), nil
}
