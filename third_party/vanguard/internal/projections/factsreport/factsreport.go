package factsreport

import (
	"bytes"
	"fmt"
)

// factsJSONPlaceholder is the marker the page template carries where the graph is
// embedded. It sits inside a JavaScript comment so the template is valid on its own,
// and a render fails if it is ever missing rather than shipping a page that can only
// fall back to fetching a sibling file.
const factsJSONPlaceholder = "/* {{FACTS_JSON}} */"

// RenderHTML returns the self-contained facts-graph page with graphJSON embedded in
// it. The page is a D3.js viewer with complete-history and state-at timeline modes
// driven by the graph's temporal assertions and its fixed analysis cutoff; the
// embedded copy is what lets it open straight from disk, and fetching the sibling
// facts.json is only a fallback.
//
// It returns bytes rather than writing a file: this package owns the page, and where
// a page lands is internal/projections/persistence's business.
func RenderHTML(graphJSON []byte) ([]byte, error) {
	if !bytes.Contains(factsHTMLTemplate, []byte(factsJSONPlaceholder)) {
		return nil, fmt.Errorf("facts report: the page template has no %s placeholder to embed the graph in",
			factsJSONPlaceholder)
	}
	return bytes.Replace(factsHTMLTemplate, []byte(factsJSONPlaceholder), graphJSON, 1), nil
}
