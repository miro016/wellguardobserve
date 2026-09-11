package surfacereport

import _ "embed"

// surfaceHTMLTemplate is the self-contained page that visualizes the contracted attack
// surface. The graph is embedded into it at write time, so the page opens straight from
// disk; fetching the sibling attack-surface.json is only a fallback for a page whose
// embedded block was stripped.
//
//go:embed surface_template.html
var surfaceHTMLTemplate []byte
