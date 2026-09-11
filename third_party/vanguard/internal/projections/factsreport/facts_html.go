package factsreport

import _ "embed"

// factsHTMLTemplate is the self-contained HTML page that visualizes the facts graph.
// It expects facts.json to be in the same directory. Loaded via fetch at page open.
//
//go:embed facts_template.html
var factsHTMLTemplate []byte
