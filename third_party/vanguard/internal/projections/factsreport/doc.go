// Package factsreport renders the facts knowledge graph as a self-contained HTML
// page. That page is the whole of it: the fold belongs to
// github.com/velgard-sk/vanguard/internal/projections/facts, and writing the three
// renderings belongs to internal/projections/persistence.
//
// [RenderHTML] takes the graph's JSON and returns the page with that JSON embedded
// in it. It returns bytes rather than writing a file, so this package owns no path
// and cannot disagree with the writer about where its own artifact lands.
//
// The HTML artifact is a self-contained page that loads the facts.json beside it via fetch and renders
// an interactive D3.js force-directed graph with filters for node type, edge type, name
// search with neighbor expansion, source, and confidence. Its timeline has two explicit
// modes. History accumulated through reveals the complete ledger through a cutoff. State at
// keeps every subject rendered and styles what is current, valid-unverified, historical,
// unknown, or future at that instant. It reads temporal assertions and source_time_missing
// directly rather than guessing from proximity to scan time. The scan-completion cutoff,
// current-state composition, source-dated coverage, and legend stay visible beside the
// scrubber.
package factsreport
