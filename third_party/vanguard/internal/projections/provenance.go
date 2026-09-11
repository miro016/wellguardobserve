package projections

import (
	"sort"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// maxLineageDepth caps how far Chain/Descendants will walk, guarding against an
// accidental cycle or a pathologically deep chain.
const maxLineageDepth = 1000

// EventNode is one node in the causal graph of a scan.
type EventNode struct {
	EventID     string
	CausationID string
	Source      string
	Phase       string
	Category    string
	Summary     string // event String()
	CapturedAt  time.Time
}

// Lineage is the causal graph of all events in a scan. Every non-root event
// carries a CausationID pointing at the event that triggered it, so the stream
// alone is enough to reconstruct any event's full ancestry and descendants.
type Lineage struct {
	// Nodes keyed by EventID.
	Nodes map[string]*EventNode
	// children maps a CausationID to the EventIDs it caused.
	children map[string][]string
}

// NewLineage returns a Lineage with initialised maps.
func NewLineage() Lineage {
	var l Lineage
	l.ensureInit()
	return l
}

func (l *Lineage) ensureInit() {
	if l.Nodes == nil {
		l.Nodes = make(map[string]*EventNode)
	}
	if l.children == nil {
		l.children = make(map[string][]string)
	}
}

// Apply records an event and its causation edge. It is idempotent: re-applying
// the same event does not duplicate the node or the edge.
func (l *Lineage) Apply(evt events.DomainEvent) {
	l.ensureInit()
	m := evt.Meta()
	if m.EventID == "" {
		return
	}
	if _, exists := l.Nodes[m.EventID]; exists {
		return
	}
	l.Nodes[m.EventID] = &EventNode{
		EventID:     m.EventID,
		CausationID: m.CausationID,
		Source:      m.Source,
		Phase:       string(m.Phase),
		Category:    string(m.Category),
		Summary:     evt.String(),
		CapturedAt:  m.CapturedAt,
	}
	if m.CausationID != "" {
		l.children[m.CausationID] = appendUnique(l.children[m.CausationID], m.EventID)
	}
}

// Chain returns the ancestry of an event from root to the event itself. It walks
// CausationID pointers upward, stopping at an event with no recorded parent (a
// lifecycle root) and guarding against cycles and excessive depth.
func (l *Lineage) Chain(eventID string) []*EventNode {
	var chain []*EventNode
	visited := make(map[string]bool)
	id := eventID
	for depth := 0; id != "" && depth < maxLineageDepth; depth++ {
		node, ok := l.Nodes[id]
		if !ok || visited[id] {
			break
		}
		visited[id] = true
		chain = append(chain, node)
		id = node.CausationID
	}
	// Collected leaf -> root; reverse to root -> leaf.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// Descendants returns every event transitively caused by eventID, ordered by
// time then EventID. The event itself is not included.
func (l *Lineage) Descendants(eventID string) []*EventNode {
	out := make([]*EventNode, 0)
	visited := map[string]bool{eventID: true}
	queue := append([]string(nil), l.children[eventID]...)
	for len(queue) > 0 && len(visited) < maxLineageDepth {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true
		if node, ok := l.Nodes[id]; ok {
			out = append(out, node)
		}
		queue = append(queue, l.children[id]...)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CapturedAt.Equal(out[j].CapturedAt) {
			return out[i].CapturedAt.Before(out[j].CapturedAt)
		}
		return out[i].EventID < out[j].EventID
	})
	return out
}

// ChainsForEvents returns one ancestry chain per unique, non-empty event ID. The
// report uses this to print, per significant asset or finding, "how we got here"
// from each event that contributed to it.
func (l *Lineage) ChainsForEvents(eventIDs []string) [][]*EventNode {
	seen := make(map[string]bool)
	var chains [][]*EventNode
	for _, id := range eventIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if chain := l.Chain(id); len(chain) > 0 {
			chains = append(chains, chain)
		}
	}
	return chains
}
