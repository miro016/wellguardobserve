package persistence

import (
	"fmt"

	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
	"github.com/velgard-sk/vanguard/internal/projections/collectionhealth"
)

// SourceHealth maps the already validated collection manifest into the one
// projection-owned collection-health summary every derived artifact renders.
//
// It is a function rather than a method on the manifest because the manifest is the
// collection phase's type and collectionhealth is a projection package: the mapping
// belongs to the side that consumes it, so the collection half never depends on a
// projection component to describe itself.
//
// It is the single manifest-to-projection mapper, and it copies durable manifest
// values rather than deriving anything: the status is the recorded status, and the
// health rows are the recorded rows. It never infers an outcome from the phase list,
// from scan completion events, from the tool stream, or from packet-capture state,
// because the collection manifest is the sole persisted authority for what a
// collection achieved and a second derivation would eventually contradict it.
//
// An error means the manifest is internally inconsistent in a way the projection
// refuses to render. Callers fail the build rather than writing artifacts that
// describe an outcome nothing vouches for.
func SourceHealth(m *collection.Manifest) (*collectionhealth.Summary, error) {
	in := collectionhealth.Summary{
		ScanID: m.ScanID,
		Status: collectionhealth.Status(m.Status),
		Phases: m.Phases,
	}
	if m.Health != nil {
		in.Total = m.Health.Total
		in.Problems = make([]collectionhealth.Problem, 0, len(m.Health.Problems))
		for _, p := range m.Health.Problems {
			in.Problems = append(in.Problems, collectionhealth.Problem{
				Code: p.Code, Tool: p.Tool, Component: p.Component, Count: p.Count,
			})
		}
	}
	summary, err := collectionhealth.New(in)
	if err != nil {
		return nil, fmt.Errorf("collection manifest for scan %s: %w", m.ScanID, err)
	}
	return &summary, nil
}
