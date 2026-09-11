package dataquality

import "github.com/velgard-sk/vanguard/internal/collection/events"

// Report is the full provider data-quality result: the per-field content
// comparison, the operational rollup, and the efficiency score, plus the weights
// the score used. It renders to deterministic Markdown and JSON.
type Report struct {
	// Fields is the per-comparable-field content comparison, in registry order.
	Fields []FieldReport `json:"fields"`
	// Op is the operational rollup; Op.Available is false when no tool-event stream.
	Op OpStats `json:"op"`
	// Scores is the per-provider efficiency score, best first.
	Scores []ProviderScore `json:"scores"`
	// Weights are the score weights, printed so the score is explainable.
	Weights ScoreWeights `json:"weights"`
}

// Build computes the data-quality report from the raw domain-event stream and the
// operational stats. It is deterministic and fully offline: the same inputs always
// produce the same report. Pass an empty OpStats (Available false) for content-only.
func Build(evts []events.DomainEvent, op OpStats) Report {
	weights := DefaultWeights()
	fields := make([]FieldReport, 0)
	for _, f := range Fields() {
		fields = append(fields, buildFieldReport(f, evts))
	}
	return Report{
		Fields:  fields,
		Op:      op,
		Scores:  buildScores(fields, op, weights),
		Weights: weights,
	}
}
