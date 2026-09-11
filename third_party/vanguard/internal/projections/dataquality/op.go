package dataquality

import (
	"sort"
	"time"
)

// ProviderOps is the operational rollup for one provider, lifted from the
// tool-event stream. It is the seed of the operational-quality table and
// the reliability term of the efficiency score.
type ProviderOps struct {
	// Provider is the tool name, matching events.EventMeta.Source.
	Provider string `json:"provider"`
	// Events is the total tool events the provider emitted.
	Events int `json:"events"`
	// Errors is the count of error-level events.
	Errors int `json:"errors"`
	// Warns is the count of warn-level events.
	Warns int `json:"warns"`
	// RateLimited is the count of provider rate-limit hits.
	RateLimited int `json:"rateLimited"`
	// Empties is the count of successful calls that returned zero results.
	Empties int `json:"empties"`
	// Calls is the number of distinct correlated tool invocations.
	Calls int `json:"calls"`
	// FailedCalls is the number of correlated calls that genuinely failed (a
	// transport/protocol error or an active probe that connected to nothing). Unlike
	// Errors it counts the active probes whose failures are warns, so it is the
	// numerator of the reliability term. A clean empty passive result and an
	// unavailable call are excluded.
	FailedCalls int `json:"failedCalls"`
	// Unavailable is the number of correlated calls the provider declined to serve
	// (paid plan, auth refusal, membership wall, or rate-limit). Excluded from
	// FailedCalls and from the reliability denominator so an unavailable provider on
	// a free key reads "n/a", not 0% reliable.
	Unavailable int `json:"unavailable"`
	// MedianLatency is the median correlated-call duration.
	MedianLatency time.Duration `json:"medianLatency"`
}

// ErrorRate is errors as a fraction of all events, 0 when the provider emitted
// nothing.
func (p *ProviderOps) ErrorRate() float64 {
	if p.Events == 0 {
		return 0
	}
	return float64(p.Errors) / float64(p.Events)
}

// AvailableCalls is the correlated calls that genuinely ran against an available
// provider: total calls minus those the provider declined (paid plan, auth,
// membership, rate-limit). It is the denominator for the failed-call rate, so an
// unavailable provider does not deflate its own reliability.
func (p *ProviderOps) AvailableCalls() int {
	return p.Calls - p.Unavailable
}

// FailedCallRate is failed calls as a fraction of available calls, 0 when no call
// was available.
func (p *ProviderOps) FailedCallRate() float64 {
	avail := p.AvailableCalls()
	if avail <= 0 {
		return 0
	}
	return float64(p.FailedCalls) / float64(avail)
}

// Reliability is the provider's reliability term in [0,1] and whether it is
// defined. It is undefined (ok == false, rendered "n/a") when correlated calls
// happened but every one was unavailable - the provider declined them all, so there
// is nothing to score - rather than reporting a misleading 0%. With at least one
// available call it is 1 - the failed-call rate (which sees active probes whose
// failures are warns, not errors). With no correlated call at all it falls back to
// 1 - the event error rate, so an older stream without call spans still scores.
func (p *ProviderOps) Reliability() (value float64, ok bool) {
	if p.Calls > 0 {
		if p.AvailableCalls() <= 0 {
			return 0, false
		}
		return 1 - p.FailedCallRate(), true
	}
	return 1 - p.ErrorRate(), true
}

// OpStats is the operational input to the report: per-provider rollups plus a flag
// for whether the tool-event stream was available at all. When Available is false
// the report renders content-only and the score drops the reliability term, so a
// missing tooling.jsonl degrades gracefully rather than scoring every provider 0.
type OpStats struct {
	// Available is true when the tool-event stream was read.
	Available bool `json:"available"`
	// Providers maps provider name to its operational rollup.
	Providers map[string]ProviderOps `json:"providers,omitempty"`
}

// sortedOps returns the operational rollups ordered by provider name.
func (o OpStats) sortedOps() []ProviderOps {
	out := make([]ProviderOps, 0, len(o.Providers))
	for _, p := range o.Providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}
