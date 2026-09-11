package dataquality

import "sort"

// ScoreWeights are the printed, explainable weights of the efficiency score. They
// are not tuned: the goal is to inform a "keep paying for this provider?" decision,
// not to be authoritative. The weights are renormalised over the terms actually
// available, so dropping reliability (no tool-event stream) does not deflate the
// score.
type ScoreWeights struct {
	// Coverage rewards reporting a value for many of the shared target keys.
	Coverage float64 `json:"coverage"`
	// Unique rewards contributing keys/values no other provider reported.
	Unique float64 `json:"unique"`
	// Reliability rewards a low failed-call rate in the tool-event stream (the share
	// of calls that returned no usable result), falling back to the error rate when
	// no call was correlated.
	Reliability float64 `json:"reliability"`
}

// DefaultWeights is the starting, deliberately simple weighting.
func DefaultWeights() ScoreWeights {
	return ScoreWeights{Coverage: 0.5, Unique: 0.3, Reliability: 0.2}
}

// ProviderScore is a provider's transparent efficiency score and the three
// component ratios it is built from, each in [0,1].
type ProviderScore struct {
	// Provider is the tool name.
	Provider string `json:"provider"`
	// Coverage is the average per-field share of shared keys this provider covered.
	Coverage float64 `json:"coverage"`
	// Unique is the share of this provider's contributions that were sole.
	Unique float64 `json:"unique"`
	// Reliability is 1 - failed-call rate (the share of correlated calls that
	// returned no usable result), falling back to 1 - error rate when no call was
	// correlated; 0 when no tool-event stream was available. The failed-call basis
	// sees active probes whose connection failures are logged at warn, not error.
	Reliability float64 `json:"reliability"`
	// Score is the weight-combined result in [0,1].
	Score float64 `json:"score"`
}

// buildScores combines the per-field coverage with the operational reliability
// into one explainable score per provider. The provider set is the union of every
// content provider and every operational provider, so a provider that errored out
// without producing content still appears (with coverage 0).
func buildScores(fields []FieldReport, op OpStats, w ScoreWeights) []ProviderScore {
	type acc struct {
		covSum       float64 // sum of per-field coverage ratios
		covFields    int     // fields the provider participated in
		contribTotal int     // keys + values the provider reported
		contribSole  int     // unique keys + unique values
	}
	accs := map[string]*acc{}
	get := func(p string) *acc {
		a := accs[p]
		if a == nil {
			a = &acc{}
			accs[p] = a
		}
		return a
	}

	for _, fr := range fields {
		if fr.TotalKeys == 0 {
			continue
		}
		for _, pc := range fr.Providers {
			a := get(pc.Provider)
			a.covSum += float64(pc.Keys) / float64(fr.TotalKeys)
			a.covFields++
			a.contribTotal += pc.Keys + pc.Values
			a.contribSole += pc.UniqueKeys + pc.UniqueValues
		}
	}
	for p := range op.Providers {
		get(p)
	}

	names := make([]string, 0, len(accs))
	for p := range accs {
		names = append(names, p)
	}
	sort.Strings(names)

	out := make([]ProviderScore, 0, len(names))
	for _, name := range names {
		a := accs[name]
		ps := ProviderScore{Provider: name}
		if a.covFields > 0 {
			ps.Coverage = a.covSum / float64(a.covFields)
		}
		if a.contribTotal > 0 {
			ps.Unique = float64(a.contribSole) / float64(a.contribTotal)
		}

		num := w.Coverage*ps.Coverage + w.Unique*ps.Unique
		den := w.Coverage + w.Unique
		if op.Available {
			pops := op.Providers[name]
			// Drop the reliability term when it is undefined (every call was
			// unavailable): the score is then content-only for that provider, like a
			// missing tool-event stream, rather than penalised by a 0 reliability.
			if rel, ok := pops.Reliability(); ok {
				ps.Reliability = rel
				num += w.Reliability * ps.Reliability
				den += w.Reliability
			}
		}
		if den > 0 {
			ps.Score = num / den
		}
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}
