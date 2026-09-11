package toolsignals

import (
	"fmt"
	"math"
	"sort"
)

// trendPoint is one scan's value for a tracked metric, kept in corpus order.
type trendPoint struct {
	scan  string
	value float64
}

// trendMetric describes one per-tool metric compared along the corpus order. A trend
// signal fires when the metric worsens from the first scan to the last by a material
// amount, and does so either monotonically (a clean regression, not a one-scan blip)
// or by crossing the good/bad threshold.
type trendMetric struct {
	// id is the catalogue id of the trend signal.
	id string
	// label names the metric in the summary.
	label string
	// higherIsWorse is true when a rising value is the regression (rate limits,
	// failed-call rate), false when a falling value is (attribution ratio).
	higherIsWorse bool
	// threshold is the good/bad boundary for a threshold crossing; a negative value
	// disables the crossing test (only monotonic worsening fires).
	threshold float64
	// minDelta is the smallest first-to-last change treated as material, so a trivial
	// drift does not fire.
	minDelta float64
	// integer is true when the value is a count (rendered as an integer), false when it
	// is a ratio (rendered as a percentage).
	integer bool
	// values returns tool -> metric value for the scans where the metric is defined.
	values func(sd ScanData) map[string]float64
}

// trendMetrics is the fixed set of metrics tracked across the corpus, with thresholds
// drawn from cfg so the same corpus and config are deterministic.
func trendMetrics(cfg Config) []trendMetric {
	return []trendMetric{
		{
			id: SigTrendAttributionDrop, label: "target-attribution ratio",
			higherIsWorse: false, threshold: cfg.TargetRatioThreshold, minDelta: 0.2,
			values: func(sd ScanData) map[string]float64 {
				out := map[string]float64{}
				for tool, a := range sd.Attribution {
					if a.total() == 0 || !cfg.isTargetedTool(tool) {
						continue
					}
					out[tool] = a.targetedRatio()
				}
				return out
			},
		},
		{
			id: SigTrendRateLimitRising, label: "rate-limit count",
			higherIsWorse: true, threshold: 0, minDelta: 2, integer: true,
			values: func(sd ScanData) map[string]float64 {
				out := map[string]float64{}
				for tool, ts := range sd.Stats.Tools {
					out[tool] = float64(ts.RateLimited)
				}
				return out
			},
		},
		{
			id: SigTrendFailedCallRateRising, label: "failed-call rate",
			higherIsWorse: true, threshold: cfg.FailedCallRateThreshold, minDelta: 0.2,
			values: func(sd ScanData) map[string]float64 {
				out := map[string]float64{}
				for tool, ts := range sd.Stats.Tools {
					avail := ts.Calls - ts.Unavailable
					if avail < minCallsForRate {
						continue
					}
					out[tool] = float64(ts.FailedCalls) / float64(avail)
				}
				return out
			},
		},
	}
}

// trendSignals compares each tracked metric along the corpus order and returns a
// signal for every (metric, tool) that regressed. Trends need at least two scans; a
// single-scan corpus yields none.
//
// A trend reads only signal when the corpus is meaningfully ordered - reruns of one
// target over time, or an intended baseline-then-candidate pair passed via -scans.
// Across a heterogeneous -root of different targets the ordering is by scan time, so a
// difference between two unrelated targets is not a regression; the >= 3-point rule for
// monotonic worsening and the threshold-crossing rule keep that variation from firing.
func trendSignals(scans []ScanData, cfg Config) []Signal {
	if len(scans) < 2 {
		return nil
	}
	var out []Signal
	for _, m := range trendMetrics(cfg) {
		series := map[string][]trendPoint{}
		for _, sd := range scans {
			vals := m.values(sd)
			for _, tool := range mapKeysSorted(vals) {
				series[tool] = append(series[tool], trendPoint{scan: sd.Label, value: vals[tool]})
			}
		}
		for _, tool := range mapKeysSorted(series) {
			if fired, reason := m.worsened(series[tool]); fired {
				out = append(out, m.signal(tool, series[tool], reason))
			}
		}
	}
	return out
}

// worsened reports whether a tool's metric series regressed materially, and by which
// rule. It needs at least two points (scans where the metric was defined).
func (m trendMetric) worsened(pts []trendPoint) (fired bool, reason string) {
	if len(pts) < 2 {
		return false, ""
	}
	first, last := pts[0].value, pts[len(pts)-1].value
	if !m.isWorse(first, last) || math.Abs(last-first) < m.minDelta {
		return false, ""
	}
	// A monotonic worsening is only a trend with at least three points: a sustained
	// direction, not a two-scan delta (which, across a heterogeneous corpus, is more
	// likely target variation than a regression). A two-point change fires only when it
	// crossed the good/bad threshold - an unambiguous boundary regression.
	if len(pts) >= 3 && m.monotonic(pts) {
		return true, "monotonic worsening"
	}
	if m.crossedThreshold(first, last) {
		return true, "threshold crossing"
	}
	return false, ""
}

// isWorse reports whether b is worse than a for this metric's direction.
func (m trendMetric) isWorse(a, b float64) bool {
	if m.higherIsWorse {
		return b > a
	}
	return b < a
}

// monotonic reports whether no step in the series improved on the one before it.
func (m trendMetric) monotonic(pts []trendPoint) bool {
	for i := 1; i < len(pts); i++ {
		if m.isWorse(pts[i].value, pts[i-1].value) {
			// pts[i-1] is worse than pts[i]: the metric improved at this step.
			return false
		}
	}
	return true
}

// crossedThreshold reports whether the series moved from the good side of the
// threshold to the bad side.
func (m trendMetric) crossedThreshold(first, last float64) bool {
	if m.threshold < 0 {
		return false
	}
	return !m.isBad(first) && m.isBad(last)
}

// isBad reports whether v is on the bad side of the metric's threshold.
func (m trendMetric) isBad(v float64) bool {
	if m.higherIsWorse {
		return v > m.threshold
	}
	return v < m.threshold
}

// signal builds the corpus-scoped trend Signal for one tool's regressed series.
func (m trendMetric) signal(tool string, pts []trendPoint, reason string) Signal {
	order := make([]string, 0, len(pts))
	values := make([]float64, 0, len(pts))
	for _, p := range pts {
		order = append(order, p.scan)
		values = append(values, p.value)
	}
	labels := append([]string(nil), order...)
	sort.Strings(labels)

	return Signal{
		ID:       m.id,
		Severity: SeverityMedium,
		Scope:    "corpus",
		Tool:     tool,
		Summary: fmt.Sprintf("%s %s worsened from %s to %s across the corpus (%s)",
			tool, m.label, m.fmtVal(pts[0].value), m.fmtVal(pts[len(pts)-1].value), reason),
		Evidence: map[string]any{
			"first":     pts[0].value,
			"last":      pts[len(pts)-1].value,
			"series":    values,
			"scanOrder": order,
			"reason":    reason,
		},
		Scans: labels,
	}
}

// fmtVal renders a metric value: an integer count, or a ratio as a percentage.
func (m trendMetric) fmtVal(v float64) string {
	if m.integer {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.0f%%", v*100)
}
