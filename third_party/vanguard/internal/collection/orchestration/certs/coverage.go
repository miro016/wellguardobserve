package certs

import "sync"

// CrtshCoverageShortfall reports whether crt.sh's discovered subdomain count is
// materially below the certspotter corroborator's, given the minimum acceptable
// ratio. crt.sh can return HTTP 200 with a truncated certificate set, silently
// dropping subdomains; certspotter reads the same Certificate Transparency logs,
// so a much smaller crt.sh set is a genuine truncation signal.
//
// It returns false when the cross-check is disabled (minRatio <= 0) or cannot be
// performed (certspotter contributed nothing, e.g. it is disabled or its query
// failed), so an absent or disabled second source never produces a false warning.
func CrtshCoverageShortfall(crtshCount, certspotterCount int, minRatio float64) bool {
	if minRatio <= 0 || certspotterCount <= 0 {
		return false
	}
	return float64(crtshCount) < minRatio*float64(certspotterCount)
}

// CertspotterInert reports whether the certspotter CT cross-check ran but could not
// corroborate crt.sh: the cross-check is enabled (minRatio > 0), certspotter
// contributed no distinct names, yet crt.sh contributed some. It is the inverse of a
// shortfall - the second source is present but did its job on nothing (a keyless
// recent-window limit, rate limiting, or a failed query) - so the corroboration is
// silently inert rather than a clean agreement, and the caller flags it.
//
// It returns false when the cross-check is disabled (minRatio <= 0), when certspotter
// contributed anything (certspotterCount > 0, which the shortfall predicate covers
// instead), or when crt.sh is itself empty (a genuinely certless root has nothing to
// corroborate). By construction it is mutually exclusive with CrtshCoverageShortfall
// on certspotterCount (0 here vs > 0 there), so at most one of the two fires.
func CertspotterInert(crtshCount, certspotterCount int, minRatio float64) bool {
	return minRatio > 0 && certspotterCount == 0 && crtshCount > 0
}

// Coverage records the distinct names each discovery source contributed, so the
// certificate-transparency cross-check can compare crt.sh's coverage against the
// certspotter second source and flag a likely-truncated crt.sh response.
//
// It is label-agnostic: it keeps one set of names per source label, and the caller
// supplies the labels (Record for every discovered name, Count with the cert-source
// labels it wants to compare). It is safe for concurrent use - Record runs on the
// emit hot path across many goroutines - so it carries its own mutex and callers
// must not hold an external lock across a call.
type Coverage struct {
	mu       sync.Mutex
	bySource map[string]map[string]bool
}

// NewCoverage returns an empty Coverage ready to Record into.
func NewCoverage() *Coverage {
	return &Coverage{bySource: make(map[string]map[string]bool)}
}

// Record adds name to source's set, deduplicating a name already recorded for that
// source. The source's set is created on its first Record.
func (c *Coverage) Record(source, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.bySource[source]
	if set == nil {
		set = make(map[string]bool)
		c.bySource[source] = set
	}
	set[name] = true
}

// Count returns the number of distinct names recorded for source, or 0 for a source
// that was never recorded.
func (c *Coverage) Count(source string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bySource[source])
}
