// Package analysis defines tunable policies used when interpreting immutable scan
// evidence. It deliberately does not define events: capture times and provider-supplied
// timestamps are facts recorded in the event stream, while freshness windows and clock
// skew tolerances are analyst choices that may change when an old capture is rebuilt.
//
// FreshnessPolicy is shared by the facts surface, finding classification, temporal
// coverage, and operator report. Keeping one policy object prevents two views of the
// same complete event stream from assigning different meanings to "recent" or from
// silently accepting different amounts of clock skew.
package analysis
