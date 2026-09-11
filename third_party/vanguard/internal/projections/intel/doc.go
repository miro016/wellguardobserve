// Package intel provides local-first exploit-intelligence enrichment: a small,
// curated, dated snapshot of known-exploited vulnerabilities (a trimmed CISA KEV
// list) and common default credentials, bundled in the repository and loaded from
// an embedded file.
//
// It is deliberately local-first: there is no scan-time network call,
// so enrichment is offline, reproducible, and replay-stable. The snapshot is
// intentionally small and curated (the high-value KEV entries and the common
// default-credential products), not an exhaustive feed - refresh it as a manual,
// reviewed edit of catalogue.json rather than an automated pull.
//
// [Default] loads and caches the bundled [Catalogue]. Consumers enrich findings
// with it: a CVE finding whose identifier is in the KEV snapshot is flagged
// known-exploited (and the risk model prioritises it), and a service whose product
// has a default-credential entry surfaces the candidate as a starting point for an
// authorized, gated credential check - never an unbounded brute force. Enrichment
// only attaches flags and references; it never runs anything.
package intel
