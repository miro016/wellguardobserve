// Package certs owns the orchestrator's certificate-transparency coverage logic.
//
// crt.sh is the crawler's sole certificate source, and it can answer imperfectly
// in two ways that a single reading cannot distinguish from a clean result:
//
//   - Silent partial: HTTP 200 with a truncated certificate set, so some subdomains
//     are dropped without any error.
//   - Degraded-empty: a clean HTTP 200 with no names at all while the backend is
//     degraded, indistinguishable from a target that genuinely has no certificates.
//
// Judging either case needs a second Certificate Transparency source (certspotter,
// and later a history source) to compare against. This package holds the pure
// decisions for that judgement plus the per-source name tracking they read:
//
//   - Coverage records the distinct names each discovery source contributed, so the
//     cross-check can compare crt.sh's count against the corroborator's.
//   - CrtshCoverageShortfall is the pure predicate the post-crawl cross-check uses to
//     decide whether crt.sh is materially below the corroborator.
//   - CertspotterInert is the pure predicate for the inverse gap: certspotter returned
//     nothing while crt.sh found names, so the cross-check ran but corroborated nothing.
//
// # Degraded-empty corroboration
//
// When crt.sh returns a degraded-empty for a query, the orchestrator consults up to
// two independent CT sources for that same query and hands their answers to Decide,
// the pure confirm-vs-downgrade core:
//
//   - LiveCertSource (certspotter) proves a cert exists right now but cannot see
//     history; HistoryCertSource (censys) indexes CT history and can corroborate a
//     host whose certs are all expired. The interfaces keep this package tool-agnostic:
//     the orchestrator adapts the tool clients to them and copies their results into
//     the plain Certs/CertMeta/SourceResult types here.
//   - Decide takes the count of sources actually consulted and their SourceResults and
//     returns a Verdict: NoCorroboration when no source was available, Confirmed when
//     any source saw a cert (High, with names/certs to backfill), or Downgraded when
//     every consulted source also saw nothing. A Downgraded empty is only authoritative
//     ("likely a real empty", Low) when a history source agreed; a live-only empty is
//     Medium and unconfirmed, since certspotter cannot see historical certs.
//   - History outranks live: when both are present, censys carries the decision and its
//     names/certs lead the backfill, because certspotter falsely agrees "empty" for a
//     host whose certs are all expired. The backfill union deduplicates names
//     case-insensitively and certs by fingerprint.
//
// Keeping the decision here means all certificate-completeness logic is unit-testable
// in one isolated place, with fakes for the sources.
//
// Retrieval provenance travels with the answers rather than being re-derived: Certs
// and SourceResult carry a RetrievalSource string ("service", "cache_embedded", or
// empty when the source does not state it), and a Confirmed verdict copies the
// deciding source's value onto Verdict.RetrievalSource. The orchestrator then stamps
// it on every name and certificate the verdict backfills, so a recovered observation
// records whether the data that recovered it came from a live provider request or a
// compiled-in fixture. It is a plain string because this package stays events-free.
//
// # The subsystem emits nothing
//
// The orchestrator stays the single translator from tool and system events into
// domain events, so this package must not publish events or build events.* values.
// It exposes pure decisions and plain data; the orchestrator keeps the wiring
// (state, budget, concurrency, publish, fan-out) and translates each returned value
// into events. Coverage is the one stateful type here, and it is self-synchronizing
// (its own mutex) so the orchestrator can Record into it from the emit hot path
// without holding its own lock and without nesting the two locks.
package certs
