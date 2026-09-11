// Package dataquality compares what the different data providers reported for one
// scanned customer, so an engineer can judge which sources are worth their cost
// and where they agree or conflict. It is the read-only content half of the
// provider data-quality analyzer.
//
// # Why a raw-stream comparison
//
// The domain-event projection (internal/projections) collapses per-provider
// data: when dnsinfo and censys both report addresses for a name, the inventory
// keeps the merged result, not who said what. Data quality needs the opposite:
// per provider, per comparable field, the exact values each one contributed. So
// this package folds the raw event stream ([]events.DomainEvent) directly, keyed
// by the producing tool (events.EventMeta.Source), rather than reusing a read
// model that has already merged the sources.
//
// # Comparable fields
//
// A small, explicit registry (fields.go) names the comparable fields, each with an
// extractor that walks the stream into observations: target key (domain or IP) ->
// provider -> the set of normalised values it reported. Two field kinds exist:
//
//   - presence fields (subdomains): the key is itself the value; coverage is "did
//     this provider find this name", and there is no notion of conflict. This is
//     where the certificate-transparency cross-check surfaces: crtsh and the
//     certspotter second CT source both stamp DnsDomainNameDiscovered, so their
//     per-provider subdomain coverage sits side by side here. (The orchestrator
//     also raises a coverage IssueObserved during the scan when crt.sh's count is
//     materially short of certspotter's - a likely truncated crt.sh response - so a
//     silent partial answer is visible in the report, not just this comparison.)
//   - valued fields (addresses, services, nameservers, registrar, web
//     technologies): the key carries
//     a set of values, so the providers on a key are classified three ways - agree
//     (identical sets), coverage gap (nested sets: one provider saw more than another,
//     a scope difference), or conflict (two providers each hold a value the other
//     lacks, a genuine disagreement). Separating coverage gaps from conflicts keeps
//     the conflict count an accuracy signal rather than a methodology artifact: an
//     18-port active portscan structurally reports a subset of a full-range passive
//     provider, which is a coverage gap, not a disagreement. A service value carries
//     its transport, and a provider that reported a port without naming one compares
//     as "port/unknown". Folding it into "port/tcp" would score agreement between a
//     provider that said nothing and a scan that said tcp, which is a manufactured
//     agreement rather than an observed one.
//
// The web-technologies field is keyed by normalised endpoint URL and compares
// wappalyzer with webinfo. httpprobe is excluded because it probes IP URLs without
// domain Host/SNI identity, so its response is not the same virtual host. Everywhere
// else fingerprints merge into one technology list; this field preserves provider
// overlap for quality analysis. A versioned observation contributes bare product and
// exact version, so bare-vs-version is a coverage gap while different exact versions
// remain a conflict. Categories and CPEs are metadata, not comparison identity.
//
// Product identity comes from
// [github.com/velgard-sk/vanguard/internal/valueobjects.NormalizeTechnology] -
// the same decision the inventory merge and the facts asset key use, including the
// capture-proven aliases that reconcile IIS, ARR, ASP.NET, and Apache spellings. It
// used to be a private copy here, which is how this report could show clean agreement
// on the very endpoints the operator report showed duplicated: two answers to one
// question. Any new alias belongs in the shared normalizer, never here.
//
// # What is computed
//
// For each field (compare.go): per-provider coverage and unique contribution, the
// count of keys where providers agree, the coverage-gap keys (nested value-sets), and
// the concrete conflicts (key plus the values each provider gave) for an analyst to
// adjudicate. A transparent,
// printed-weights efficiency score (score.go) combines coverage, unique
// contribution, and operational reliability so the "keep paying for this provider?"
// decision is explainable rather than a black box.
//
// # Operational input
//
// The operational half (latency, failed calls, empties) lives in the tool-event
// stream (internal/collection/tooleventlog). To stay dependency-free over the event
// types alone, this
// package accepts a small OpStats input (op.go) that the app layer fills from the
// tooleventlog read model; it degrades gracefully when that stream is absent.
//
// The reliability term is built from the failed-call rate, not the event error
// rate: an active probe that fails to connect (port scan reaching nothing, https
// negotiating no TLS, smtp where no MX completes STARTTLS) logs its failure at
// warn, not error, so an error-rate term scored such a provider a perfect 1.0
// while it produced no data. ProviderOps.Reliability prefers FailedCalls over
// available calls and falls back to the error rate only when no call was correlated
// (older streams).
//
// A call has one of three outcomes, so reliability measures the provider, not the
// target:
//   - Failed - a transport/protocol error, or an active probe that connected to
//     nothing (an all-zero connectivity count). Counts against reliability.
//   - Empty-but-valid - a passive search that answered cleanly with zero results
//     (the target simply has no such data). Surfaced as Empties; not a failure.
//   - Unavailable - the provider declined to serve (paid plan, auth refusal,
//     membership wall, or rate-limit). Excluded from both the failed count and the
//     reliability denominator; when every call was unavailable, Reliability is
//     undefined and renders "n/a" rather than 0%.
package dataquality
