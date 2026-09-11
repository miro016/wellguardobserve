package certs

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// LiveCertSource reports whether a live (currently-valid) certificate exists for a
// query. certspotter implements it: its free tier serves only currently-valid certs,
// so it can prove "a cert exists right now" but not "a cert ever existed". The
// orchestrator adapts *certspotter.Client to this interface in the wiring step; a nil
// source is simply not consulted.
//
// present is true when any issuance was returned before the in-scope name filter, so
// a host serving a live wildcard whose SANs are all out of scope still reports
// present==true with empty names.
type LiveCertSource interface {
	Certs(ctx context.Context, domain string) (names []string, present bool, err error)
}

// HistoryCertSource reports Certificate Transparency history for a query: presence,
// the in-scope names, and per-cert metadata for backfill. censys implements it (it
// indexes CT history independently of crt.sh's Sectigo backend), which is why it can
// corroborate a degraded-empty for a host whose certs are all historical - the case a
// LiveCertSource cannot see. The orchestrator adapts *censys.Client to this interface
// in the wiring step; a nil source is simply not consulted.
type HistoryCertSource interface {
	Certificates(ctx context.Context, domain string) (*Certs, error)
}

// Certs is the tool-agnostic result a HistoryCertSource returns for a query. It is a
// plain data mirror of censys's DomainCertificates so this package does not import the
// tool package: the orchestrator's adapter copies the censys result into it.
type Certs struct {
	// Present is true when the source saw any certificate for the query, before the
	// in-scope name filter.
	Present bool
	// Names are the distinct in-scope names (SANs) across all certificates.
	Names []string
	// Certs is the per-certificate metadata needed to backfill CertificateDiscovered.
	Certs []CertMeta
	// RetrievalSource states how the source obtained this answer: "service" for a
	// provider request made during this scan, "cache_embedded" for data compiled into
	// the tool. It is empty for a source that does not state it. This package only
	// carries the value; the orchestrator maps it onto the backfilled events.
	RetrievalSource string
}

// CertMeta is the plain per-certificate metadata a verdict hands back so the
// orchestrator can translate it into a CertificateDiscovered event when backfilling a
// degraded-empty. It carries only the fields that event needs, not the whole SDK
// certificate.
type CertMeta struct {
	// FingerprintSHA256 is the certificate's SHA-256 fingerprint. It is the identity
	// used to de-duplicate certs seen by more than one source.
	FingerprintSHA256 string
	// Names are the certificate's subject alternative names (SANs).
	Names []string
	// CommonName is the subject common name.
	CommonName string
	// IssuerDN is the issuer distinguished name.
	IssuerDN string
	// SerialNumber is the certificate serial number.
	SerialNumber string
	// NotBefore is the start of the validity period. Zero if the source omitted it.
	NotBefore time.Time
	// NotAfter is the end of the validity period. Zero if the source omitted it.
	NotAfter time.Time
}

// SourceResult is one consulted second-source's answer for a degraded query, as the
// orchestrator gathered it before calling Decide. The orchestrator builds one per
// source that actually returned (an errored source is not consulted, so it produces no
// SourceResult and is excluded from the consulted count).
type SourceResult struct {
	// Source is the source label ("censys", "certspotter"), used in the verdict
	// message and as backfill provenance.
	Source string
	// History marks a result from a HistoryCertSource (censys's CT index). History
	// outranks live: when both a history and a live source are present, the history
	// source carries the decision and its names/certs lead the backfill, because a
	// live source only sees currently-valid certs and can falsely agree "empty" for a
	// host whose certs are all expired.
	History bool
	// Present is true when the source saw any certificate for the query.
	Present bool
	// Names are the distinct in-scope names the source contributed.
	Names []string
	// Certs is the per-certificate metadata the source contributed. It is empty for a
	// live source, which reports presence and names but no metadata.
	Certs []CertMeta
	// RetrievalSource is how this source obtained its answer ("service",
	// "cache_embedded", or empty when the source does not state it). The verdict
	// carries the deciding source's value so a backfilled name or certificate records
	// how the data that recovered it was obtained.
	RetrievalSource string
}

// Outcome is the class of a Verdict.
type Outcome int

const (
	// NoCorroboration means no second source was available to consult. The
	// orchestrator keeps its own generic issue for this case.
	NoCorroboration Outcome = iota
	// Confirmed means at least one consulted source saw a certificate, proving crt.sh's
	// empty was a degradation and not a real empty.
	Confirmed
	// Downgraded means every consulted source also saw nothing. The severity carries the
	// authority of that agreement: Low ("likely a real empty") when a history source
	// agreed, Medium ("unconfirmed") when only a live source did.
	Downgraded
)

// Severity ranks a verdict's issue without importing the domain events package, so
// this package stays events-free. The orchestrator maps these to events.Severity in
// the wiring step. Ordered constants allow numeric comparison.
type Severity int

const (
	// SeverityLow marks a downgraded verdict: a second CT source also saw nothing, so
	// the degraded-empty is likely a real empty.
	SeverityLow Severity = iota
	// SeverityMedium marks an unconfirmed verdict: a degraded-empty that either no source
	// could corroborate (none available) or that only a live source agreed was empty (not
	// authoritative). The live-only case carries its own message; the no-source case lets
	// the orchestrator fall back to its generic issue.
	SeverityMedium
	// SeverityHigh marks a confirmed verdict: a second CT source found certs/names
	// crt.sh missed, proving the empty was a degradation.
	SeverityHigh
)

// Verdict is the pure decision for a degraded crt.sh empty: what the consulted second
// sources concluded, the severity and message to raise, and the names/certs to
// backfill. It builds no events.* values; the orchestrator translates it.
type Verdict struct {
	// Outcome is the class of the decision.
	Outcome Outcome
	// Severity is the local severity for the raised issue.
	Severity Severity
	// Message is the human-readable issue detail. It is deliberately query-free: the
	// query is carried separately on the orchestrator's IssueObserved. Empty for
	// NoCorroboration, where the orchestrator keeps its own generic message.
	Message string
	// Names are the distinct names to backfill (deduplicated case-insensitively across
	// present sources, history first). Empty unless Confirmed.
	Names []string
	// Certs are the certificates to backfill (deduplicated by fingerprint across
	// present sources, history first). Empty unless Confirmed, and only history
	// sources contribute metadata.
	Certs []CertMeta
	// ConfirmedBy is the label of the deciding source. Empty unless Confirmed. When
	// both a history and a live source are present, it is the history source.
	ConfirmedBy string
	// RetrievalSource is the deciding source's RetrievalSource, so the backfilled
	// names and certificates record whether the data that recovered them came from
	// the provider or from a compiled-in fixture. Empty unless Confirmed, or when the
	// deciding source does not state it.
	RetrievalSource string
}

// Decide maps consulted second-source results to a verdict for a degraded crt.sh
// empty. It is pure: no I/O, no events, deterministic in its inputs.
//
// consulted is the number of sources that were actually reachable and returned (an
// errored source is not counted and contributes no SourceResult). results holds those
// answers. The rules:
//
//   - consulted == 0: NoCorroboration - no second source was available.
//   - any result Present: Confirmed - a second source saw a cert crt.sh missed. High
//     severity; ConfirmedBy is the strongest present source (history outranks live);
//     Names/Certs are unioned from the present sources, history leading.
//   - all consulted results empty: Downgraded. The severity reflects the authority of
//     the agreement - Low ("likely a real empty") when a history source (censys) is among
//     the empties, Medium ("unconfirmed") when only a live source (certspotter) agreed,
//     since a live source cannot see historical certs and its empty is not authoritative.
func Decide(consulted int, results []SourceResult) Verdict {
	if consulted == 0 {
		return Verdict{Outcome: NoCorroboration, Severity: SeverityMedium}
	}

	var present []SourceResult
	for _, r := range results {
		if r.Present {
			present = append(present, r)
		}
	}

	if len(present) == 0 {
		// Every consulted source came back empty. Only a HISTORY source (censys) can
		// prove a real empty: it indexes CT history, so its empty means "no cert ever
		// issued". A LIVE source (certspotter) sees only currently-valid certs, so its
		// empty is not authoritative - a host whose certs are all historical or expired
		// reads empty to it, and the keyless tier also empties under rate limits.
		// Downgrade to "likely a real empty" only when a history source agreed; a
		// live-only empty stays Medium and unconfirmed, which matches (rather than
		// contradicts) the coverage cross-check that flags the same certspotter empty as
		// inert.
		if anyHistory(results) {
			return Verdict{
				Outcome:  Downgraded,
				Severity: SeverityLow,
				Message:  downgradeMessage(results),
			}
		}
		return Verdict{
			Outcome:  Downgraded,
			Severity: SeverityMedium,
			Message:  unconfirmedMessage(results),
		}
	}

	deciding := strongestPresent(present)
	names, certs := unionBackfill(present)
	return Verdict{
		Outcome:         Confirmed,
		Severity:        SeverityHigh,
		Message:         fmt.Sprintf("crt.sh degraded-empty CONFIRMED by %s: found %d cert-name(s)", deciding.Source, len(names)),
		Names:           names,
		Certs:           certs,
		ConfirmedBy:     deciding.Source,
		RetrievalSource: deciding.RetrievalSource,
	}
}

// strongestPresent returns the deciding source among the present ones: a history
// source if any is present (history is authoritative), otherwise the first present
// live source. present must be non-empty. The whole result is returned, not just its
// label, so the verdict can also carry how that source obtained its answer.
func strongestPresent(present []SourceResult) SourceResult {
	for _, r := range present {
		if r.History {
			return r
		}
	}
	return present[0]
}

// unionBackfill unions the names and certs of the present sources, history sources
// first so their data leads the backfill. Names are deduplicated case-insensitively
// (first casing wins); certs are deduplicated by fingerprint (a cert with an empty
// fingerprint cannot be deduplicated and is kept).
func unionBackfill(present []SourceResult) ([]string, []CertMeta) {
	ordered := make([]SourceResult, 0, len(present))
	for _, r := range present {
		if r.History {
			ordered = append(ordered, r)
		}
	}
	for _, r := range present {
		if !r.History {
			ordered = append(ordered, r)
		}
	}

	var names []string
	seenName := make(map[string]bool)
	var certs []CertMeta
	seenFP := make(map[string]bool)
	for _, r := range ordered {
		for _, n := range r.Names {
			key := strings.ToLower(n)
			if key == "" || seenName[key] {
				continue
			}
			seenName[key] = true
			names = append(names, n)
		}
		for _, c := range r.Certs {
			fp := strings.ToLower(c.FingerprintSHA256)
			if fp != "" {
				if seenFP[fp] {
					continue
				}
				seenFP[fp] = true
			}
			certs = append(certs, c)
		}
	}
	return names, certs
}

// anyHistory reports whether any consulted result came from a history source (censys).
// A history source's empty is authoritative for "a real empty"; a live source's is not.
func anyHistory(results []SourceResult) bool {
	for _, r := range results {
		if r.History {
			return true
		}
	}
	return false
}

// unconfirmedMessage names the live sources that agreed empty when no authoritative
// history source was consulted, so the raised issue is honest that the degraded-empty is
// unconfirmed rather than presenting it as a likely real empty.
func unconfirmedMessage(results []SourceResult) string {
	labels := make([]string, 0, len(results))
	for _, r := range results {
		labels = append(labels, r.Source)
	}
	return fmt.Sprintf("crt.sh degraded-empty unconfirmed: only live CT source(s) (%s) agreed empty, which cannot see historical certs", strings.Join(labels, " + "))
}

// downgradeMessage names crt.sh and every consulted source so the raised issue makes
// the agreement auditable ("all CT sources (crt.sh + censys + certspotter) empty ...").
func downgradeMessage(results []SourceResult) string {
	labels := make([]string, 0, len(results)+1)
	labels = append(labels, "crt.sh")
	for _, r := range results {
		labels = append(labels, r.Source)
	}
	return fmt.Sprintf("all CT sources (%s) empty, likely a real empty", strings.Join(labels, " + "))
}
