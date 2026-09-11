package findings

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// DMARC severity labels the mailsec tool assigns to a domain's DMARC posture.
// They mirror entities.MailSecurity.DMARCSeverity grading.
const (
	dmarcMissing = "critical" // no DMARC record published
	dmarcNone    = "warning"  // p=none (monitor only, no enforcement)
)

// cweEmailSpoofing is CWE-290 (Authentication Bypass by Spoofing): the weakness
// class shared by every mail-authentication gap raised here.
const cweEmailSpoofing = "CWE-290"

// MailSecurity raises findings for weak email-authentication posture: missing or
// unenforced DMARC, and SPF that is missing, over the lookup limit, duplicated,
// pass-all, or neutral. These let an attacker spoof mail from the domain, so they
// are among the highest-value passive findings.
//
// Findings are gated on the domain showing any mail intent: it publishes MX,
// SPF, DMARC, or DKIM records. MX alone is not enough to gate on, because the MX
// lookup can transiently fail (it timed out for vissim.no, a live O365 mail
// domain, yielding MXCount 0) and suppressing a real finding on a lookup gap
// would hide data - the opposite of the goal. A domain that publishes any
// mail-authentication record is asserting a mail identity and is spoofable, so
// weak posture there is a real finding. A bare subdomain with none of these
// (e.g. www.*) inherits the organizational policy and is not flagged.
func MailSecurity(evt events.DomainEvent) []events.FindingRaised {
	m, ok := evt.(events.MailSecurityDiscovered)
	if !ok {
		return nil
	}
	mailUsed := m.MXCount > 0 || m.SPF != "" || m.DMARC != "" || len(m.DKIM) > 0
	if !mailUsed {
		return nil
	}

	var out []events.FindingRaised

	switch m.DMARCSeverity {
	case dmarcMissing:
		f := events.FindingRaised{
			Rule:            "dmarc-missing",
			Title:           "DMARC not configured",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        fmt.Sprintf("%s is used for mail but publishes no DMARC record, so spoofed mail from the domain is not rejected", m.Domain),
			Recommendation:  "Publish a DMARC record and move to an enforcing policy (p=quarantine, then p=reject).",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityMedium
		out = append(out, f)
	case dmarcNone:
		f := events.FindingRaised{
			Rule:            "dmarc-policy-none",
			Title:           "DMARC policy is monitoring-only (p=none)",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        fmt.Sprintf("%s publishes DMARC with p=none, which only reports and does not block spoofed mail", m.Domain),
			Recommendation:  "Tighten the DMARC policy to p=quarantine or p=reject once reports look clean.",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityLow
		out = append(out, f)
	}

	return append(out, spfFindings(m)...)
}

// spfFindings evaluates the domain SPF posture in one fixed order, so two SPF
// weaknesses never contradict each other in the same report.
//
// A missing record ends the evaluation: there is no policy to judge. More than one
// published record ends it too, and for a stronger reason - receivers must treat
// multiple SPF records as a permanent error, so the record Vanguard happens to have
// stored is merely the first invalid one, and describing its terminal policy would
// describe a policy that is not in force.
//
// On a single valid record the lookup limit and the terminal policy are independent
// weaknesses and may both be raised: a record can be both unresolvable and
// permissive, and reporting only one of them would leave the other unfixed.
func spfFindings(m events.MailSecurityDiscovered) []events.FindingRaised {
	if m.SPF == "" {
		f := events.FindingRaised{
			Rule:            "spf-missing",
			Title:           "SPF record not published",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        fmt.Sprintf("%s is used for mail but publishes no SPF record, so receivers cannot tell which hosts may send for it", m.Domain),
			Recommendation:  "Publish an SPF record listing the authorized senders and ending in -all.",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityLow
		return []events.FindingRaised{f}
	}

	if m.SPFAnalysis != nil && m.SPFAnalysis.Multiple {
		f := events.FindingRaised{
			Rule:            "spf-multiple-records",
			Title:           "Multiple SPF records invalidate the policy",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        multipleSPFEvidence(m.Domain, len(m.SPFAnalysis.Records)),
			Recommendation:  "Consolidate every authorized sender and mechanism into a single SPF TXT record, keeping it within the 10-lookup limit.",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityMedium
		return []events.FindingRaised{f}
	}

	var out []events.FindingRaised
	if m.SPFAnalysis != nil && m.SPFAnalysis.OverLimit {
		f := events.FindingRaised{
			Rule:            "spf-over-limit",
			Title:           "SPF exceeds the 10-lookup limit",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        fmt.Sprintf("the SPF record for %s needs %d DNS lookups, over the RFC 7208 limit of %d, so it fails validation (permerror)", m.Domain, m.SPFAnalysis.LookupCount, m.SPFAnalysis.LookupLimit),
			Recommendation:  "Flatten or consolidate SPF includes so the record resolves within 10 DNS lookups.",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityMedium
		out = append(out, f)
	}

	// The terminal policy is read from the stored record itself, so it needs no
	// analysis block: a domain whose SPF was never analyzed still gets the finding.
	policy := classifySPFPolicy(m.SPF)
	switch policy {
	case spfPassAll:
		f := events.FindingRaised{
			Rule:            "spf-pass-all",
			Title:           "SPF authorizes every sender",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        fmt.Sprintf("the SPF record for %s reaches %s, a pass-all fallback, so any host on the internet passes SPF for the domain", m.Domain, passAllToken(m.SPF)),
			Recommendation:  "Replace the pass-all fallback with an explicit list of authorized senders and an intentional terminal qualifier, moving to -all once the listed senders are validated.",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityMedium
		out = append(out, f)
	case spfNeutralAll, spfImplicitNeutral:
		f := events.FindingRaised{
			Rule:            "spf-neutral-policy",
			Title:           "SPF policy has a neutral fallback",
			FindingCategory: string(entities.FindingDNS),
			AssetKind:       assetDomain,
			AssetID:         m.Domain,
			Evidence:        neutralSPFEvidence(m.Domain, policy),
			Recommendation:  "Enumerate the authorized senders and choose an intentional terminal policy, validating mail flows before enforcing -all.",
			References:      []string{cweEmailSpoofing},
		}
		f.Severity = events.SeverityLow
		out = append(out, f)
	case spfUnknown, spfFailAll, spfSoftFailAll, spfRedirected:
		// -all and ~all are intentional policies, a redirect delegates the decision to
		// a domain this rule does not resolve, and an unparsable record is not evidence
		// of a weak policy. None of them is a finding here.
	}
	return out
}

// multipleSPFEvidence states how many records were persisted when the analyzer
// recorded them, and falls back to the plain fact when it did not. The count comes
// from the stored analysis, never from parsing an error message.
func multipleSPFEvidence(domain string, records int) string {
	if records > 1 {
		return fmt.Sprintf("%s publishes %d SPF records; RFC 7208 permits one, so receivers must treat SPF evaluation for the domain as a permanent error (permerror) rather than picking one", domain, records)
	}
	return fmt.Sprintf("%s publishes more than one SPF record, so receivers must treat SPF evaluation for the domain as a permanent error (permerror) rather than picking one", domain)
}

// neutralSPFEvidence distinguishes the neutral a domain wrote from the neutral it
// fell into. Neither says mail is accepted or rejected: SPF simply makes no
// authorization statement about a sender it does not list.
func neutralSPFEvidence(domain string, policy spfPolicy) string {
	if policy == spfNeutralAll {
		return fmt.Sprintf("the SPF record for %s ends in ?all, an explicit neutral fallback, so SPF makes no authorization decision about any sender it does not list", domain)
	}
	return fmt.Sprintf("the SPF record for %s lists senders but has no all mechanism and no redirect, so evaluation falls through to the default neutral result and SPF makes no authorization decision about any sender it does not list", domain)
}

// passAllToken names the spelling of the pass-all fallback the record used, so the
// remediation points at the token to change without reprinting the whole record.
func passAllToken(record string) string {
	for _, term := range strings.Fields(record) {
		if strings.EqualFold(term, "all") {
			return "a bare all"
		}
		if strings.EqualFold(term, "+all") {
			return "+all"
		}
	}
	return "a pass-all fallback"
}
