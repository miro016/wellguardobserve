package facts

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// applyRegistration folds a DomainRegistrationDiscovered event onto the domain as a
// registration_observed fact (registrar, lifecycle dates, nameservers as metadata).
func (g *Graph) applyRegistration(e events.DomainRegistrationDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	// WHOIS/RDAP creation and expiry form the domain's authoritative registration
	// lifecycle. The min/max fold combines this window with certificate and provider
	// observations while scan time remains on the observation.
	if !e.CreatedDate.IsZero() || !e.ExpiryDate.IsZero() {
		firstSeen, lastSeen := g.realSeenWindow(m, "domain "+domain+" registration", e.CreatedDate, e.ExpiryDate)
		g.upsertAssetClaim(Asset{Type: assetTypeFor(domain, g.rootTarget), Key: domain,
			FirstSeen: firstSeen, LastSeen: lastSeen},
			claim{ValidFrom: e.CreatedDate, ValidUntil: e.ExpiryDate, Confidence: ConfidenceHigh})
	}
	md := map[string]any{"registrar": e.Registrar, "data_source": e.DataSource, "dnssec": e.DNSSEC}
	if !e.CreatedDate.IsZero() {
		md["created"] = e.CreatedDate
	}
	if !e.ExpiryDate.IsZero() {
		md["expiry"] = e.ExpiryDate
	}
	if len(e.Nameservers) > 0 {
		md["nameservers"] = e.Nameservers
	}
	if len(e.Status) > 0 {
		md["status"] = e.Status
	}
	g.addObsEvidence(m, domain, "registration_observed", "registration_evidence", "registration:"+domain,
		fmt.Sprintf("%s reported registration for %s (registrar %s).", m.Source, domain, e.Registrar),
		ConfidenceHigh, md)
}

// applyMailSecurity folds a MailSecurityDiscovered event onto the domain as a
// mail_security_observed fact (SPF presence, DMARC grade, DKIM/MX counts as metadata).
func (g *Graph) applyMailSecurity(e events.MailSecurityDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	g.addObsEvidence(m, domain, "mail_security_observed", "mail_security_evidence", "mailsec:"+domain,
		fmt.Sprintf("%s reported mail security for %s (DMARC %s).", m.Source, domain, e.DMARCSeverity),
		ConfidenceHigh, map[string]any{"has_spf": e.SPF != "", "dmarc_severity": e.DMARCSeverity,
			"dkim_selectors": len(e.DKIM), "mx_count": e.MXCount})
}

// applyReputation folds a DomainReputationDiscovered event onto the domain as a
// reputation_observed fact (community score, malicious/suspicious counts, tags).
func (g *Graph) applyReputation(e events.DomainReputationDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	md := map[string]any{"reputation": e.Reputation, "malicious": e.Malicious, "suspicious": e.Suspicious}
	if len(e.Tags) > 0 {
		md["tags"] = e.Tags
	}
	g.addObsEvidence(m, domain, "reputation_observed", "reputation_evidence", "reputation:"+domain,
		fmt.Sprintf("%s reported reputation for %s (score %d, %d malicious).",
			m.Source, domain, e.Reputation, e.Malicious), ConfidenceMedium, md)
}

// applyBreach folds a BreachDataDiscovered event onto the domain as a breach_data_observed
// fact. Only the alias count is recorded; the breached addresses (PII) are not copied into
// the externalizable graph.
func (g *Graph) applyBreach(e events.BreachDataDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain == "" {
		return
	}
	g.ensureDomain(m, domain)
	g.addObsEvidence(m, domain, "breach_data_observed", "breach_data_evidence", "breach:"+domain,
		fmt.Sprintf("%s reported %d exposed alias(es) on %s.", m.Source, len(e.Breaches), domain),
		ConfidenceMedium, map[string]any{"alias_count": len(e.Breaches)})
}

// applyMxTLS folds an MxTlsDiscovered event: each MX host as a MailService asset with its
// STARTTLS posture recorded as an observation.
func (g *Graph) applyMxTLS(e events.MxTlsDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain != "" {
		g.ensureDomain(m, domain)
	}
	for _, h := range e.Hosts {
		host := normalizeFQDN(h.Host)
		if host == "" {
			continue
		}
		g.upsertAsset(Asset{Type: AssetMailService, Key: host, Attributes: map[string]any{attrHost: host},
			FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
		currentness := liveVerifiedCurrentness(m.ObservationKind, h.Error == "")
		g.addObsEvidenceWithCurrentness(m, host, "mx_tls_observed", "mx_tls_evidence", "mxtls:"+host,
			fmt.Sprintf("%s probed STARTTLS on %s (supported: %t).", m.Source, host, h.StartTLSSupported),
			ConfidenceHigh, currentness, map[string]any{"starttls": h.StartTLSSupported,
				"tls_version": h.TLSVersion, "error": h.Error, attrPriority: h.Priority})
	}
}

// applyWebAssets folds a WebAssetsDiscovered event: each dork hit as an Endpoint asset
// with the dork and its exposure category.
func (g *Graph) applyWebAssets(e events.WebAssetsDiscovered) {
	m := e.Meta()
	domain := normalizeFQDN(e.Domain)
	if domain != "" {
		g.ensureDomain(m, domain)
	}
	for _, a := range e.Assets {
		if strings.TrimSpace(a.URL) == "" {
			continue
		}
		url, err := entities.EndpointID(a.URL)
		if err != nil {
			g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
				Message: fmt.Sprintf("invalid web asset URL %q: %s", a.URL, err), RawEventID: m.EventID})
			continue
		}
		host, hostType, hostVersion, ok := httpURLHost(url, g.rootTarget)
		if !ok {
			g.addIssue(Issue{Type: issueQuarantine, Source: m.Source, Severity: events.SeverityLow,
				Message: fmt.Sprintf("web asset URL %q has no materializable host", a.URL), RawEventID: m.EventID})
			continue
		}
		g.upsertAsset(Asset{Type: AssetEndpoint, Key: url,
			Attributes: map[string]any{attrURL: url, "category": a.Category, "dork": a.Dork},
			FirstSeen:  m.CapturedAt, LastSeen: m.CapturedAt, Sources: srcs(m.Source)})
		// A search-engine hit is not a response Vanguard saw, so the host gets a
		// no-subject-time reference and the edge stays medium/passive. The edge itself is
		// still sound: the URL's authority names that host by construction.
		g.upsertAssetClaim(Asset{Type: hostType, Key: host,
			Attributes: hostAssetAttributes(host, hostVersion), Sources: srcs(m.Source)},
			claim{NoSubjectTime: true})
		disc := "webasset:" + url
		g.addObsEvidence(m, url, "web_asset_observed", "web_asset_evidence", disc,
			fmt.Sprintf("%s surfaced %s via a %s dork.", m.Source, url, a.Category), ConfidenceMedium,
			map[string]any{"category": a.Category, "dork": a.Dork, attrQueryDomain: domain})
		g.upsertRelationshipClaim(Relationship{Type: RelServesEndpoint, From: host, To: url,
			EvidenceID: evID(m.EventID, disc), Confidence: ConfidenceMedium, Mode: m.Phase,
			SourceEventID: m.EventID, FirstSeen: m.CapturedAt, LastSeen: m.CapturedAt},
			claim{NoSubjectTime: true})
	}
}
