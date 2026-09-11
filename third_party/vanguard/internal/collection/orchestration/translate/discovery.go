package translate

import (
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/certs"
	"github.com/velgard-sk/vanguard/internal/collection/orchestration/crawler"
)

// CrawlerEvent maps a crawler system event (a discovered domain name or
// certificate) to the matching domain event, or nil for an event that carries no
// discovery.
func CrawlerEvent(evt crawler.SystemEvent, scanID string) []events.DomainEvent {
	switch e := evt.(type) {
	case crawler.DomainNameFound:
		kind := events.ObservationKindHistoricalLog
		if e.ParentDomain == "" && e.Depth == 0 {
			kind = events.ObservationKindInput
		}
		d := events.DnsDomainNameDiscovered{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     e.ID(),
				Source:          SourceCrtsh,
				Phase:           events.PhasePassive,
				Category:        events.CategoryDiscovery,
				ObservationKind: kind,
				CapturedAt:      e.Timestamp,
				RetrievalSource: events.RetrievalSource(e.RetrievalSource),
			},
			Domain:          e.Domain,
			ParentDomain:    e.ParentDomain,
			Depth:           e.Depth,
			DiscoverySource: crawlerDomainSource(e),
		}
		d.EventID = events.NewEventID(e.Timestamp, d)
		return []events.DomainEvent{d}

	case *crawler.CertificateFound:
		c := events.CertificateDiscovered{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     e.ID(),
				Source:          SourceCrtsh,
				Phase:           events.PhasePassive,
				Category:        events.CategoryDiscovery,
				ObservationKind: events.ObservationKindHistoricalLog,
				CapturedAt:      e.Timestamp,
				RetrievalSource: events.RetrievalSource(e.RetrievalSource),
			},
			SearchQuery: e.SearchQuery,
			Certificate: events.CertificateData{
				CommonName:   e.Certificate.CommonName,
				IssuerName:   e.Certificate.IssuerName,
				SerialNumber: e.Certificate.SerialNumber,
				ValidFrom:    e.Certificate.NotBefore,
				ValidUntil:   e.Certificate.NotAfter,
				LoggedAt:     e.Certificate.EntryTimestamp,
				Domains:      append([]string(nil), e.Certificate.Domains...),
			},
		}
		c.EventID = events.NewEventID(e.Timestamp, c)
		return []events.DomainEvent{c}
	}
	return nil
}

// crawlerDomainSource classifies how the crawler discovered a domain from its
// parent linkage, so the discovery method is stamped on the event rather than
// re-derived downstream. It mirrors the read model's fallback heuristic.
func crawlerDomainSource(e crawler.DomainNameFound) string {
	switch {
	case e.ParentDomain == "":
		return events.DiscoverySourceRoot
	case e.Domain == e.ParentDomain || strings.HasSuffix(e.Domain, "."+e.ParentDomain):
		return events.DiscoverySourceCrtshSubdomain
	default:
		return events.DiscoverySourceCrtshCert
	}
}

// Subfinder maps a subfinder-discovered subdomain to a domain event, stamped with
// the subfinder discovery source. The root name itself is recorded as the root
// domain; everything else is a direct subdomain of the root.
func Subfinder(subdomain, root, scanID string) []events.DomainEvent {
	return passiveSubdomain(subdomain, root, scanID, SourceSubfinder, events.DiscoverySourceSubfinder, time.Time{})
}

// CertspotterSubdomain maps a certspotter-discovered subdomain to a domain event,
// stamped with the certspotter discovery source. It mirrors Subfinder: a
// root-level passive CT source feeding the discovery pipeline (and the crt.sh
// coverage cross-check).
func CertspotterSubdomain(subdomain, root, scanID string) []events.DomainEvent {
	return passiveSubdomain(subdomain, root, scanID, SourceCertspotter, events.DiscoverySourceCertspotter, time.Time{})
}

// CorroboratedSubdomain maps a name recovered by the degraded-empty CT corroboration
// to a domain event, stamped with the corroborating source (censys or certspotter).
// It backfills a name a degraded crt.sh empty lost, so it re-enters the same
// discovery fan-out as any passively-enumerated subdomain. source is the EventMeta
// source label; the discovery source mirrors it.
func CorroboratedSubdomain(subdomain, root, source, scanID string, retrieval events.RetrievalSource) []events.DomainEvent {
	return passiveSubdomainFrom(subdomain, root, scanID, source, discoverySourceFor(source), time.Time{}, retrieval)
}

// discoverySourceFor maps a corroboration source label to its DiscoverySource. An
// unrecognized label passes through verbatim rather than being dropped.
func discoverySourceFor(source string) string {
	switch source {
	case SourceCensys:
		return events.DiscoverySourceCensys
	case SourceCertspotter:
		return events.DiscoverySourceCertspotter
	default:
		return source
	}
}

// CorroboratedCertificate maps a certificate recovered by the degraded-empty CT
// corroboration to a CertificateDiscovered, stamped with the corroborating source, so
// a degraded crt.sh empty repopulates the certificate inventory it left blank. query
// is the degraded query the certificate was recovered for; corrID joins the event back
// to the corroborating tool call.
func CorroboratedCertificate(cert certs.CertMeta, query, source, scanID, corrID string, retrieval events.RetrievalSource) []events.DomainEvent {
	now := time.Now()
	c := events.CertificateDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			Source:          source,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindHistoricalLog,
			CapturedAt:      now,
			ToolCorrID:      corrID,
			RetrievalSource: retrieval,
		},
		SearchQuery: query,
		Certificate: events.CertificateData{
			CommonName:   cert.CommonName,
			IssuerName:   cert.IssuerDN,
			SerialNumber: cert.SerialNumber,
			ValidFrom:    cert.NotBefore,
			ValidUntil:   cert.NotAfter,
			Domains:      append([]string(nil), cert.Names...),
		},
	}
	c.EventID = events.NewEventID(now, c)
	return []events.DomainEvent{c}
}

// VirustotalSubdomain maps a VirusTotal-discovered subdomain to a domain event,
// stamped with the virustotal discovery source. It mirrors Subfinder: both are
// root-level passive subdomain sources that differ only in the source label, except
// VirusTotal also reports a source observation time for the name. It is carried onto
// the event separately from the time Vanguard captured the event, and is zero when
// unknown.
func VirustotalSubdomain(subdomain, root, scanID string, sourceObservedAt time.Time) []events.DomainEvent {
	return passiveSubdomain(subdomain, root, scanID, SourceVirustotal, events.DiscoverySourceVirustotal, sourceObservedAt)
}

// WebsearchHost maps an in-scope host found in a web-search result to a domain
// event, stamped with the websearch discovery source. It mirrors Subfinder: a
// root-level passive source feeding the discovery pipeline.
func WebsearchHost(host, root, scanID string) []events.DomainEvent {
	return passiveSubdomain(host, root, scanID, SourceWebsearch, events.DiscoverySourceWebsearch, time.Time{})
}

// passiveSubdomain builds a DnsDomainNameDiscovered for a subdomain found by a
// root-level passive enumeration source (subfinder, virustotal). The root name
// itself is recorded as the root domain; everything else is a direct subdomain of
// the root. source is the EventMeta.Source label and subSource the DiscoverySource
// stamped on the event. sourceObservedAt is the source's own real-world timestamp
// (VirusTotal), or the zero time when the source carries none.
func passiveSubdomain(subdomain, root, scanID, source, subSource string, sourceObservedAt time.Time) []events.DomainEvent {
	return passiveSubdomainFrom(subdomain, root, scanID, source, subSource, sourceObservedAt, "")
}

// passiveSubdomainFrom is passiveSubdomain with an explicit retrieval source, for the
// corroboration path where the deciding data may have come from the embedded fixture.
// The plain passiveSubdomain leaves the field empty: its callers are service-only
// tools that have not adopted retrieval provenance, and empty means "not stated".
func passiveSubdomainFrom(subdomain, root, scanID, source, subSource string, sourceObservedAt time.Time, retrieval events.RetrievalSource) []events.DomainEvent {
	if !sourceObservedAt.IsZero() {
		sourceObservedAt = sourceObservedAt.UTC()
	}
	parent := root
	discoverySource := subSource
	depth := 1
	if subdomain == root {
		parent = ""
		discoverySource = events.DiscoverySourceRoot
		depth = 0
	}
	now := time.Now()
	kind := events.ObservationKindPassiveSnapshot
	if source == SourceCertspotter || source == SourceCensys {
		kind = events.ObservationKindHistoricalLog
	}
	d := events.DnsDomainNameDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			Source:          source,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: kind,
			CapturedAt:      now,
			RetrievalSource: retrieval,
		},
		Domain:           subdomain,
		ParentDomain:     parent,
		Depth:            depth,
		DiscoverySource:  discoverySource,
		SourceObservedAt: sourceObservedAt,
	}
	d.EventID = events.NewEventID(now, d)
	return []events.DomainEvent{d}
}
