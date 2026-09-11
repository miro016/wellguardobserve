package translate

import (
	"net"
	"sort"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/asn"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/breach"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/censys"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/dnsinfo"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/mailsec"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/netlas"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/shodan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/virustotal"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/websearch"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/whois"
	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// DnsRecords maps a *dnsinfo.Records result to domain events. causationID is the
// DnsDomainNameDiscovered event ID that triggered the lookup.
func DnsRecords(records *dnsinfo.Records, scanID, causationID, corrID string) []events.DomainEvent {
	if records == nil {
		return nil
	}

	var mx []valueobjects.MXRecord
	for _, m := range records.MX {
		mx = append(mx, valueobjects.MXRecord{Host: m.Host, Priority: m.Priority})
	}
	var ptr []valueobjects.PTRRecord
	for _, p := range records.PTR {
		ptr = append(ptr, valueobjects.PTRRecord{IP: p.IP, Hostname: p.Hostname})
	}
	var soa *valueobjects.SOARecord
	if records.SOA != nil {
		soa = &valueobjects.SOARecord{
			PrimaryNS:  records.SOA.PrimaryNS,
			AdminEmail: records.SOA.AdminEmail,
			Serial:     records.SOA.Serial,
			Refresh:    records.SOA.Refresh,
			Retry:      records.SOA.Retry,
			Expire:     records.SOA.Expire,
			MinTTL:     records.SOA.MinTTL,
		}
	}
	now := time.Now()
	d := events.DnsRecordsDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceDnsinfo,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindDNSAnswer,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:   records.Domain,
		Resolver: records.Resolver,
		A:        append([]string(nil), records.A...),
		AAAA:     append([]string(nil), records.AAAA...),
		CNAME:    append([]string(nil), records.CNAME...),
		MX:       mx,
		NS:       append([]string(nil), records.NS...),
		TXT:      append([]string(nil), records.TXT...),
		PTR:      ptr,
		SOA:      soa,
		DNSSEC:   records.DNSSEC,
	}
	d.EventID = events.NewEventID(now, d)
	return []events.DomainEvent{d}
}

// ZoneTransfer maps a successful zone transfer result to domain events.
// causationID is the DnsRecordsDiscovered event ID for the same domain.
func ZoneTransfer(domain, nameserver string, records []dnsinfo.ZoneRecord, scanID, causationID, corrID string) []events.DomainEvent {
	zrs := make([]valueobjects.ZoneRecord, 0, len(records))
	for _, r := range records {
		zrs = append(zrs, valueobjects.ZoneRecord{
			Name:  r.Name,
			Type:  r.Type,
			Value: r.Value,
			TTL:   r.TTL,
		})
	}
	now := time.Now()
	z := events.ZoneTransferDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceDnsinfo,
			Phase:           events.PhaseActive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindActiveProbe,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:     domain,
		Nameserver: nameserver,
		Records:    zrs,
	}
	z.EventID = events.NewEventID(now, z)
	return []events.DomainEvent{z}
}

// Registration maps a *whois.Registration result to a domain event. causationID
// is the DnsDomainNameDiscovered event ID that triggered the lookup.
func Registration(domain string, reg *whois.Registration, scanID, causationID, corrID string) []events.DomainEvent {
	if reg == nil {
		return nil
	}
	contacts := make([]valueobjects.RegistrationContact, 0, len(reg.Contacts))
	for _, c := range reg.Contacts {
		contacts = append(contacts, valueobjects.RegistrationContact{
			Role:         c.Role,
			Name:         c.Name,
			Organization: c.Organization,
			Email:        c.Email,
			Phone:        c.Phone,
			Address:      c.Address,
		})
	}
	now := time.Now()
	r := events.DomainRegistrationDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceWhois,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:      domain,
		DataSource:  reg.Source,
		Registrar:   reg.Registrar,
		WhoisServer: reg.Server,
		CreatedDate: reg.CreatedDate,
		UpdatedDate: reg.UpdatedDate,
		ExpiryDate:  reg.ExpiryDate,
		Nameservers: append([]string(nil), reg.Nameservers...),
		DNSSEC:      reg.DNSSEC,
		Contacts:    contacts,
	}
	r.EventID = events.NewEventID(now, r)
	return []events.DomainEvent{r}
}

// MailSecurity maps a *mailsec.MailRecords result to a domain event. causationID
// is the DnsDomainNameDiscovered event ID that triggered the lookup.
func MailSecurity(domain string, records *mailsec.MailRecords, scanID, causationID, corrID string) []events.DomainEvent {
	if records == nil {
		return nil
	}
	dkim := make([]valueobjects.DKIMRecord, 0, len(records.DKIM))
	for _, d := range records.DKIM {
		dkim = append(dkim, valueobjects.DKIMRecord{Selector: d.Selector, Value: d.Value})
	}
	var bimi *valueobjects.BIMIRecord
	if records.BIMI != nil {
		bimi = &valueobjects.BIMIRecord{Raw: records.BIMI.Raw, LogoURL: records.BIMI.LogoURL, VMCURL: records.BIMI.VMCURL}
	}
	var spf *valueobjects.SPFAnalysis
	if a := records.SPFAnalysis; a != nil {
		includes := make([]valueobjects.SPFInclude, 0, len(a.Includes))
		for _, inc := range a.Includes {
			includes = append(includes, valueobjects.SPFInclude{Domain: inc.Domain, Record: inc.Record, Lookups: inc.Lookups, Error: inc.Error})
		}
		spf = &valueobjects.SPFAnalysis{
			Records:     append([]string(nil), a.Records...),
			LookupCount: a.LookupCount,
			LookupLimit: a.LookupLimit,
			VoidCount:   a.VoidCount,
			VoidLimit:   a.VoidLimit,
			OverLimit:   a.OverLimit,
			Multiple:    a.Multiple,
			Includes:    includes,
			Errors:      append([]string(nil), a.Errors...),
		}
	}
	now := time.Now()
	m := events.MailSecurityDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceMailsec,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:        domain,
		SPF:           records.SPF,
		SPFAnalysis:   spf,
		DMARC:         records.DMARC,
		DMARCSeverity: records.DMARCSeverity,
		DKIM:          dkim,
		BIMI:          bimi,
		MXCount:       len(records.MX),
	}
	m.EventID = events.NewEventID(now, m)
	return []events.DomainEvent{m}
}

// BreachData maps a *breach.Result to a domain event. causationID is the
// DnsDomainNameDiscovered event ID that triggered the lookup. A nil or empty
// result yields no event: a domain with no breached aliases is not a discovery.
func BreachData(domain string, result *breach.Result, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil || len(result.Aliases) == 0 {
		return nil
	}
	aliases := make([]valueobjects.BreachedAlias, 0, len(result.Aliases))
	for _, a := range result.Aliases {
		aliases = append(aliases, valueobjects.BreachedAlias{
			Alias:    a.Alias,
			Breaches: append([]string(nil), a.Breaches...),
		})
	}
	now := time.Now()
	b := events.BreachDataDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceBreach,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:   domain,
		Breaches: aliases,
	}
	b.EventID = events.NewEventID(now, b)
	return []events.DomainEvent{b}
}

// CensysHosts maps a *censys.DomainHosts result to a domain event. causationID is
// the DnsDomainNameDiscovered event ID that triggered the lookup. A nil or empty
// result yields no event: a domain with no Censys hosts is not a discovery.
func CensysHosts(domain string, result *censys.DomainHosts, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil || len(result.Hosts) == 0 {
		return nil
	}
	hosts := make([]valueobjects.CensysHost, 0, len(result.Hosts))
	for _, h := range result.Hosts {
		services := make([]valueobjects.CensysService, 0, len(h.Services))
		for _, s := range h.Services {
			services = append(services, valueobjects.CensysService{Port: s.Port, Protocol: s.Protocol, Transport: s.Transport, SourceObservedAt: s.ObservedAt})
		}
		var asnInfo *valueobjects.CensysASN
		if h.ASN != nil {
			asnInfo = &valueobjects.CensysASN{Number: h.ASN.Number, Name: h.ASN.Name, Description: h.ASN.Description}
		}
		var loc *valueobjects.CensysLocation
		if h.Location != nil {
			loc = &valueobjects.CensysLocation{Country: h.Location.Country, City: h.Location.City}
		}
		hosts = append(hosts, valueobjects.CensysHost{
			IP:                 h.IP,
			Services:           services,
			ASN:                asnInfo,
			Location:           loc,
			OS:                 h.OS,
			Products:           append([]string(nil), h.Products...),
			Vulns:              append([]string(nil), h.Vulns...),
			Reputation:         h.Reputation,
			Labels:             append([]string(nil), h.Labels...),
			Sources:            append([]string(nil), h.Sources...),
			NetworkAllocatedAt: h.NetworkAllocatedAt,
			NetworkCIDRs:       append([]string(nil), h.NetworkCIDRs...),
		})
	}
	now := time.Now()
	c := events.CensysHostsDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceCensys,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
			RetrievalSource: events.RetrievalSource(result.RetrievalSource),
		},
		Domain:    domain,
		Hosts:     hosts,
		Truncated: result.Truncated,
	}
	c.EventID = events.NewEventID(now, c)
	return []events.DomainEvent{c}
}

// ShodanHosts maps a *shodan.DomainHosts result to a domain event. causationID is
// the DnsDomainNameDiscovered event ID that triggered the lookup. A nil or empty
// result yields no event.
func ShodanHosts(domain string, result *shodan.DomainHosts, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil || len(result.Hosts) == 0 {
		return nil
	}
	hosts := make([]valueobjects.ShodanHost, 0, len(result.Hosts))
	for i := range result.Hosts {
		h := &result.Hosts[i]
		services := make([]valueobjects.ShodanService, 0, len(h.Services))
		for _, s := range h.Services {
			services = append(services, valueobjects.ShodanService{Port: s.Port, Transport: s.Transport})
		}
		hosts = append(hosts, valueobjects.ShodanHost{
			IP:               h.IP,
			Services:         services,
			ASN:              h.ASN,
			Org:              h.Org,
			ISP:              h.ISP,
			OS:               h.OS,
			Hostnames:        append([]string(nil), h.Hostnames...),
			Tags:             append([]string(nil), h.Tags...),
			Country:          h.Country,
			City:             h.City,
			Products:         append([]string(nil), h.Products...),
			Vulns:            append([]string(nil), h.Vulns...),
			SourceObservedAt: h.ObservedAt,
		})
	}
	now := time.Now()
	s := events.ShodanHostsDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceShodan,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:    domain,
		Hosts:     hosts,
		Truncated: result.Truncated,
	}
	s.EventID = events.NewEventID(now, s)
	return []events.DomainEvent{s}
}

// NetlasHosts maps a *netlas.DomainHosts result to a domain event. causationID is
// the DnsDomainNameDiscovered event ID that triggered the lookup. A nil or empty
// result yields no event.
func NetlasHosts(domain string, result *netlas.DomainHosts, scanID, causationID, corrID string) []events.DomainEvent {
	if result == nil || len(result.Hosts) == 0 {
		return nil
	}
	hosts := make([]valueobjects.NetlasHost, 0, len(result.Hosts))
	for i := range result.Hosts {
		h := &result.Hosts[i]
		services := make([]valueobjects.NetlasService, 0, len(h.Services))
		for _, s := range h.Services {
			services = append(services, valueobjects.NetlasService{
				Port:                s.Port,
				Transport:           s.Transport,
				ApplicationProtocol: s.ApplicationProtocol,
			})
		}
		hosts = append(hosts, valueobjects.NetlasHost{
			IP:               h.IP,
			Services:         services,
			ASN:              h.ASN,
			Org:              h.Org,
			ISP:              h.ISP,
			Hostnames:        append([]string(nil), h.Hostnames...),
			Country:          h.Country,
			City:             h.City,
			JARM:             h.JARM,
			Products:         append([]string(nil), h.Products...),
			Vulns:            append([]string(nil), h.Vulns...),
			SourceObservedAt: h.ObservedAt,
		})
	}
	now := time.Now()
	n := events.NetlasHostsDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceNetlas,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:    domain,
		Hosts:     hosts,
		Truncated: result.Truncated,
	}
	n.EventID = events.NewEventID(now, n)
	return []events.DomainEvent{n}
}

// VirustotalReputation maps a *virustotal.DomainReport to a domain event.
// causationID is the DnsDomainNameDiscovered event ID that triggered the lookup.
// The category and popularity-rank maps are flattened into sorted slices for
// stable event IDs and consistent presentation.
func VirustotalReputation(domain string, report *virustotal.DomainReport, scanID, causationID, corrID string) []events.DomainEvent {
	if report == nil {
		return nil
	}
	categories := make([]valueobjects.ReputationCategory, 0, len(report.Categories))
	for vendor, cat := range report.Categories {
		categories = append(categories, valueobjects.ReputationCategory{Vendor: vendor, Category: cat})
	}
	sort.Slice(categories, func(i, j int) bool { return categories[i].Vendor < categories[j].Vendor })

	ranks := make([]valueobjects.PopularityRank, 0, len(report.PopularityRanks))
	for vendor, rank := range report.PopularityRanks {
		ranks = append(ranks, valueobjects.PopularityRank{Vendor: vendor, Rank: rank})
	}
	sort.Slice(ranks, func(i, j int) bool { return ranks[i].Vendor < ranks[j].Vendor })

	now := time.Now()
	r := events.DomainReputationDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceVirustotal,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain:          domain,
		Reputation:      report.Reputation,
		Malicious:       report.Analysis.Malicious,
		Suspicious:      report.Analysis.Suspicious,
		Harmless:        report.Analysis.Harmless,
		Undetected:      report.Analysis.Undetected,
		Categories:      categories,
		Tags:            append([]string(nil), report.Tags...),
		PopularityRanks: ranks,
		JARM:            report.JARM,
		Registrar:       report.Registrar,
	}
	r.EventID = events.NewEventID(now, r)
	return []events.DomainEvent{r}
}

// WebAssets maps a *websearch.DomainAssets result to a domain event. A nil or
// empty result yields no event: a domain with no dork hits is not a discovery.
func WebAssets(domain string, result *websearch.DomainAssets, scanID, corrID string) []events.DomainEvent {
	if result == nil || len(result.Assets) == 0 {
		return nil
	}
	assets := make([]valueobjects.WebAsset, 0, len(result.Assets))
	for _, a := range result.Assets {
		assets = append(assets, valueobjects.WebAsset{
			URL:      a.URL,
			Host:     a.Host,
			Dork:     a.Dork,
			Category: a.Category,
		})
	}
	now := time.Now()
	w := events.WebAssetsDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			Source:          SourceWebsearch,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Domain: domain,
		Assets: assets,
	}
	w.EventID = events.NewEventID(now, w)
	return []events.DomainEvent{w}
}

// IPAddresses maps the A and AAAA records of a DNS result to one
// IPAddressDiscovered event per address. causationID is the DnsRecordsDiscovered
// event ID those addresses were resolved from.
func IPAddresses(domain string, records *dnsinfo.Records, scanID, causationID, corrID string) []events.IPAddressDiscovered {
	if records == nil {
		return nil
	}
	now := time.Now()
	out := make([]events.IPAddressDiscovered, 0, len(records.A)+len(records.AAAA))
	add := func(ip, recordType string) {
		e := events.IPAddressDiscovered{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     causationID,
				Source:          SourceDnsinfo,
				Phase:           events.PhasePassive,
				Category:        events.CategoryDiscovery,
				ObservationKind: events.ObservationKindDNSAnswer,
				CapturedAt:      now,
				ToolCorrID:      corrID,
			},
			IP:         ip,
			Domain:     domain,
			RecordType: recordType,
			// A DNS-resolved address is a directly observed fact.
			Confidence: events.ConfidenceConfirmed,
		}
		e.EventID = events.NewEventID(now, e)
		out = append(out, e)
	}
	for _, ip := range records.A {
		add(ip, "A")
	}
	for _, ip := range records.AAAA {
		add(ip, "AAAA")
	}
	return out
}

// ProviderIPAddresses maps the IPs of a passive host-intel result (Censys/Shodan/
// Netlas) to one IPAddressDiscovered per unique, parseable address. Unlike
// IPAddresses (DNS A/AAAA, confirmed) these are third-party assertions: Source is
// the provider, Confidence is inferred, and RecordType is empty (the address was not
// resolved from a DNS record). causationID is the *HostsDiscovered facet EventID.
func ProviderIPAddresses(domain string, ips []string, source, scanID, causationID, corrID string) []events.IPAddressDiscovered {
	if len(ips) == 0 {
		return nil
	}
	now := time.Now()
	seen := make(map[string]bool, len(ips))
	out := make([]events.IPAddressDiscovered, 0, len(ips))
	for _, ip := range ips {
		if seen[ip] || net.ParseIP(ip) == nil {
			continue
		}
		seen[ip] = true
		e := events.IPAddressDiscovered{
			EventMeta: events.EventMeta{
				ScanID:          scanID,
				CausationID:     causationID,
				Source:          source,
				Phase:           events.PhasePassive,
				Category:        events.CategoryDiscovery,
				ObservationKind: events.ObservationKindPassiveSnapshot,
				CapturedAt:      now,
				ToolCorrID:      corrID,
			},
			IP:     ip,
			Domain: domain,
			// RecordType stays empty: the address is a provider assertion, not
			// resolved from a DNS A/AAAA record.
			Confidence: events.ConfidenceInferred,
		}
		e.EventID = events.NewEventID(now, e)
		out = append(out, e)
	}
	return out
}

// Netblock maps an *asn.Record result to a NetblockDiscovered event. causationID
// is the IPAddressDiscovered event ID for the looked-up IP.
func Netblock(record *asn.Record, scanID, causationID, corrID string) []events.DomainEvent {
	if record == nil {
		return nil
	}
	now := time.Now()
	n := events.NetblockDiscovered{
		EventMeta: events.EventMeta{
			ScanID:          scanID,
			CausationID:     causationID,
			Source:          SourceAsn,
			Phase:           events.PhasePassive,
			Category:        events.CategoryDiscovery,
			ObservationKind: events.ObservationKindPassiveSnapshot,
			CapturedAt:      now,
			ToolCorrID:      corrID,
		},
		Prefix:   record.Prefix,
		ASN:      record.ASN,
		Name:     record.Name,
		Country:  record.Country,
		Registry: record.Registry,
	}
	n.EventID = events.NewEventID(now, n)
	return []events.DomainEvent{n}
}

// ToDomainEvents adapts a slice of IPAddressDiscovered to the DomainEvent
// interface slice expected by publish.
func ToDomainEvents(ips []events.IPAddressDiscovered) []events.DomainEvent {
	out := make([]events.DomainEvent, len(ips))
	for i, e := range ips {
		out[i] = e
	}
	return out
}
