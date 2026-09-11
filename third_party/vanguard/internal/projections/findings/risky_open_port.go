package findings

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// cweExposedService is the weakness every exposure rule in this package cites:
// exposure of a resource to the wrong sphere. It is named once so the active,
// provider-reported, and UDP rules cannot drift onto different identifiers for the
// same claim.
const cweExposedService = "CWE-668"

// sensitivePorts maps ports that should not be publicly exposed to a label.
var sensitivePorts = map[int]string{
	21:    "FTP",
	23:    "Telnet",
	135:   "MSRPC",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

// RiskyOpenPort raises a finding for a sensitive service exposed on an open port.
func RiskyOpenPort(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.ServiceDiscovered)
	if !ok {
		return nil
	}
	sid := entities.NewServiceID(e.IP, e.Port, e.Protocol)
	if sid.Proto != entities.ProtocolTCP {
		// sensitivePorts labels TCP services, and the recommendation is written for
		// one. A sensitive UDP service is its own rule, not this one wearing a
		// different transport.
		return nil
	}
	label, risky := sensitivePorts[e.Port]
	if !risky {
		return nil
	}
	f := events.FindingRaised{
		Rule:            "risky-open-port",
		Title:           fmt.Sprintf("Sensitive service exposed: %s", label),
		FindingCategory: string(entities.FindingExposure),
		AssetKind:       assetService,
		AssetID:         sid.String(),
		Evidence:        fmt.Sprintf("%s (%s) is reachable on %s port %d", label, e.Service, e.IP, e.Port),
		Recommendation:  "Restrict access to this service with a firewall or move it off the public internet.",
		References:      []string{cweExposedService},
		Service:         events.ServiceFacet{Port: sid.Port, Proto: sid.Proto, Product: e.Product, Version: e.Version, CPEs: e.CPEs},
	}
	f.Severity = events.SeverityHigh
	return []events.FindingRaised{f}
}
