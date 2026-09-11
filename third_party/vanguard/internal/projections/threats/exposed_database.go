package threats

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// ExposedDatabase fires when one database service is both internet-exposed and
// known to ship with well-known default credentials. The findings must share the
// canonical service asset, so weaknesses on different sockets never form a path.
func ExposedDatabase(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets(entities.AssetKindService) {
		findings := g.Findings(asset)
		exposure := findings["risky-open-port"]
		credentials := findings["default-credentials"]
		if exposure == nil || credentials == nil {
			continue
		}
		label, ok := databaseLabel(exposure.Service, credentials.Service)
		if !ok {
			continue
		}
		out = append(out, ThreatScenario{
			Name:       "Exposed database with default credentials",
			Severity:   int(events.SeverityCritical),
			Narrative:  fmt.Sprintf("%s exposes %s to the internet and the identified product ships with well-known default credentials; an attacker can attempt direct database access and compromise stored data.", asset.ID, label),
			Summary:    fmt.Sprintf("%s is exposed to the internet and the identified product ships with well-known default credentials; an attacker can attempt direct database access and compromise stored data.", label),
			Assets:     []entities.AssetRef{asset},
			Evidence:   []string{evidence(exposure), evidence(credentials)},
			References: []string{"MITRE ATT&CK T1078.001", "CWE-1392", "CWE-668"},
		}.withChain(exposure, credentials))
	}
	return out
}

// databaseLabel identifies database services only from structured finding facets.
// A product name wins because it is more specific; a facet port is the fallback
// when the scanner could not fingerprint the product.
func databaseLabel(facets ...entities.ServiceFacet) (string, bool) {
	for _, facet := range facets {
		product := strings.TrimSpace(facet.Product)
		if isDatabaseProduct(product) {
			return product, true
		}
	}
	for _, facet := range facets {
		switch facet.Port {
		case 1433:
			return "Microsoft SQL Server", true
		case 3306:
			return "MySQL-compatible database", true
		case 5432:
			return "PostgreSQL", true
		case 6379:
			return "Redis", true
		case 9200:
			return "Elasticsearch", true
		case 11211:
			return "Memcached", true
		case 27017:
			return "MongoDB", true
		}
	}
	return "", false
}

// isDatabaseProduct recognizes the database identities the collection tools emit.
func isDatabaseProduct(product string) bool {
	product = strings.ToLower(product)
	for _, token := range []string{
		"couchdb", "database", "elasticsearch", "mariadb", "memcached",
		"mongodb", "mongo db", "mssql", "mysql", "postgres", "redis", "sql server",
	} {
		if strings.Contains(product, token) {
			return true
		}
	}
	return false
}
