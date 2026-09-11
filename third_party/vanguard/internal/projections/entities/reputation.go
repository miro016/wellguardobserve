package entities

import (
	"time"

	"github.com/velgard-sk/vanguard/internal/valueobjects"
)

// Reputation aggregates the threat-intelligence VirusTotal reports for a single
// Domain: the community reputation score, per-engine analysis vote counts,
// content categories, tags, popularity ranks, JARM fingerprint, and registrar.
// Like MailSecurity and BreachExposure it is a facet of the owning Domain rather
// than a standalone asset, and is an independent passive view of the domain's
// standing. The registrar is kept here as a corroborating field; whois/RDAP
// (Registration) remains the authoritative registration source.
type Reputation struct {
	// Score is the VirusTotal community reputation score (can be negative).
	Score int
	// Malicious is the number of engines that flagged the domain as malicious.
	Malicious int
	// Suspicious is the number of engines that flagged the domain as suspicious.
	Suspicious int
	// Harmless is the number of engines that rated the domain harmless.
	Harmless int
	// Undetected is the number of engines with no detection.
	Undetected int
	// Categories holds the per-vendor content classifications.
	Categories []valueobjects.ReputationCategory
	// Tags holds the free-form tags VirusTotal attached to the domain.
	Tags []string
	// PopularityRanks holds the per-provider popularity rankings.
	PopularityRanks []valueobjects.PopularityRank
	// JARM is the JARM TLS fingerprint VirusTotal observed, empty when absent.
	JARM string
	// Registrar is the registrar VirusTotal reports, empty when absent.
	Registrar string
	// ResolvedAt is when the reputation data was last gathered.
	ResolvedAt time.Time
}
