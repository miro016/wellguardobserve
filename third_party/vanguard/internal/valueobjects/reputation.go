package valueobjects

// ReputationCategory is one vendor's content classification of a domain (for
// example BitDefender -> "searchengines"), as reported by VirusTotal.
type ReputationCategory struct {
	// Vendor is the classifying engine or feed.
	Vendor string
	// Category is the content category that vendor assigned.
	Category string
}

// PopularityRank is one ranking provider's position for a domain (for example
// "Cisco Umbrella" -> 1), as reported by VirusTotal.
type PopularityRank struct {
	// Vendor is the ranking provider.
	Vendor string
	// Rank is the position the provider assigns (lower is more popular).
	Rank int
}
