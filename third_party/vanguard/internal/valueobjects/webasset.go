package valueobjects

// WebAsset is a single URL discovered through a web-search (Google dork) query,
// with the host it lives on and the dork (and its category) that surfaced it. The
// category classifies the exposure the dork hunted for (for example "config",
// "backup", "admin"), so consumers can judge how sensitive the hit is.
type WebAsset struct {
	// URL is the discovered address.
	URL string
	// Host is the lowercased hostname of the URL.
	Host string
	// Dork is the Google dork query that surfaced the URL.
	Dork string
	// Category is the dork category (for example "config", "backup", "general").
	Category string
}
