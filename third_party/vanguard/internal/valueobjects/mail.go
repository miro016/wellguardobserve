package valueobjects

// DKIMRecord is one discovered DKIM selector and its TXT value.
type DKIMRecord struct {
	// Selector is the DKIM selector label (for example "google", "selector1").
	Selector string
	// Value is the raw TXT record value for the selector.
	Value string
}

// BIMIRecord holds a BIMI record and the URLs parsed from it.
type BIMIRecord struct {
	// Raw is the unparsed BIMI TXT record.
	Raw string
	// LogoURL is the brand logo location from the l= tag.
	LogoURL string
	// VMCURL is the Verified Mark Certificate location from the a= tag.
	VMCURL string
}

// SPFAnalysis is the result of static worst-case SPF analysis for a domain.
// Counts are the maximum possible DNS lookups assuming every mechanism is
// evaluated; real SPF evaluation may short-circuit earlier depending on the
// sender IP and mail flow.
type SPFAnalysis struct {
	// Records holds every SPF (v=spf1) TXT record found; more than one is invalid.
	Records []string
	// LookupCount is the worst-case number of DNS-generating mechanisms.
	LookupCount int
	// LookupLimit is the RFC 7208 limit LookupCount is compared against.
	LookupLimit int
	// VoidCount is the number of lookups that resolved to nothing.
	VoidCount int
	// VoidLimit is the limit VoidCount is compared against.
	VoidLimit int
	// OverLimit is true when LookupCount exceeds LookupLimit.
	OverLimit bool
	// Multiple is true when more than one SPF record was published (invalid).
	Multiple bool
	// Includes records each include:/redirect= target and its resolved cost.
	Includes []SPFInclude
	// Errors holds analysis-level problems (multiple records, query failures).
	Errors []string
}

// SPFInclude records one include: or redirect= target and its resolved lookup
// count. Lookups excludes the lookup for the include/redirect itself (counted by
// the parent record).
type SPFInclude struct {
	// Domain is the include/redirect target.
	Domain string
	// Record is the target's SPF record, when found.
	Record string
	// Lookups is the number of DNS-generating mechanisms in the target's record.
	Lookups int
	// Error describes why the target could not be resolved, when applicable.
	Error string
}
