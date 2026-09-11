package mailsec

// MailRecords holds the email-security DNS records gathered for a domain. It is
// the tool's own output type, decoupled from the domain model; the orchestrator
// translates it into a domain event.
type MailRecords struct {
	MX            []MXRecord
	SPF           string
	SPFAnalysis   *SPFAnalysis
	DMARC         string
	DMARCSeverity string
	DKIM          []DKIMRecord
	BIMI          *BIMIRecord
	MTASTS        string
}

// MXRecord holds one MX host and priority pair.
type MXRecord struct {
	Host     string
	Priority uint16
}

// DKIMRecord holds one discovered DKIM selector and TXT value.
type DKIMRecord struct {
	Selector string
	Value    string
}

// BIMIRecord holds a raw BIMI record and parsed URLs.
type BIMIRecord struct {
	Raw     string
	LogoURL string
	VMCURL  string
}

// SPFAnalysis holds the result of static worst-case SPF analysis. Counts are the
// maximum possible DNS lookups assuming all mechanisms are evaluated; real SPF
// evaluation may short-circuit earlier depending on the sender IP and mail flow.
type SPFAnalysis struct {
	Domain      string
	Records     []string
	LookupCount int
	LookupLimit int
	VoidCount   int
	VoidLimit   int
	OverLimit   bool
	Multiple    bool
	Includes    []SPFInclude
	Errors      []string
}

// SPFInclude records one include: or redirect= target and its resolved lookup
// count. Lookups excludes the lookup for the include/redirect itself (counted by
// the parent record).
type SPFInclude struct {
	Domain  string
	Record  string
	Lookups int
	Error   string
}
