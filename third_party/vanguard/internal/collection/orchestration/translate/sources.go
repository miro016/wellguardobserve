package translate

// Source* are the EventMeta.Source labels stamped on the domain events the
// translators produce, one per producing tool. They are exported because the
// orchestrator reuses the same label as the tool name in its per-call
// correlation IDs (newToolCorrID), so the value has a single definition shared
// by the side that tags the tool call and the side that stamps the event.
const (
	SourceCrtsh       = "crtsh"
	SourceCertspotter = "certspotter"
	SourceSubfinder   = "subfinder"
	SourceDnsinfo     = "dnsinfo"
	SourceAsn         = "asn"
	SourceWhois       = "whois"
	SourceMailsec     = "mailsec"
	SourceBreach      = "breach"
	SourceCensys      = "censys"
	SourceVirustotal  = "virustotal"
	SourceWebsearch   = "websearch"
	SourceShodan      = "shodan"
	SourceNetlas      = "netlas"
	SourcePortscan    = "portscan"
	SourceHTTP        = "httpprobe"
	SourceHTTPS       = "https"
	SourceSMTP        = "smtp"
	SourceWebinfo     = "webinfo"
	SourceWappalyzer  = "wappalyzer"
	SourceGoScans     = "goscans"
)
