package websearch

import "fmt"

// Dork categories classify what a dork pattern hunts for, so downstream
// consumers (and the orchestrator's detector) can judge how sensitive a hit is.
const (
	// CategoryGeneral is a broad site: query with no sensitive intent; its hits
	// are useful for host discovery but are not findings on their own.
	CategoryGeneral = "general"
	// CategoryAuth covers login / sign-in / auth endpoints.
	CategoryAuth = "auth"
	// CategoryAdmin covers admin / panel / dashboard / management interfaces.
	CategoryAdmin = "admin"
	// CategoryAPI covers API / versioned / swagger / graphql endpoints.
	CategoryAPI = "api"
	// CategoryConfig covers configuration / environment files.
	CategoryConfig = "config"
	// CategoryBackup covers backup / database dump files.
	CategoryBackup = "backup"
	// CategoryIndexOf covers open directory listings ("index of").
	CategoryIndexOf = "indexof"
	// CategoryWordPress covers exposed WordPress paths.
	CategoryWordPress = "wordpress"
	// CategoryPreProd covers test / staging / dev / uat / sandbox environments.
	CategoryPreProd = "preprod"
)

// dorkPattern is a Google dork template and the category of exposure it hunts.
// Each %s in pattern is replaced with the target domain.
type dorkPattern struct {
	pattern  string
	category string
}

// googleDorkPatterns are the Google dork templates applied to the root domain.
// Multi-term alternatives are parenthesized so the OR stays bound to the site:
// operator. Without the parentheses Google binds site: to only the first term and
// the remaining OR alternatives match the whole web, so the search returns
// off-target hosts (SEO articles, unrelated third parties) instead of the target.
var googleDorkPatterns = []dorkPattern{
	{"site:%s", CategoryGeneral},
	{"site:*.%s", CategoryGeneral},
	{"site:%s (inurl:login OR inurl:signin OR inurl:auth)", CategoryAuth},
	{"site:%s (inurl:admin OR inurl:panel OR inurl:dashboard OR inurl:manage)", CategoryAdmin},
	{"site:%s (inurl:api OR inurl:v1 OR inurl:v2 OR inurl:swagger OR inurl:graphql)", CategoryAPI},
	{"site:%s (ext:conf OR ext:config OR ext:yml OR ext:yaml OR ext:env)", CategoryConfig},
	{"site:%s (ext:bak OR ext:backup OR ext:old OR ext:sql OR ext:dump)", CategoryBackup},
	{`site:%s intitle:"index of"`, CategoryIndexOf},
	{"site:%s (inurl:wp-admin OR inurl:wp-content OR inurl:wp-login)", CategoryWordPress},
	{"site:%s (inurl:test OR inurl:staging OR inurl:dev OR inurl:uat OR inurl:sandbox)", CategoryPreProd},
}

// expandedDork is a dork query with the domain substituted in, plus its category.
type expandedDork struct {
	query    string
	category string
}

// buildGoogleDorks returns the expanded Google dork queries for domain.
func buildGoogleDorks(domain string) []expandedDork {
	out := make([]expandedDork, len(googleDorkPatterns))
	for i, p := range googleDorkPatterns {
		out[i] = expandedDork{query: fmt.Sprintf(p.pattern, domain), category: p.category}
	}
	return out
}
