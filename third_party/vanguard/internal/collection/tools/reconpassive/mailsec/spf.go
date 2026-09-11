package mailsec

import (
	"context"
	"strings"

	dns "codeberg.org/miekg/dns"
)

// queryFunc abstracts DNS TXT queries so the SPF analyzer is testable without
// live DNS.
type queryFunc func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error)

// analyzeSPFWith runs static worst-case SPF analysis using qf for DNS lookups.
func analyzeSPFWith(ctx context.Context, domain string, qf queryFunc) *SPFAnalysis {
	analysis := &SPFAnalysis{
		Domain:      domain,
		LookupLimit: spfLookupLimit,
		VoidLimit:   spfVoidLimit,
	}

	rrs, err := qf(ctx, domain, dns.TypeTXT)
	if err != nil {
		analysis.Errors = append(analysis.Errors, err.Error())
		return analysis
	}

	for _, value := range txtValues(rrs) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "v=spf1") {
			analysis.Records = append(analysis.Records, value)
		}
	}

	analysis.Multiple = len(analysis.Records) > 1
	if analysis.Multiple {
		analysis.Errors = append(analysis.Errors,
			"multiple SPF records found; domain is invalid per RFC 7208 section 4.5")
		// Still count mechanisms for diagnostics, but skip recursion.
		for _, record := range analysis.Records {
			analysis.LookupCount += countShallowLookups(record)
		}
		analysis.OverLimit = analysis.LookupCount > analysis.LookupLimit
		return analysis
	}

	if len(analysis.Records) == 1 {
		visited := map[string]struct{}{domain: {}}
		lookups, voids, includes := resolveSPFRecord(ctx, analysis.Records[0], 0, visited, qf)
		analysis.LookupCount = lookups
		analysis.VoidCount = voids
		analysis.Includes = includes
	}

	analysis.OverLimit = analysis.LookupCount > analysis.LookupLimit
	return analysis
}

// resolveSPFRecord recursively resolves an SPF record string, following include:
// and redirect= chains. It returns the total lookup count, void count, and the
// include chain for transparency.
func resolveSPFRecord(ctx context.Context, record string, depth int, visited map[string]struct{}, qf queryFunc) (lookups, voids int, includes []SPFInclude) {
	for _, field := range strings.Fields(record) {
		token := strings.ToLower(strings.TrimLeft(field, "+-~?"))
		switch {
		case strings.HasPrefix(token, "include:"):
			lookups++ // the include: itself costs one lookup
			l, v, inc := resolveTarget(ctx, strings.TrimPrefix(token, "include:"), depth, visited, qf)
			lookups += l
			voids += v
			includes = append(includes, inc)
		case strings.HasPrefix(token, "redirect="):
			lookups++ // redirect costs one lookup
			l, v, inc := resolveTarget(ctx, strings.TrimPrefix(token, "redirect="), depth, visited, qf)
			lookups += l
			voids += v
			includes = append(includes, inc)
		case token == "a", strings.HasPrefix(token, "a:"), strings.HasPrefix(token, "a/"):
			lookups++
		case token == "mx", strings.HasPrefix(token, "mx:"), strings.HasPrefix(token, "mx/"):
			lookups++
		case token == "ptr", strings.HasPrefix(token, "ptr:"):
			lookups++
		case strings.HasPrefix(token, "exists:"):
			lookups++
		}
	}
	return lookups, voids, includes
}

// resolveTarget recursively resolves one include/redirect target domain.
func resolveTarget(ctx context.Context, target string, depth int, visited map[string]struct{}, qf queryFunc) (lookups, voids int, inc SPFInclude) {
	inc = SPFInclude{Domain: target}

	switch {
	case strings.Contains(target, "%{"):
		inc.Error = "contains macros; cannot resolve statically"
		return lookups, voids, inc
	case visitedContains(visited, target):
		inc.Error = "loop detected"
		return lookups, voids, inc
	case depth >= maxSPFRecursion:
		inc.Error = "recursion limit reached"
		return lookups, voids, inc
	}
	visited[target] = struct{}{}

	rrs, err := qf(ctx, target, dns.TypeTXT)
	if err != nil {
		inc.Error = err.Error()
		voids++
		return lookups, voids, inc
	}

	var spfRecord string
	for _, value := range txtValues(rrs) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "v=spf1") {
			spfRecord = value
			break
		}
	}
	if spfRecord == "" {
		inc.Error = "no SPF record found"
		voids++
		return lookups, voids, inc
	}

	inc.Record = spfRecord
	l, v, _ := resolveSPFRecord(ctx, spfRecord, depth+1, visited, qf)
	inc.Lookups = l
	return l, v, inc
}

func visitedContains(visited map[string]struct{}, target string) bool {
	_, seen := visited[target]
	return seen
}

// countShallowLookups counts DNS-generating mechanisms without recursion. It is
// the fallback for invalid (multiple) SPF records.
func countShallowLookups(record string) int {
	count := 0
	for _, field := range strings.Fields(record) {
		token := strings.ToLower(strings.TrimLeft(field, "+-~?"))
		switch {
		case strings.HasPrefix(token, "include:"):
			count++
		case strings.HasPrefix(token, "redirect="):
			count++
		case token == "a", strings.HasPrefix(token, "a:"), strings.HasPrefix(token, "a/"):
			count++
		case token == "mx", strings.HasPrefix(token, "mx:"), strings.HasPrefix(token, "mx/"):
			count++
		case token == "ptr", strings.HasPrefix(token, "ptr:"):
			count++
		case strings.HasPrefix(token, "exists:"):
			count++
		}
	}
	return count
}
