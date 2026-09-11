package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// MissingSecurityHeaders raises a finding for an HTTPS endpoint missing key
// security response headers (HSTS, CSP).
func MissingSecurityHeaders(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.HttpEndpointDiscovered)
	if !ok {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(e.URL), "https://") {
		return nil
	}
	present := map[string]bool{}
	for _, h := range e.Headers {
		present[h] = true
	}

	var missing []string
	severity := events.SeverityLow
	if !present["Strict-Transport-Security"] {
		missing = append(missing, "Strict-Transport-Security")
		severity = events.SeverityMedium
	}
	if !present["Content-Security-Policy"] {
		missing = append(missing, "Content-Security-Policy")
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	endpointID, ok := endpointAssetID(e.URL)
	if !ok {
		// A URL that cannot be normalized owns no Endpoint asset; raising a finding
		// against it would name a target the graph does not hold.
		return nil
	}
	f := events.FindingRaised{
		Rule:            "missing-security-headers",
		Title:           "Missing HTTP security headers",
		FindingCategory: string(entities.FindingMisconfig),
		AssetKind:       assetEndpoint,
		AssetID:         endpointID,
		Evidence:        fmt.Sprintf("%s is missing %s", e.URL, strings.Join(missing, ", ")),
		Recommendation:  "Add the missing security headers to harden the endpoint.",
		References:      []string{"CWE-693"},
		Locations:       []string{e.URL},
	}
	f.Severity = severity
	return []events.FindingRaised{f}
}
