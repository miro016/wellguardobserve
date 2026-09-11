package findings

import (
	"fmt"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// PlaintextHTTP raises a finding for content served over plaintext HTTP that is
// not merely redirecting to HTTPS.
func PlaintextHTTP(evt events.DomainEvent) []events.FindingRaised {
	e, ok := evt.(events.HttpEndpointDiscovered)
	if !ok {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(e.URL), "http://") {
		return nil
	}
	// A redirect (3xx) to HTTPS is acceptable; only flag plaintext that serves content.
	if e.StatusCode < 200 || e.StatusCode >= 300 {
		return nil
	}
	endpointID, ok := endpointAssetID(e.URL)
	if !ok {
		// A URL that cannot be normalized owns no Endpoint asset; raising a finding
		// against it would name a target the graph does not hold.
		return nil
	}
	f := events.FindingRaised{
		Rule:            "plaintext-http",
		Title:           "Content served over plaintext HTTP",
		FindingCategory: string(entities.FindingExposure),
		AssetKind:       assetEndpoint,
		AssetID:         endpointID,
		Evidence:        fmt.Sprintf("%s returned HTTP %d over plaintext without redirecting to HTTPS", e.URL, e.StatusCode),
		Recommendation:  "Redirect HTTP to HTTPS and enable HSTS.",
		References:      []string{"CWE-319"},
		Locations:       []string{e.URL},
	}
	f.Severity = events.SeverityLow
	return []events.FindingRaised{f}
}
