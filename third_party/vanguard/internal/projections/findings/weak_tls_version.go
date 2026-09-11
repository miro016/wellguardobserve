package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// WeakTLSVersion raises a finding when an HTTPS endpoint still negotiates a
// deprecated TLS protocol version. TLS 1.0 is critical (High); TLS 1.1 is a
// warning (Medium). The worst supported version sets the severity.
func WeakTLSVersion(evt events.DomainEvent) []events.FindingRaised {
	t, ok := evt.(events.TlsPostureDiscovered)
	if !ok {
		return nil
	}
	var weak []string
	severity := events.SeverityInfo
	for _, v := range t.Versions {
		if !v.Supported {
			continue
		}
		switch v.Risk {
		case "critical":
			weak = append(weak, v.Version)
			if severity < events.SeverityHigh {
				severity = events.SeverityHigh
			}
		case "warning":
			weak = append(weak, v.Version)
			if severity < events.SeverityMedium {
				severity = events.SeverityMedium
			}
		}
	}
	if len(weak) == 0 {
		return nil
	}
	sort.Strings(weak)
	f := events.FindingRaised{
		Rule:            "weak-tls-version",
		Title:           "Deprecated TLS protocol version supported",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetDomain,
		AssetID:         t.Domain,
		Evidence:        fmt.Sprintf("%s still negotiates %s", t.Domain, strings.Join(weak, ", ")),
		Recommendation:  "Disable TLS 1.0/1.1 and require TLS 1.2 or higher.",
		References:      []string{"CWE-326"},
	}
	f.Severity = severity
	return []events.FindingRaised{f}
}
