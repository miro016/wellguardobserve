package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// MxNoStartTLS raises a finding when one or more of a domain's MX hosts do not
// offer STARTTLS, leaving inbound mail open to passive interception.
func MxNoStartTLS(evt events.DomainEvent) []events.FindingRaised {
	m, ok := evt.(events.MxTlsDiscovered)
	if !ok || len(m.Hosts) == 0 {
		return nil
	}
	// A host is only flagged when STARTTLS was actually observed absent. A host
	// whose probe errored (e.g. port 25 blocked from the scanner, dial timeout)
	// has unknown STARTTLS support: its StartTLSSupported is false because the
	// connection never completed, not because STARTTLS is missing. Flagging it
	// would be a false positive, so a host with a non-empty Error is skipped.
	var plaintext []string
	for i := range m.Hosts {
		if m.Hosts[i].Error != "" {
			continue
		}
		if !m.Hosts[i].StartTLSSupported {
			plaintext = append(plaintext, m.Hosts[i].Host)
		}
	}
	if len(plaintext) == 0 {
		return nil
	}
	sort.Strings(plaintext)
	f := events.FindingRaised{
		Rule:            "mx-no-starttls",
		Title:           "MX host does not offer STARTTLS",
		FindingCategory: string(entities.FindingTLS),
		AssetKind:       assetDomain,
		AssetID:         m.Domain,
		Evidence:        fmt.Sprintf("%d MX host(s) for %s do not offer STARTTLS: %s", len(plaintext), m.Domain, strings.Join(plaintext, ", ")),
		Recommendation:  "Enable STARTTLS on all MX hosts so inbound mail is encrypted in transit.",
		References:      []string{"CWE-319"},
	}
	f.Severity = events.SeverityMedium
	return []events.FindingRaised{f}
}
