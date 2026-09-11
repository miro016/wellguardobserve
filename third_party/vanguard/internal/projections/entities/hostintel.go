package entities

import "time"

// HostIntel is provider-asserted host intelligence folded onto an IP asset: the CVEs
// and characteristic/threat tags a passive source (Shodan, Censys, Netlas) attributes
// to the address. It is inferred - a scenario may chain it, but it
// never outranks a directly observed finding of equal severity until the active
// phase corroborates it. Zero value means no intel was reported for the
// address.
type HostIntel struct {
	// CVEs are provider-asserted CVE ids for the host's services, sorted and deduped.
	// They seed a safe cve-corroborate target even when no finding was raised.
	CVEs []string
	// Tags are provider characteristic/threat tags (for example "self-signed", "vpn",
	// or a malware-family label), sorted and deduped.
	Tags []string
	// Sources are the providers that contributed (for example "shodan", "censys",
	// "netlas"), sorted and deduped.
	Sources []string
	// SourceObservedAt is the most recent point-in-time observation reported by the
	// provider. It is not a Vanguard live verification.
	SourceObservedAt time.Time
}

// IsZero reports whether no host intel was reported for the address.
func (h HostIntel) IsZero() bool {
	return len(h.CVEs) == 0 && len(h.Tags) == 0 && len(h.Sources) == 0
}
