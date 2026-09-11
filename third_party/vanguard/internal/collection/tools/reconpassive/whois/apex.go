package whois

import "github.com/weppos/publicsuffix-go/publicsuffix"

// RegistrableApex returns the registrable domain (eTLD+1) of name using the
// public-suffix list: www.bp.vissim.no -> vissim.no, vissim.no -> vissim.no,
// a.b.example.co.uk -> example.co.uk.
//
// Domain registration is a property of the registrable apex, not of a subdomain:
// every subdomain shares its parent's registration, and a registry's RDAP/WHOIS
// server returns 404 for a non-registrable name. Callers use this to look up (and
// deduplicate) registration once per apex rather than once per discovered name.
//
// When the name cannot be reduced (it is already a public suffix, or is
// unparseable) it is returned unchanged so the caller can still attempt the
// lookup rather than dropping it silently.
func RegistrableApex(name string) string {
	apex, err := publicsuffix.Domain(name)
	if err != nil {
		return name
	}
	return apex
}
