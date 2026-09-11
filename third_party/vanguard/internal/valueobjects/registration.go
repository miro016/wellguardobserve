package valueobjects

// RegistrationContact is one contact record from a domain's registration data
// (WHOIS or RDAP), such as the registrant, administrative, or technical contact.
type RegistrationContact struct {
	// Role identifies the contact type (e.g. "registrant", "administrative",
	// "technical", "registrar").
	Role string
	// Name is the contact's personal or entity name.
	Name string
	// Organization is the contact's organization, if distinct from Name.
	Organization string
	// Email is the contact's email address.
	Email string
	// Phone is the contact's phone number, including any extension.
	Phone string
	// Address is the contact's postal address, joined into a single line.
	Address string
}
