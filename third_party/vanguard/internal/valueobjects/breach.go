package valueobjects

// BreachedAlias records a single email alias on a domain that appears in known
// data breaches, together with the breaches that exposed it.
type BreachedAlias struct {
	// Alias is the local part of the email address (before the @).
	Alias string
	// Breaches are the names of the breaches that exposed the alias
	// (for example "Adobe", "LinkedIn").
	Breaches []string
}
