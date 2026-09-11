package entities

import "time"

// Evidence is a redacted proof artifact captured during a probe. It never holds
// credentials, PII, session tokens, or full sensitive bodies: only a short
// Summary, a size-capped RedactedSnippet with secrets masked, and a Hash of the
// raw observation for correlation. The raw bytes are not persisted.
type Evidence struct {
	// ID is the stable identifier referenced by the producing event.
	ID string
	// Kind classifies the artifact ("banner", "http-response", "zone", "handshake").
	Kind string
	// Summary is a short, non-sensitive description of what was observed.
	Summary string
	// RedactedSnippet is a size-capped excerpt with secrets masked.
	RedactedSnippet string
	// Hash is a hash of the raw observation, for correlation without storing raw bytes.
	Hash string
	// CapturedAt is when the evidence was captured.
	CapturedAt time.Time
}
