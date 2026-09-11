package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// DefaultSnippetCap bounds the size of a redacted evidence snippet. Evidence is a
// proof of exposure, not a data capture, so the snippet stays small.
const DefaultSnippetCap = 256

// secretPatterns mask obvious secrets and PII in an evidence snippet before it is
// stored. The intent is conservative: when in doubt, mask. Each pattern either keeps
// a sensitive key visible and replaces only the value, or replaces the whole
// sensitive token, so the snippet still reads as evidence without leaking the
// secret. This is the single, shared redaction every tool goes through; no raw
// sensitive bytes are persisted to events.jsonl or the report.
var secretPatterns = []*regexp.Regexp{
	// key: value / key=value for sensitive keys. No leading word boundary, so a
	// prefixed key (DB_PASSWORD, X-Api-Key) still matches; over-masking is the safe
	// direction for redaction.
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|session|cookie)["']?\s*[:=]\s*\S+`),
	// Authorization: Bearer <token> style.
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`),
	// AWS-style access key ids.
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	// JWT / JWS compact tokens (three base64url segments starting "eyJ...").
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	// PEM private-key blocks: mask the whole block, not just the header.
	regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
	// Email addresses are PII; mask the local part and domain, keep nothing.
	regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
}

// maskSecrets replaces secret-looking substrings with a redaction marker.
func maskSecrets(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// Snippet masks secrets, drops non-printable bytes, and caps the length, so no
// tool returns raw sensitive bytes. limit <= 0 uses DefaultSnippetCap.
func Snippet(s string, limit int) string {
	if limit <= 0 {
		limit = DefaultSnippetCap
	}
	s = maskSecrets(s)
	s = strings.Map(func(r rune) rune {
		// Keep printable ASCII and common whitespace; drop the rest so a binary
		// banner cannot smuggle control bytes into the report.
		if r == '\n' || r == '\t' || (r >= 0x20 && r < 0x7f) {
			return r
		}
		return -1
	}, s)
	if len(s) > limit {
		return s[:limit] + "...(truncated)"
	}
	return s
}

// Hash returns the hex SHA-256 of b, the correlation hash stored on evidence so a
// raw observation can be matched without persisting it.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
