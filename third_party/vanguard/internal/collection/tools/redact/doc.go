// Package redact is the single, shared evidence-redaction helper for the tool
// layer. It masks secrets and PII (credentials, tokens, API/access keys, bearer
// tokens, JWTs, PEM private keys, AWS access-key ids, and email addresses), drops
// non-printable bytes, caps the snippet, and stores only a hash of the raw
// observation for correlation. The raw bytes are never returned to callers and so
// never reach events.jsonl or the report.
//
// It is security-critical and deliberately conservative: when in doubt it
// over-masks, because over-redaction is the safe direction. The GoScans actor runs
// its evidence through these helpers, so the masking logic lives in exactly one
// place.
package redact
