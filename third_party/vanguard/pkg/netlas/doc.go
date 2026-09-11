// Package netlas is a thin, low-level HTTP client for the Netlas REST API
// (https://netlas.io). Netlas has no official Go SDK, so this package wraps the
// handful of endpoints vanguard needs: it owns transport, API-key authentication,
// pagination parameters, and non-2xx error mapping, and otherwise stays out of
// the way.
//
// It is deliberately not a domain tool: it does not emit events or know about
// vanguard's domain model. The per-result document is returned as raw JSON
// ([SearchItem.Data]) so each caller decodes only the fields it cares about. The
// vanguard Netlas tool (internal/collection/tools/reconpassive/netlas) builds on top of this
// wrapper and adds events, aggregation, and the domain translation.
//
// Netlas is a paid service: requests are authenticated with an API key sent in the
// X-Api-Key header, and search requests consume the account's request budget.
package netlas
