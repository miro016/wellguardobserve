package crtsh

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// cacheDataJSON is the compiled-in crt.sh result fixture. It is package data, not a
// runtime file: the collector reads no cache directory, so adding results means
// editing cache_data.json and recompiling.
//
//go:embed cache_data.json
var cacheDataJSON []byte

// cacheData is the decoded shape of cache_data.json. Queries is keyed by the exact
// request query the client would send - the bare domain for FetchDomain and the
// "%."-prefixed wildcard for FetchSubdomains - so the two searches for one domain stay
// distinct entries. There is no partial matching, so an absent key is a miss. The
// nested objects decode straight into [SearchResult], so their JSON keys are that
// type's Go field names.
type cacheData struct {
	// Queries holds one search result per cached request query.
	Queries map[string]SearchResult `json:"queries"`
}

// cache is the validated, read-only lookup built from cacheDataJSON. It is never
// mutated after loadCache returns, so it needs no lock, refresh, or persistence, and
// every lookup hands back a deep copy so a caller cannot write through to the fixture.
type cache struct {
	queries map[string]SearchResult
}

// loadCache decodes and validates the embedded fixture. A cache-using Client calls it
// during construction so malformed data fails fast instead of mid-crawl.
func loadCache() (*cache, error) {
	var data cacheData
	dec := json.NewDecoder(bytes.NewReader(cacheDataJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("crtsh: decode embedded cache: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("crtsh: decode embedded cache: multiple JSON values")
		}
		return nil, fmt.Errorf("crtsh: decode embedded cache trailing data: %w", err)
	}
	for query, entry := range data.Queries {
		if err := validateQueryEntry(query, entry); err != nil {
			return nil, err
		}
	}
	return &cache{queries: data.Queries}, nil
}

// validateQueryEntry rejects an entry that could not have come from a real search: an
// empty or unnormalized query key, a wildcard query with no domain after the prefix,
// the same crt.sh certificate id twice within one query, or a certificate with no CT
// log timestamp or a validity window that ends before it starts.
func validateQueryEntry(query string, entry SearchResult) error {
	if query == "" {
		return fmt.Errorf("crtsh: embedded cache has an empty query key")
	}
	if query != normalizeQuery(query) {
		return fmt.Errorf("crtsh: embedded cache query %q is not normalized", query)
	}
	if strings.TrimPrefix(query, "%.") == "" {
		return fmt.Errorf("crtsh: embedded cache query %q has no domain", query)
	}
	seen := make(map[int64]bool, len(entry.Certs))
	for i := range entry.Certs {
		cert := &entry.Certs[i]
		if cert.ID == 0 {
			return fmt.Errorf("crtsh: embedded cache query %q has a certificate without an id", query)
		}
		if seen[cert.ID] {
			return fmt.Errorf("crtsh: embedded cache query %q lists certificate %d twice", query, cert.ID)
		}
		seen[cert.ID] = true
		if cert.EntryTimestamp.IsZero() {
			return fmt.Errorf("crtsh: embedded cache query %q certificate %d has no CT log timestamp", query, cert.ID)
		}
		if !cert.NotAfter.After(cert.NotBefore) {
			return fmt.Errorf("crtsh: embedded cache query %q certificate %d expires before it starts", query, cert.ID)
		}
	}
	return nil
}

// normalizeQuery is the single normalization used for cache keys and lookups, so a
// cached key matches exactly the query the client would send.
func normalizeQuery(query string) string {
	return strings.ToLower(strings.TrimSpace(query))
}

// resultFor returns a deep copy of the cached result for the exact request query. The
// bool is false when the query is not cached.
func (c *cache) resultFor(query string) (SearchResult, bool) {
	entry, ok := c.queries[normalizeQuery(query)]
	if !ok {
		return SearchResult{}, false
	}
	return SearchResult{Certs: copyCerts(entry.Certs), DegradedEmpty: entry.DegradedEmpty}, true
}

// copyCerts deep-copies certificates, including each certificate's name slice, so a
// mutated result cannot reach back into the fixture.
func copyCerts(in []Certificate) []Certificate {
	if in == nil {
		return nil
	}
	out := make([]Certificate, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Domains = copyStrings(in[i].Domains)
	}
	return out
}

// copyStrings copies a string slice, preserving nil so a copy compares equal to its
// original.
func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
