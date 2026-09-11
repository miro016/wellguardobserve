package intel

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed catalogue.json
var catalogueJSON []byte

// rawCatalogue is the on-disk shape of catalogue.json.
type rawCatalogue struct {
	Version            string       `json:"version"`
	Released           string       `json:"released"`
	Source             string       `json:"source"`
	KnownExploited     []kevRecord  `json:"knownExploited"`
	DefaultCredentials []credRecord `json:"defaultCredentials"`
}

type kevRecord struct {
	CVE  string `json:"cve"`
	Name string `json:"name"`
}

type credRecord struct {
	Products  []string `json:"products"`
	Candidate string   `json:"candidate"`
	Note      string   `json:"note"`
}

// KEVEntry is a known-exploited vulnerability the catalogue carries.
type KEVEntry struct {
	// CVE is the canonical (upper-case) identifier.
	CVE string
	// Name is a short human label for the vulnerability.
	Name string
}

// DefaultCred is a product's well-known default-credential candidate.
type DefaultCred struct {
	// Product is the matched product alias (lower-case).
	Product string
	// Candidate is the default credential to try first ("user:pass" or a note like
	// "(unauthenticated by default)"). It is a starting guess for an authorized,
	// gated check, never an unbounded brute force.
	Candidate string
	// Note explains the candidate.
	Note string
}

// Catalogue is a local, dated snapshot of exploit intelligence: a trimmed
// known-exploited-vulnerabilities (CISA KEV) list and a small default-credential
// map. It is bundled in the repo and loaded from the embedded file, so enrichment
// is offline, reproducible, and replay-stable - no scan-time network dependency.
type Catalogue struct {
	// Version is the snapshot version tag.
	Version string
	// Released is the snapshot date, so an operator knows its age.
	Released time.Time
	// Source describes the snapshot and how it is maintained.
	Source string

	kev   map[string]KEVEntry    // key: upper-case CVE
	creds map[string]DefaultCred // key: lower-case product alias
}

var (
	defaultOnce sync.Once
	defaultCat  *Catalogue
)

// Default returns the bundled catalogue, parsed once and cached. Parsing the
// embedded file cannot fail in a built binary, but if it ever did the catalogue
// degrades to empty (enrichment becomes a no-op) rather than panicking, keeping
// the feature optional.
func Default() *Catalogue {
	defaultOnce.Do(func() {
		c, err := parse(catalogueJSON)
		if err != nil {
			c = &Catalogue{kev: map[string]KEVEntry{}, creds: map[string]DefaultCred{}}
		}
		defaultCat = c
	})
	return defaultCat
}

// parse builds a Catalogue from the raw JSON, indexing it for O(1) lookup.
func parse(data []byte) (*Catalogue, error) {
	var raw rawCatalogue
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("intel: parse catalogue: %w", err)
	}
	released, err := time.Parse("2006-01-02", raw.Released)
	if err != nil {
		return nil, fmt.Errorf("intel: parse released date %q: %w", raw.Released, err)
	}
	c := &Catalogue{
		Version:  raw.Version,
		Released: released,
		Source:   raw.Source,
		kev:      make(map[string]KEVEntry, len(raw.KnownExploited)),
		creds:    make(map[string]DefaultCred, len(raw.DefaultCredentials)),
	}
	for _, k := range raw.KnownExploited {
		cve := normalizeCVE(k.CVE)
		if cve == "" {
			continue
		}
		c.kev[cve] = KEVEntry{CVE: cve, Name: k.Name}
	}
	for _, r := range raw.DefaultCredentials {
		for _, p := range r.Products {
			alias := strings.ToLower(strings.TrimSpace(p))
			if alias == "" {
				continue
			}
			c.creds[alias] = DefaultCred{Product: alias, Candidate: r.Candidate, Note: r.Note}
		}
	}
	return c, nil
}

// KnownExploited reports whether cve is in the known-exploited snapshot, returning
// the entry. The lookup is case-insensitive.
func (c *Catalogue) KnownExploited(cve string) (KEVEntry, bool) {
	e, ok := c.kev[normalizeCVE(cve)]
	return e, ok
}

// DefaultCredentials returns the default-credential candidate for a product, if the
// catalogue has one. It matches a catalogue alias as a whole-word-ish substring of
// the (lower-cased) product string, so an nmap product like "Apache Tomcat" matches
// the "tomcat" alias. The longest matching alias wins for determinism.
func (c *Catalogue) DefaultCredentials(product string) (DefaultCred, bool) {
	p := strings.ToLower(strings.TrimSpace(product))
	if p == "" {
		return DefaultCred{}, false
	}
	if dc, ok := c.creds[p]; ok {
		return dc, true
	}
	var best DefaultCred
	found := false
	for alias, dc := range c.creds {
		if strings.Contains(p, alias) && len(alias) > len(best.Product) {
			best, found = dc, true
		}
	}
	return best, found
}

// Reference is a short, dated catalogue tag for citing the snapshot on a finding.
func (c *Catalogue) Reference() string {
	return fmt.Sprintf("CISA KEV snapshot %s (%s)", c.Version, c.Released.Format("2006-01-02"))
}

// normalizeCVE upper-cases and trims a CVE id for stable keying.
func normalizeCVE(cve string) string {
	return strings.ToUpper(strings.TrimSpace(cve))
}
