# intel catalogue

`catalogue.json` is a local-first, curated snapshot of exploit intelligence,
embedded into the binary by `intel.go`. Two parts:

- `knownExploited`: high-value CVEs known exploited in the wild (a trimmed CISA KEV
  highlight list). A discovered CVE finding matching one is flagged
  `known-exploited` and the risk model prioritises it.
- `defaultCredentials`: common product -> default-credential candidates. A
  discovered service whose product matches surfaces the candidate as a single,
  authorized starting guess for a gated credential check (never a brute force).

## Refreshing (manual, reviewed)

By design there is no automated upstream pull (that would add a network/runtime
dependency). To refresh:

1. Edit `catalogue.json`. Keep it small and curated - the high-value entries, not
   an exhaustive feed.
2. Bump `version` and set `released` to today (`YYYY-MM-DD`). The date is shown on
   enriched findings so an operator knows the snapshot's age.
3. Keep CVE ids canonical (`CVE-YYYY-NNNN`) and product aliases lower-case.
4. Run `task all` - the loader test parses and validates the file.

Automated refresh from an upstream feed is intentionally deferred; see
`docs/backlog/recon/passive-sources.md`.
