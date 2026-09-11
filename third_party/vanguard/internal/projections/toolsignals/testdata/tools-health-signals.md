# Tool Health Signals

- Corpus: **3 scan(s)** (mode `root`)
- Min severity shown: `info`
- Signals shown: 10 (1 high, 8 medium, 1 low, 0 info)
- Note: log-integrity signals present; the numbers below may be incomplete.

## Integrity caveats

- **medium** `log-integrity/schema` - envelope schema version(s) [2] differ from expected 1 (seen in 02-beta)

## Signals

- **high** `waste/self-inflicted-rate-limit` (scan) on certspotter/t.example - certspotter hit a self-inflicted rate limit while double-querying t.example. seen in 03-gamma
- **medium** `attribution/target-gap` (scan) on crtsh - crtsh attributed only 10/100 events to a target (10%). seen in 03-gamma
- **medium** `diag/opaque-provider-error` (corpus) on subfinder - subfinder logged 5 opaque error(s) with no concrete cause. seen in 3 scans: 01-alpha, 02-beta, 03-gamma
- **medium** `hygiene/expected-outcome-at-warn` (corpus) on dnsinfo - dnsinfo logs 4 of 4 warns for expected benign outcomes (100%). seen in 3 scans: 01-alpha, 02-beta, 03-gamma
- **medium** `reliability/degradation-storm` (scan) on crtsh - crtsh burned 8 retry/degraded events. seen in 02-beta
- **medium** `reliability/failed-call-rate` (scan) on smtp - smtp failed 3 of 4 available calls (75%). seen in 03-gamma
- **medium** `trend/attribution-drop` (corpus) on crtsh - crtsh target-attribution ratio worsened from 90% to 10% across the corpus (monotonic worsening). seen in 3 scans: 01-alpha, 02-beta, 03-gamma
- **medium** `waste/duplicate-concurrent-query` (scan) on certspotter/t.example - certspotter queried t.example by 2 overlapping calls. seen in 03-gamma
- **low** `reliability/external-rate-limit` (scan) on netlas - netlas hit 1 external rate limit(s). seen in 03-gamma

## Per-tool corpus rollup

| Tool | Events | Errors | Warns | RateLimited | Calls | Failed |
|------|--------|--------|-------|-------------|-------|--------|
| certspotter | 3 | 1 | 0 | 1 | 2 | 0 |
| crtsh | 36 | 0 | 24 | 0 | 12 | 0 |
| dnsinfo | 48 | 0 | 12 | 0 | 36 | 0 |
| netlas | 2 | 1 | 0 | 1 | 1 | 0 |
| smtp | 7 | 0 | 3 | 0 | 4 | 3 |
| subfinder | 21 | 0 | 15 | 0 | 6 | 0 |

## Per-scan summary

| Scan | ScanID | Status | Events | Tools | High | Medium | Low | Info |
|------|--------|--------|--------|-------|------|--------|-----|------|
| 01-alpha | scan_alpha | ok | 100 | 3 | 0 | 0 | 2 | 0 |
| 02-beta | scan_beta | ok | 120 | 3 | 0 | 2 | 2 | 0 |
| 03-gamma | scan_gamma | ok | 90 | 6 | 1 | 3 | 3 | 0 |

1 subfolder(s) skipped (no tooling log): captures/not-a-scan

