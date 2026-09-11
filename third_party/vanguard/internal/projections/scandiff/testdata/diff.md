# Scan Diff

- Baseline (A): **example.com** (scan `scanA`, 6 events)
- Candidate (B): **example.com** (scan `scanB`, 5 events)

## Summary

Findings: candidate adds 1 critical; resolves 1 high.

- Matched: 1
- Changed: 1
- Missing: 2
- Unexpected: 2

Issues (operational, not diffed): baseline 1, candidate 0.

| Type | Matched | Changed | Missing | Unexpected |
|------|---------|---------|---------|------------|
| DnsDomainNameDiscovered | 1 | 0 | 1 | 1 |
| FindingRaised | 0 | 0 | 1 | 1 |
| ServiceDiscovered | 0 | 1 | 0 | 0 |

## Coverage

| Entity | Baseline | Candidate | Common | Gained | Lost |
|--------|----------|-----------|--------|--------|------|
| domains | 2 | 2 | 1 | 1 | 1 |
| ips | 1 | 1 | 1 | 0 | 0 |
| services | 1 | 1 | 1 | 0 | 0 |
| endpoints | 0 | 0 | 0 | 0 | 0 |
| certificates | 0 | 0 | 0 | 0 | 0 |
| findings | 1 | 1 | 0 | 1 | 1 |
| netblocks | 0 | 0 | 0 | 0 | 0 |

### domains

- gained (1): new.example.com
- lost (1): gone.example.com

### findings

- gained (1): exposed-env|domain|new.example.com
- lost (1): weak-tls|domain|gone.example.com

## Findings

### New (1)

- **exposed-env** (critical) on domain new.example.com

### Resolved (1)

- **weak-tls** (high) on domain gone.example.com

## Changes

### ServiceDiscovered

- `203.0.113.10|443/tcp`
  - product: nginx -> apache

## Appeared (unexpected in B)

- DnsDomainNameDiscovered new.example.com
- FindingRaised exposed-env|domain|new.example.com

## Disappeared (missing from B)

- DnsDomainNameDiscovered gone.example.com
- FindingRaised weak-tls|domain|gone.example.com

## Operational

| Provider | Calls A->B | Failed A->B | Empties A->B |
|----------|------------|-------------|--------------|
| censys | 3->1 | 0->2 | 1->0 |
| crtsh | 1->1 | 0->0 | 0->0 |

