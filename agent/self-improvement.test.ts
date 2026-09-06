import { describe, expect, test } from 'bun:test';
import { applyConfidenceGuard, evaluateScan, improvementCandidates } from './self-improvement';
import type { InvestigationReport } from './types';

const report = {
  target: { id: 'target', hostname: 'example.test', authorizationStatus: 'admin_override' }, summary: '', conversation: [], tls: [], relations: [], identities: [], startedAt: '', completedAt: '',
  assets: [{ key: 'service:example.test:443:unknown', kind: 'service', label: 'Unknown web service', subtitle: '', state: 'unknown', confidence: 30, basis: 'observed', details: [] }],
  findings: [{ title: 'Observed service', summary: 'An observed service requires review.', severity: 'low', confidence: 80, asset: 'https://example.test', evidence: ['GET https://example.test returned 200'], remediation: 'Review the service.', sourceUrls: [], cveIds: [], weaknessIds: [], assetKey: 'service:example.test:443:unknown', relatedAssetKeys: [], relationKey: '' }],
  actions: [{ tool: 'inspect_http', input: {}, summary: '{"status":200}', at: '' }, { tool: 'query_nvd', input: {}, summary: '{"_wellguardError":"timeout"}', at: '' }]
} as InvestigationReport;

describe('governed self-improvement', () => {
  test('scores retained evidence and detects failures and unresolved services', () => {
    const result = evaluateScan(report, { hits: 2, misses: 1, revalidations: 0, staleUses: 0, originRequests: 1, skipped: 0, bySource: {} });
    expect(result.toolErrors).toBe(1); expect(result.unknownServices).toBe(1); expect(result.cacheHits).toBe(2); expect(result.qualityScore).toBeGreaterThan(50);
  });
  test('requires repeated feedback before proposing a confidence cap', () => {
    expect(improvementCandidates({ falsePositivePatterns: [{ patternKey: 'a', count: 1 }], evaluations: [] })).toHaveLength(0);
    const items = improvementCandidates({ falsePositivePatterns: [{ patternKey: 'a', count: 2 }], evaluations: [] });
    expect(items[0]?.recommendedAction).toBe('cap-confidence');
  });
  test('applies only an approved code-owned confidence cap', () => {
    expect(applyConfidenceGuard({ confidence: 92 }, 'a', { confidenceCaps: { a: 60 }, prioritizeUnknownServices: false, proposalIds: [] }).confidence).toBe(60);
  });
});
