import { describe, expect, test } from 'bun:test';
import { buildKnowledgePatterns, findingLifecycle, latestCompletedScans } from '../src/app/services/posture-intelligence';
import type { Finding, Scan } from '../src/app/models';

const scans: Scan[] = [
  { id: 'new-scan', target: 'target', status: 'completed', startedAt: '2026-09-05T10:00:00Z', completedAt: '2026-09-05T10:01:00Z', summary: '', error: '', created: '2026-09-05T10:00:00Z' },
  { id: 'old-scan', target: 'target', status: 'completed', startedAt: '2026-09-01T10:00:00Z', completedAt: '2026-09-01T10:01:00Z', summary: '', error: '', created: '2026-09-01T10:00:00Z' }
];
const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: 'finding', target: 'target', scan: 'new-scan', title: 'Public admin endpoint', summary: 'An administrator endpoint is public.', severity: 'high', confidence: 95,
  asset: 'https://admin.example.test', evidence: [], remediation: 'Restrict the endpoint.', sourceUrls: [], cveIds: [], weaknessIds: ['CWE-284'], frameworkRefs: [], customerNarrative: null,
  assetKey: 'service:admin.example.test:443:keycloak', relatedAssetKeys: [], relationKey: '', observations: [{ scan: 'new-scan', observedAt: '2026-09-05T10:01:00Z' }], runCount: 1,
  created: '2026-09-05T10:01:00Z', status: 'open', ...overrides
});

describe('posture intelligence', () => {
  test('does not equate absence in the latest scan with resolution', () => {
    const latest = latestCompletedScans(scans).get('target');
    expect(findingLifecycle(finding({ scan: 'old-scan' }), latest?.id)).toBe('not_observed');
    expect(findingLifecycle(finding({ status: 'resolved' }), latest?.id)).toBe('resolved');
  });

  test('separates new and persistent current observations', () => {
    expect(findingLifecycle(finding(), 'new-scan')).toBe('new');
    expect(findingLifecycle(finding({ runCount: 2, observations: [{ scan: 'old-scan', observedAt: '2026-09-01T10:01:00Z' }, { scan: 'new-scan', observedAt: '2026-09-05T10:01:00Z' }] }), 'new-scan')).toBe('persistent');
  });

  test('aggregates repeat patterns across targets', () => {
    const patterns = buildKnowledgePatterns([finding(), finding({ id: 'second', target: 'target-two', scan: 'second-scan' })], [...scans, { ...scans[0]!, id: 'second-scan', target: 'target-two' }]);
    expect(patterns).toHaveLength(1);
    expect(patterns[0]?.occurrences).toBe(2);
    expect(patterns[0]?.affectedTargetIds).toHaveLength(2);
  });
});
