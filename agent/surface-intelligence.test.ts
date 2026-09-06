import { describe, expect, test } from 'bun:test';
import { assessFindingPriority, diffAssets, mergeTopologySnapshots } from '../src/app/services/surface-intelligence';
import type { AssetRecord, Finding } from '../src/app/models';

const asset = (key: string, label: string, subtitle = 'Observed', state: AssetRecord['state'] = 'observed'): AssetRecord => ({
  id: key, target: 'target', scan: 'scan', key, kind: key.startsWith('port:') ? 'port' : 'service', label, subtitle, state, confidence: 90, basis: 'observed', details: [{ label: 'Version', value: subtitle, evidence: 'Direct response.' }]
});
const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: 'finding', target: 'target', scan: 'scan', title: 'Internet-facing service has a confirmed vulnerable version', summary: 'A directly observed version matches a confirmed CVE.', severity: 'high', confidence: 90,
  asset: 'https://admin.example.test', evidence: ['CISA KEV known exploited vulnerability', 'EPSS: 72%', 'CVSS 4.0: 9.1'], remediation: 'Upgrade the affected service.', sourceUrls: [], cveIds: ['CVE-2026-12345'], weaknessIds: [], frameworkRefs: [], customerNarrative: null,
  assetKey: 'service:admin', relatedAssetKeys: [], relationKey: '', observations: [{ scan: 'scan', observedAt: '2026-09-06T10:00:00Z' }], runCount: 1, created: '2026-09-06T10:00:00Z', status: 'open', ...overrides
});

describe('surface intelligence', () => {
  test('diffs immutable asset snapshots without calling the agent', () => {
    const previous = [asset('service:admin', 'Admin', '1.0'), asset('port:server:8080', ':8080')];
    const current = [asset('service:admin', 'Admin', '2.0'), asset('service:api', 'API')];
    expect(diffAssets(current, previous).map((change) => `${change.state}:${change.assetKey}`)).toEqual([
      'added:service:api', 'changed:service:admin', 'not_observed:port:server:8080'
    ]);
  });

  test('keeps missing threat intelligence unknown while using retained KEV, EPSS and CVSS inputs', () => {
    const enriched = assessFindingPriority(finding(), 'critical', 'new');
    expect(enriched.kev).toBeTrue(); expect(enriched.epss).toBeCloseTo(0.72); expect(enriched.cvss).toBe(9.1); expect(enriched.score).toBe(100);
    const unknown = assessFindingPriority(finding({ evidence: [], threatContext: undefined }), 'low', 'not_observed');
    expect(unknown.kev).toBeNull(); expect(unknown.epss).toBeNull(); expect(unknown.factors.find((factor) => factor.label.startsWith('EPSS'))?.available).toBeFalse();
    expect(assessFindingPriority(finding({ evidence: ['Vector CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N'], threatContext: undefined }), 'standard', 'new').cvss).toBeNull();
  });

  test('marks graph additions, material changes and prior-only nodes', () => {
    const topology = (nodes: Array<{ id: string; label: string }>) => ({ nodes: nodes.map((node) => ({ ...node, kind: 'service' as const, subtitle: node.label, state: 'observed' as const, x: 0, y: 0, details: [], findingIds: [] })), edges: [] });
    const merged = mergeTopologySnapshots(topology([{ id: 'same', label: 'Changed' }, { id: 'new', label: 'New' }]), topology([{ id: 'same', label: 'Old' }, { id: 'gone', label: 'Gone' }]));
    expect(merged.nodes.find((node) => node.id === 'same')?.changeState).toBe('changed');
    expect(merged.nodes.find((node) => node.id === 'new')?.changeState).toBe('added');
    expect(merged.nodes.find((node) => node.id === 'gone')?.changeState).toBe('not_observed');
  });
});
