import { describe, expect, test } from 'bun:test';
import { buildKnowledgeObservation, knowledgeCategory } from './knowledge';
import type { AgentAsset, AgentFinding } from './types';

const finding = (overrides: Partial<AgentFinding> = {}): AgentFinding => ({
  title: 'Default administrator credentials remain enabled', summary: 'The public login accepted a documented default credential.',
  severity: 'critical', confidence: 100, asset: 'https://admin.example.test', evidence: [], remediation: 'Disable the default account and rotate credentials.',
  sourceUrls: [], cveIds: [], weaknessIds: ['CWE-1392'], assetKey: 'service:admin.example.test:443:filebrowser', ...overrides
});

describe('knowledge observation classification', () => {
  test('creates a stable technology-specific pattern', () => {
    const assets: AgentAsset[] = [{ key: 'service:admin.example.test:443:filebrowser', kind: 'service', label: 'File Browser', subtitle: 'admin.example.test', state: 'risk', confidence: 100, basis: 'observed', details: [] }];
    const first = buildKnowledgeObservation(finding(), assets);
    const second = buildKnowledgeObservation(finding({ asset: 'https://other.example.test' }), assets);
    expect(first.category).toBe('Identity & access');
    expect(first.technology).toBe('File Browser');
    expect(first.patternKey).toBe(second.patternKey);
    expect(first.assetKind).toBe('service');
  });

  test('classifies transport and patch lifecycle without product-specific code', () => {
    expect(knowledgeCategory(finding({ title: 'TLS certificate expires soon', summary: '', weaknessIds: [] }))).toBe('Transport security');
    expect(knowledgeCategory(finding({ title: 'Unsupported service version', summary: 'CVE evidence is public.', weaknessIds: [] }))).toBe('Patch & lifecycle');
  });
});
