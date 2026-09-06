import { describe, expect, test } from 'bun:test';
import type { GeneratedToolDefinition } from './generated-tools';
import { generatedToolEligible, validateGeneratedTool } from './generated-tools';

const proposal = {
  name: 'review-public-schema', title: 'Review a public API schema',
  summary: 'Read a discovered schema and verify that it has the expected document shape.',
  rationale: 'A frontend bundle exposed a schema path that no installed inspector currently interprets.',
  category: 'api' as const, evidence: ['Frontend bundle contained the same-origin /openapi.json path.'],
  spec: { version: 'http-probe-v1' as const, steps: [{ id: 'read-schema', purpose: 'Confirm that the discovered document is an API schema.', method: 'GET' as const, path: '/openapi.json', assertions: [{ type: 'json-key-exists' as const, path: 'paths' }] }] }
};

describe('generated declarative tools', () => {
  test('validates and fingerprints a same-origin request plan', () => {
    const result = validateGeneratedTool(proposal);
    expect(result.validation.valid).toBe(true);
    expect(result.validation.checksum).toHaveLength(64);
    expect(result.validation.compatibleProfiles).toEqual(['light', 'standard', 'extended', 'advanced', 'unbounded']);
    expect(result.validation.riskLevel).toBe('passive');
  });

  test('rejects paths that could escape same-origin request policy', () => {
    const result = validateGeneratedTool({ ...proposal, spec: { ...proposal.spec, steps: [{ ...proposal.spec.steps[0], path: '//metadata.internal/' }] } });
    expect(result.validation.valid).toBe(false);
  });

  test('keeps generated POST probes out of read-only profiles', () => {
    const result = validateGeneratedTool({ ...proposal, spec: { version: 'http-probe-v1', steps: [{ id: 'submit-control', purpose: 'Compare a bounded anonymous JSON control response.', method: 'POST_JSON', path: '/api/check', body: { value: 'wellguard-control' }, assertions: [{ type: 'status-in', values: [200, 400, 401, 403] }] }] } });
    expect(result.validation.compatibleProfiles).toEqual(['advanced', 'unbounded']);
  });

  test('allows proposed tools only in explicitly automatic unbounded mode', () => {
    const validation = validateGeneratedTool(proposal).validation;
    const definition = { ...proposal, id: 'tool', workspace: 'space', checksum: validation.checksum, status: 'proposed', minProfile: 'unbounded', unboundedAutoUse: true, compatibleProfiles: validation.compatibleProfiles, requestCeiling: 1, riskLevel: 'passive', generatedByModel: 'model', sourceScan: 'scan', sourceTarget: 'target', reviewedBy: '', reviewedAt: '', reviewNote: '', created: '', updated: '' } as GeneratedToolDefinition;
    expect(generatedToolEligible(definition, 'standard')).toBe(false);
    expect(generatedToolEligible(definition, 'unbounded')).toBe(true);
    expect(generatedToolEligible({ ...definition, unboundedAutoUse: false }, 'unbounded')).toBe(false);
    expect(generatedToolEligible({ ...definition, status: 'rejected' }, 'unbounded')).toBe(false);
  });
});
