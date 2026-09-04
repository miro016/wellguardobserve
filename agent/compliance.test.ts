import { describe, expect, test } from 'bun:test';
import { COMPLIANCE_REFERENCES, complianceCatalog, frameworkReferenceSchema, frameworkReferences } from './compliance';

describe('security framework reference catalog', () => {
  test('keeps references canonical, versioned, and directly linkable', () => {
    const references = complianceCatalog();
    expect(references.length).toBeGreaterThan(10);
    expect(new Set(references.map((reference) => reference.id)).size).toBe(references.length);
    expect(references.every((reference) => reference.url.startsWith('https://'))).toBeTrue();
    expect(COMPLIANCE_REFERENCES['v5.0.0-1.2.4'].control).toStartWith('v5.0.0-');
    expect(COMPLIANCE_REFERENCES['CRA-I-2j'].note).toContain('does not decide legal applicability or conformity');
  });

  test('normalizes model input to the server-owned reference text', () => {
    const parsed = frameworkReferenceSchema.parse({ control: 'WSTG-SESS-02', title: 'invented title' });
    expect(parsed.title).toBe('Testing for Cookies Attributes');
    expect(() => frameworkReferenceSchema.parse({ control: 'CRA-passed' })).toThrow();
    expect(frameworkReferences('CRA-II-3')[0]?.relationship).toBe('regulatory-relevance');
  });
});
