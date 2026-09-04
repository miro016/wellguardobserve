import { describe, expect, test } from 'bun:test';
import { parseNucleiJsonl } from './nuclei';

describe('reviewed Nuclei result parser', () => {
  test('accepts only locally reviewed template identifiers and canonicalizes the public URL', () => {
    const output = [
      JSON.stringify({ 'template-id': 'wellguard-go-expvar', 'matched-at': 'https://203.0.113.5:8443/debug/vars', ip: '203.0.113.5', info: { name: 'Public Go expvar diagnostics' } }),
      JSON.stringify({ 'template-id': 'unreviewed-template', 'matched-at': 'https://203.0.113.5:8443/anything', info: { severity: 'critical' } }),
      'not json'
    ].join('\n');
    const matches = parseNucleiJsonl(output, 'lab.example.com', 8443, true);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.url).toBe('https://lab.example.com:8443/debug/vars');
    expect(matches[0]?.severity).toBe('medium');
  });
});
