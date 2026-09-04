import { describe, expect, test } from 'bun:test';
import { customerNarrativeFor } from './customer-narrative';

describe('customer incident narratives', () => {
  test('explains a public management surface without claiming exploitation', () => {
    const narrative = customerNarrativeFor({
      title: 'File Browser file management surface is publicly reachable',
      summary: 'An anonymous request reached the identified File Browser interface.',
      severity: 'low', evidence: ['GET https://files.example.test/ returned 200.']
    });
    expect(narrative.observed).toContain('management or sign-in surface');
    expect(narrative.possibleAttack).toContain('unchanged credentials');
    expect(narrative.boundary).toContain('did not authenticate');
    expect(narrative.boundary).toContain('upload files');
    expect(narrative.boundary).toContain('elevate privileges');
  });

  test('does not invent an attack path for healthy informational evidence', () => {
    const narrative = customerNarrativeFor({
      title: 'TLS certificate is currently valid', summary: 'The certificate passed hostname and trust validation.',
      severity: 'info', evidence: ['TLS handshake completed.']
    });
    expect(narrative.possibleAttack).toStartWith('No attack path');
  });
});
