import { describe, expect, test } from 'bun:test';
import { customerNarrativeFor } from './customer-narrative';

describe('customer incident narratives', () => {
  test('explains a public management surface without claiming exploitation', () => {
    const narrative = customerNarrativeFor({
      title: 'File Browser file management surface is publicly reachable',
      summary: 'An anonymous request reached the identified File Browser interface.',
      severity: 'low', evidence: ['GET https://files.example.test/ returned 200.']
    });
    expect(narrative.observed).toContain('file-management service');
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

  test('explains a directory listing as a bounded potential incident path', () => {
    const narrative = customerNarrativeFor({
      title: 'Public directory index exposes backup filenames',
      summary: 'A generated directory listing exposes backup-like names.',
      severity: 'medium', evidence: ['No listed file was downloaded.']
    });
    expect(narrative.observed).toContain('public file list');
    expect(narrative.possibleAttack).toContain('attempt to retrieve');
    expect(narrative.businessImpact).toContain('If a listed file were retrievable');
    expect(narrative.boundary).toContain('did not authenticate');
  });

  test('describes a file manager without claiming a credential attempt', () => {
    const narrative = customerNarrativeFor({
      title: 'File Browser management UI is exposed',
      summary: 'The File Browser sign-in page is public.',
      severity: 'high', evidence: ['Anonymous GET returned the login page.']
    });
    expect(narrative.possibleAttack).toContain('unchanged credentials');
    expect(narrative.businessImpact).toContain('over-privileged');
    expect(narrative.boundary).toContain('not authenticate');
  });
});
