import { describe, expect, test } from 'bun:test';
import { policySnapshot, resolveScanProfile } from './profiles';

describe('scan profiles', () => {
  test('resolves unknown browser input to the standard server policy', () => {
    expect(resolveScanProfile('anything').id).toBe('standard');
  });

  test('extended capability is explicit and snapshot contains no internal gates', () => {
    const profile = resolveScanProfile('extended');
    const snapshot = policySnapshot(profile);
    expect(profile.allowNucleiAudit).toBe(true);
    expect(snapshot.maxActions).toBe(96);
    expect(snapshot.methods).toEqual(['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET']);
    expect(snapshot.nucleiPolicy).toContain('reviewed local templates only');
    expect(snapshot).not.toHaveProperty('agentInstructions');
  });
});

