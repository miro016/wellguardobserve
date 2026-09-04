import { describe, expect, test } from 'bun:test';
import { policySnapshot, resolveScanProfile } from './profiles';

describe('scan profiles', () => {
  test('resolves unknown browser input to the standard server policy', () => {
    expect(resolveScanProfile('anything').id).toBe('standard');
  });

  test('active validation is available without an extra consent gate and snapshot contains no internal gates', () => {
    const profile = resolveScanProfile('extended');
    const snapshot = policySnapshot(profile);
    expect(profile.allowNucleiAudit).toBe(true);
    expect(snapshot.maxActions).toBe(104);
    expect(snapshot.methods).toEqual(['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET']);
    expect(snapshot.nucleiPolicy).toContain('reviewed local templates only');
    expect(snapshot.consentRequired).toBe(false);
    expect(snapshot.enabledTools).toContain('bounded-rate-controls-v1');
    expect(snapshot).not.toHaveProperty('agentInstructions');
  });
});
