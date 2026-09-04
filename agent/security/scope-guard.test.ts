import { describe, expect, test } from 'bun:test';
import { ScopeError, ScopeGuard, isPrivateAddress, normalizeHostname } from './scope-guard';

describe('ScopeGuard', () => {
  test('normalizes and allows only the authorized root and its subdomains', () => {
    const scope = new ScopeGuard({ id: '1', hostname: 'HTTPS://Example.COM/path', authorizationStatus: 'verified' });
    expect(scope.rootHostname).toBe('example.com');
    expect(scope.assertHostname('api.example.com')).toBe('api.example.com');
    expect(() => scope.assertHostname('example.com.attacker.test')).toThrow(ScopeError);
  });

  test('refuses targets without authorization', () => {
    expect(() => new ScopeGuard({ id: '1', hostname: 'example.com', authorizationStatus: 'pending' } as never)).toThrow(ScopeError);
  });

  test('allows only explicitly approved related hostnames, never their siblings', () => {
    const scope = new ScopeGuard({ id: '1', hostname: 'example.com', authorizedHosts: ['identity.shared-provider.test'], authorizationStatus: 'admin_override' });
    expect(scope.assertHostname('identity.shared-provider.test')).toBe('identity.shared-provider.test');
    expect(() => scope.assertHostname('other.shared-provider.test')).toThrow(ScopeError);
    expect(() => scope.assertHostname('child.identity.shared-provider.test')).toThrow(ScopeError);
  });

  test('classifies private, metadata and reserved destinations', () => {
    for (const address of ['127.0.0.1', '10.0.0.1', '172.16.4.2', '192.168.1.1', '169.254.169.254', '::1', 'fd00::1']) {
      expect(isPrivateAddress(address)).toBeTrue();
    }
    expect(isPrivateAddress('1.1.1.1')).toBeFalse();
    expect(isPrivateAddress('2606:4700:4700::1111')).toBeFalse();
  });

  test('rejects URL-like paths that could escape request scope', () => {
    const scope = new ScopeGuard({ id: '1', hostname: 'example.com', authorizationStatus: 'admin_override' });
    expect(scope.assertPath('/status')).toBe('/status');
    expect(() => scope.assertPath('//other.test')).toThrow(ScopeError);
    expect(() => scope.assertPath('https://other.test')).toThrow(ScopeError);
  });

  test('normalizes host values without accepting path material', () => {
    expect(normalizeHostname('https://Sub.Example.com:443/test')).toBe('sub.example.com');
  });
});
