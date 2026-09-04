import { isIP } from 'node:net';
import { resolve4, resolve6 } from 'node:dns/promises';
import type { AuthorizedTarget } from '../types';

export class ScopeError extends Error {}

export function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '').replace(/\.$/, '');
}

export function isPrivateAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (isIP(address) === 6) {
    const value = address.toLowerCase();
    return value === '::1' || value === '::' || value.startsWith('fc') || value.startsWith('fd') ||
      value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb') ||
      value.startsWith('ff') || value.startsWith('2001:db8:');
  }
  return true;
}

export class ScopeGuard {
  readonly rootHostname: string;

  constructor(readonly target: AuthorizedTarget) {
    if (!['verified', 'admin_override'].includes(target.authorizationStatus)) {
      throw new ScopeError('Target does not have a valid authorization state.');
    }
    this.rootHostname = normalizeHostname(target.hostname);
    if (!this.rootHostname || (!this.rootHostname.includes('.') && isIP(this.rootHostname) === 0)) {
      throw new ScopeError('Target hostname is invalid.');
    }
  }

  assertHostname(candidate?: string): string {
    const hostname = normalizeHostname(candidate || this.rootHostname);
    const exactHosts = (this.target.authorizedHosts || []).map(normalizeHostname);
    const inScope = hostname === this.rootHostname || hostname.endsWith(`.${this.rootHostname}`) || exactHosts.includes(hostname);
    if (!inScope) throw new ScopeError(`Host ${hostname} is outside the authorized root ${this.rootHostname}.`);
    return hostname;
  }

  async resolve(candidate?: string): Promise<Array<{ address: string; family: 4 | 6 }>> {
    const hostname = this.assertHostname(candidate);
    if (isIP(hostname)) {
      this.assertAddress(hostname);
      return [{ address: hostname, family: isIP(hostname) as 4 | 6 }];
    }
    const [v4, v6] = await Promise.all([
      resolve4(hostname).catch(() => []),
      resolve6(hostname).catch(() => [])
    ]);
    const addresses = [
      ...v4.map((address) => ({ address, family: 4 as const })),
      ...v6.map((address) => ({ address, family: 6 as const }))
    ];
    if (!addresses.length) throw new ScopeError(`No DNS addresses resolved for ${hostname}.`);
    addresses.forEach(({ address }) => this.assertAddress(address));
    return addresses;
  }

  assertAddress(address: string): void {
    if (!this.target.allowPrivateAddresses && isPrivateAddress(address)) {
      throw new ScopeError(`Address ${address} is private, reserved, or otherwise blocked by scan policy.`);
    }
  }

  assertPath(path: string): string {
    const value = path.trim() || '/';
    if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.length > 512) {
      throw new ScopeError('HTTP path must be a bounded relative path.');
    }
    return value;
  }
}
