import { Injectable, signal } from '@angular/core';
import PocketBase, { RecordModel } from 'pocketbase';
import { Finding, Target, TlsObservation } from '../models';

const demoTarget: Target = {
  id: 'miroslav-petro-com',
  name: 'Personal infrastructure',
  hostname: 'miroslav-petro.com',
  authorizationStatus: 'admin_override',
  status: 'observed',
  lastScanAt: new Date().toISOString(),
  assetCount: 4,
  findingCount: 2,
  posture: 64
};

const demoFindings: Finding[] = [
  {
    id: 'public-management-surface',
    title: 'Infrastructure control panel is publicly reachable',
    summary: 'The public homepage identifies itself as an Easypanel management surface. Administrative interfaces deserve a narrower trust boundary even when authentication is enabled.',
    severity: 'high', confidence: 96, asset: 'miroslav-petro.com:443',
    evidence: ['HTTP 200 at the public origin', 'Document title: Easypanel', 'Server traffic passes through Cloudflare'],
    created: new Date().toISOString(), status: 'open'
  },
  {
    id: 'tls-valid',
    title: 'TLS certificate is healthy',
    summary: 'The certificate matches the host and is currently inside its validity window.',
    severity: 'info', confidence: 100, asset: 'miroslav-petro.com:443',
    evidence: ['Issuer: Google Trust Services WE1', 'SAN covers miroslav-petro.com and *.miroslav-petro.com'],
    created: new Date().toISOString(), status: 'open'
  }
];

const demoTls: TlsObservation = {
  hostname: 'miroslav-petro.com', valid: true, issuer: 'Google Trust Services / WE1',
  validFrom: '2026-07-17T20:21:26Z', validTo: '2026-10-15T21:19:01Z', daysRemaining: 41,
  protocol: 'TLSv1.3', subjectAltNames: ['miroslav-petro.com', '*.miroslav-petro.com']
};

@Injectable({ providedIn: 'root' })
export class PocketBaseService {
  readonly client = new PocketBase(window.location.origin);
  readonly connected = signal(false);
  readonly user = signal<RecordModel | null>(this.client.authStore.record);

  constructor() {
    this.client.autoCancellation(false);
    this.client.authStore.onChange(() => this.user.set(this.client.authStore.record));
  }

  async signIn(email: string, password: string): Promise<void> {
    await this.client.collection('users').authWithPassword(email, password);
    this.connected.set(true);
  }

  signOut(): void {
    this.client.authStore.clear();
  }

  async targets(): Promise<Target[]> {
    try {
      const records = await this.client.collection('targets').getFullList({ sort: '-created' });
      this.connected.set(true);
      return records.map((record) => ({
        id: record.id, name: record['name'], hostname: record['hostname'],
        authorizationStatus: record['authorizationStatus'], status: record['status'],
        lastScanAt: record['lastScanAt'], assetCount: record['assetCount'] ?? 0,
        findingCount: record['findingCount'] ?? 0, posture: record['posture'] ?? 100
      } as Target));
    } catch {
      return [demoTarget];
    }
  }

  async findings(targetId?: string): Promise<Finding[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : '';
      const records = await this.client.collection('findings').getFullList({ filter, sort: '-created' });
      return records.map((record) => ({
        id: record.id, title: record['title'], summary: record['summary'], severity: record['severity'],
        confidence: record['confidence'], asset: record['asset'], evidence: record['evidence'] ?? [],
        source: record['source'], created: record['created'], status: record['status']
      } as Finding));
    } catch {
      return demoFindings;
    }
  }

  async tls(targetId?: string): Promise<TlsObservation> {
    try {
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : '';
      const record = await this.client.collection('tlsObservations').getFirstListItem(filter, { sort: '-created' });
      return record['details'] as TlsObservation;
    } catch {
      return demoTls;
    }
  }

  async requestScan(targetId: string): Promise<void> {
    await this.client.collection('scanRequests').create({ target: targetId, mode: 'standard', status: 'queued' });
  }
}
