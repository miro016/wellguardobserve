import { Injectable, signal } from '@angular/core';
import PocketBase, { RecordModel } from 'pocketbase';
import { AgentActionRecord, AgentMessageRecord, Finding, Scan, Target, TlsObservation } from '../models';

@Injectable({ providedIn: 'root' })
export class PocketBaseService {
  readonly client = new PocketBase(window.location.origin);
  readonly connected = signal(false);
  readonly user = signal<RecordModel | null>(this.client.authStore.record);
  readonly lastError = signal('');

  constructor() {
    this.client.autoCancellation(false);
    this.client.authStore.onChange(() => this.user.set(this.client.authStore.record));
  }

  async signIn(email: string, password: string): Promise<void> {
    await this.client.collection('users').authWithPassword(email, password);
    this.connected.set(true);
  }
  signOut(): void { this.client.authStore.clear(); }
  private failed(error: unknown): never {
    this.lastError.set(error instanceof Error ? error.message : 'PocketBase request failed.');
    throw error;
  }

  async targets(): Promise<Target[]> {
    try {
      const records = await this.client.collection('targets').getFullList({ sort: '-created' });
      this.connected.set(true);
      return records.map((r) => ({ id: r.id, name: r['name'], hostname: r['hostname'], authorizationStatus: r['authorizationStatus'], status: r['status'], lastScanAt: r['lastScanAt'], assetCount: r['assetCount'] ?? 0, findingCount: r['findingCount'] ?? 0, posture: r['posture'] ?? 100 } as Target));
    } catch (error) { return this.failed(error); }
  }

  async findings(targetId?: string): Promise<Finding[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : '';
      const records = await this.client.collection('findings').getFullList({ filter, sort: '-created' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], title: r['title'], summary: r['summary'], severity: r['severity'], confidence: r['confidence'], asset: r['asset'], evidence: r['evidence'] ?? [], remediation: r['remediation'] ?? '', sourceUrls: r['sourceUrls'] ?? [], created: r['created'], status: r['status'] } as Finding));
    } catch (error) { return this.failed(error); }
  }

  async tls(targetId?: string): Promise<TlsObservation | null> {
    try {
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : '';
      const r = await this.client.collection('tlsObservations').getFirstListItem(filter, { sort: '-created' });
      return { id: r.id, scan: r['scan'], ...(r['details'] as TlsObservation) };
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return null;
      return this.failed(error);
    }
  }

  async scans(targetId?: string): Promise<Scan[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : '';
      const records = await this.client.collection('scans').getFullList({ filter, sort: '-created' });
      return records.map((r) => ({ id: r.id, target: r['target'], request: r['request'], status: r['status'], startedAt: r['startedAt'], completedAt: r['completedAt'], summary: r['summary'] ?? '', error: r['error'] ?? '', created: r['created'] } as Scan));
    } catch (error) { return this.failed(error); }
  }

  async agentActions(options: { targetId?: string; scanId?: string } = {}): Promise<AgentActionRecord[]> {
    try {
      const clauses: string[] = [];
      if (options.targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId: options.targetId }));
      if (options.scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId: options.scanId }));
      const records = await this.client.collection('agentActions').getFullList({ filter: clauses.join(' && '), sort: 'occurredAt' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], tool: r['tool'], input: r['input'] ?? {}, summary: r['summary'] ?? '', occurredAt: r['occurredAt'] }));
    } catch (error) { return this.failed(error); }
  }

  async agentMessages(options: { targetId?: string; scanId?: string } = {}): Promise<AgentMessageRecord[]> {
    try {
      const clauses: string[] = [];
      if (options.targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId: options.targetId }));
      if (options.scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId: options.scanId }));
      const records = await this.client.collection('agentMessages').getFullList({ filter: clauses.join(' && '), sort: 'sequence' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], role: r['role'], content: r['content'] ?? '', toolName: r['toolName'] ?? '', sequence: r['sequence'] ?? 0, occurredAt: r['occurredAt'] }));
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return [];
      return this.failed(error);
    }
  }

  async requestScan(targetId: string, mode: 'light' | 'standard' = 'standard'): Promise<void> {
    await this.client.collection('scanRequests').create({ target: targetId, mode, status: 'queued' });
  }
}
