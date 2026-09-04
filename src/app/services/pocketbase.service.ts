import { Injectable, signal } from '@angular/core';
import PocketBase, { RecordModel } from 'pocketbase';
import { AgentActionRecord, AgentMessageRecord, CreateTargetInput, Finding, Scan, ScanRequest, Target, TlsObservation } from '../models';

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

  private target(record: RecordModel): Target {
    return {
      id: record.id, name: record['name'], hostname: record['hostname'], hostHints: record['hostHints'] ?? [],
      authorizationStatus: record['authorizationStatus'], status: record['status'], lastScanAt: record['lastScanAt'],
      assetCount: record['assetCount'] ?? 0, findingCount: record['findingCount'] ?? 0, posture: record['posture'] ?? 100
    } as Target;
  }

  isAdmin(): boolean { return this.user()?.['role'] === 'admin'; }

  async targets(): Promise<Target[]> {
    try {
      const records = await this.client.collection('targets').getFullList({ sort: '-created' });
      this.connected.set(true);
      return records.map((record) => this.target(record));
    } catch (error) { return this.failed(error); }
  }

  async createTarget(input: CreateTargetInput): Promise<Target> {
    if (!this.isAdmin() || !this.user()?.id) throw new Error('Only a workspace administrator can approve a target.');
    try {
      const record = await this.client.collection('targets').create({
        owner: this.user()!.id, name: input.name, hostname: input.hostname, hostHints: input.hostHints,
        authorizationStatus: 'admin_override', authorizationReason: input.authorizationReason,
        authorizedAt: new Date().toISOString(), allowPrivateAddresses: false, status: 'observed',
        assetCount: 1, findingCount: 0, posture: 100
      });
      return this.target(record);
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

  async scanForRequest(requestId: string): Promise<Scan | null> {
    try {
      const filter = this.client.filter('request = {:requestId}', { requestId });
      const r = await this.client.collection('scans').getFirstListItem(filter, { sort: '-created' });
      return { id: r.id, target: r['target'], request: r['request'], status: r['status'], startedAt: r['startedAt'], completedAt: r['completedAt'], summary: r['summary'] ?? '', error: r['error'] ?? '', created: r['created'] } as Scan;
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return null;
      return this.failed(error);
    }
  }

  async scanRequest(id: string): Promise<ScanRequest> {
    try {
      const r = await this.client.collection('scanRequests').getOne(id);
      return { id: r.id, target: r['target'], mode: r['mode'], status: r['status'], startedAt: r['startedAt'], completedAt: r['completedAt'], error: r['error'] ?? '', created: r['created'] } as ScanRequest;
    } catch (error) { return this.failed(error); }
  }

  async cancelScan(request: ScanRequest): Promise<void> {
    if (!['queued', 'processing'].includes(request.status)) return;
    await this.client.collection('scanRequests').update(request.id, { status: request.status === 'queued' ? 'cancelled' : 'cancelling' });
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

  async requestScan(targetId: string, mode: 'light' | 'standard' = 'standard'): Promise<string> {
    const record = await this.client.collection('scanRequests').create({ target: targetId, mode, status: 'queued' });
    return record.id;
  }
}
