import { Injectable, signal } from '@angular/core';
import PocketBase, { RecordModel } from 'pocketbase';
import { AgentActionRecord, AgentMessageRecord, AssetRecord, AssetRelationRecord, ChangeReview, ChangeReviewStatus, CreateTargetInput, Finding, KnowledgeObservation, ObservationCadence, ObservationSchedule, PublicIdentity, Scan, ScanMode, ScanRequest, ScheduledScanMode, Target, TargetCriticality, TargetScope, TlsObservation } from '../models';
import { nextScheduledAt } from './observation-schedule';

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

  private target(record: RecordModel, authorizedHosts: string[] = []): Target {
    return {
      id: record.id, name: record['name'], hostname: record['hostname'], hostHints: record['hostHints'] ?? [], authorizedHosts,
      authorizationStatus: record['authorizationStatus'], status: record['status'], lastScanAt: record['lastScanAt'],
      assetCount: record['assetCount'] ?? 0, findingCount: record['findingCount'] ?? 0, posture: record['posture'] ?? 100,
      criticality: record['criticality'] || 'standard', tags: Array.isArray(record['tags']) ? record['tags'] : []
    } as Target;
  }

  isAdmin(): boolean { return this.user()?.['role'] === 'admin'; }

  async targets(): Promise<Target[]> {
    try {
      const [records, scopes] = await Promise.all([
        this.client.collection('targets').getFullList({ sort: '-created' }),
        this.client.collection('targetScopes').getFullList({ filter: 'enabled = true', sort: 'created' })
      ]);
      this.connected.set(true);
      return records.map((record) => this.target(record, scopes.filter((scope) => scope['target'] === record.id).map((scope) => String(scope['hostname']))));
    } catch (error) { return this.failed(error); }
  }

  async createTarget(input: CreateTargetInput): Promise<Target> {
    if (!this.isAdmin() || !this.user()?.id) throw new Error('Only a workspace administrator can approve a target.');
    try {
      const record = await this.client.collection('targets').create({
        owner: this.user()!.id, name: input.name, hostname: input.hostname, hostHints: input.hostHints,
        authorizationStatus: 'admin_override', authorizationReason: input.authorizationReason,
        authorizedAt: new Date().toISOString(), allowPrivateAddresses: false, status: 'observed',
        assetCount: 1, findingCount: 0, posture: 100, criticality: 'standard', tags: []
      });
      for (const hostname of input.authorizedHosts) await this.addTargetScope(record.id, hostname, input.authorizationReason);
      return this.target(record, input.authorizedHosts);
    } catch (error) { return this.failed(error); }
  }

  async findings(targetId?: string, scanId?: string): Promise<Finding[]> {
    try {
      const clauses: string[] = [];
      if (targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId }));
      if (scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId }));
      const filter = clauses.join(' && ');
      const records = await this.client.collection('findings').getFullList({ filter, sort: '-created' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], title: r['title'], summary: r['summary'], severity: r['severity'], confidence: r['confidence'], asset: r['asset'], evidence: r['evidence'] ?? [], remediation: r['remediation'] ?? '', sourceUrls: r['sourceUrls'] ?? [], cveIds: r['cveIds'] ?? [], weaknessIds: r['weaknessIds'] ?? [], frameworkRefs: r['frameworkRefs'] ?? [], customerNarrative: r['customerNarrative'] && typeof r['customerNarrative'] === 'object' ? r['customerNarrative'] : null, assetKey: r['assetKey'] ?? '', relatedAssetKeys: r['relatedAssetKeys'] ?? [], relationKey: r['relationKey'] ?? '', observations: Array.isArray(r['observations']) ? r['observations'] : (r['scan'] ? [{ scan: r['scan'], observedAt: r['created'] }] : []), runCount: Number(r['runCount']) || (Array.isArray(r['observations']) && r['observations'].length ? r['observations'].length : 1), created: r['created'], status: r['status'], threatContext: r['threatContext'] && typeof r['threatContext'] === 'object' ? r['threatContext'] : undefined } as Finding));
    } catch (error) { return this.failed(error); }
  }

  async reviewFinding(finding: Finding, status: Finding['status']): Promise<void> {
    if (!this.isAdmin()) throw new Error('Only a workspace administrator can change finding disposition.');
    try { await this.client.collection('findings').update(finding.id, { status }); }
    catch (error) { return this.failed(error); }
  }

  async tls(targetId?: string, hostname?: string, scanId?: string): Promise<TlsObservation | null> {
    try {
      const clauses: string[] = [];
      if (targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId }));
      if (hostname) clauses.push(this.client.filter('hostname = {:hostname}', { hostname }));
      if (scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId }));
      const filter = clauses.join(' && ');
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
      return this.request(r);
    } catch (error) { return this.failed(error); }
  }

  async scanRequests(targetId?: string): Promise<ScanRequest[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : '';
      const records = await this.client.collection('scanRequests').getFullList({ filter, sort: '-created' });
      return records.map((record) => this.request(record));
    } catch (error) { return this.failed(error); }
  }

  private request(r: RecordModel): ScanRequest {
    return {
      id: r.id, target: r['target'], mode: r['mode'], status: r['status'], startedAt: r['startedAt'], completedAt: r['completedAt'],
      heartbeatAt: r['heartbeatAt'] ?? '', phase: r['phase'] ?? '', actionCount: r['actionCount'] ?? 0, messageCount: r['messageCount'] ?? 0,
      profileSnapshot: r['profileSnapshot'] && typeof r['profileSnapshot'] === 'object' ? r['profileSnapshot'] : null, extendedConsent: Boolean(r['extendedConsent']),
      error: r['error'] ?? '', created: r['created']
    } as ScanRequest;
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

  async requestScan(targetId: string, mode: ScanMode = 'standard'): Promise<string> {
    const record = await this.client.collection('scanRequests').create({ target: targetId, mode, status: 'queued', extendedConsent: mode === 'extended' || mode === 'advanced' || mode === 'unbounded' });
    return record.id;
  }

  async targetScopes(targetId?: string): Promise<TargetScope[]> {
    const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : '';
    const records = await this.client.collection('targetScopes').getFullList({ filter, sort: 'created' });
    return records.map((r) => ({ id: r.id, target: r['target'], hostname: r['hostname'], kind: r['kind'], reason: r['reason'], enabled: r['enabled'], authorizedAt: r['authorizedAt'] } as TargetScope));
  }

  async assets(targetId: string, scanId?: string): Promise<AssetRecord[]> {
    const clauses = [this.client.filter('target = {:target}', { target: targetId })];
    if (scanId) clauses.push(this.client.filter('scan = {:scan}', { scan: scanId }));
    const records = await this.client.collection('assets').getFullList({ filter: clauses.join(' && '), sort: 'created' });
    return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], key: r['key'], kind: r['kind'], label: r['label'], subtitle: r['subtitle'], state: r['state'], confidence: r['confidence'], basis: r['basis'], details: r['details'] ?? [] } as AssetRecord));
  }

  async assetRelations(targetId: string, scanId?: string): Promise<AssetRelationRecord[]> {
    const clauses = [this.client.filter('target = {:target}', { target: targetId })];
    if (scanId) clauses.push(this.client.filter('scan = {:scan}', { scan: scanId }));
    const records = await this.client.collection('assetRelations').getFullList({ filter: clauses.join(' && '), sort: 'created' });
    return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], key: r['key'], fromKey: r['fromKey'], toKey: r['toKey'], type: r['type'], label: r['label'], state: r['state'], confidence: r['confidence'], basis: r['basis'], evidence: r['evidence'] ?? [], findingTitles: r['findingTitles'] ?? [] } as AssetRelationRecord));
  }

  async changeReviews(targetId?: string): Promise<ChangeReview[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : '';
      const records = await this.client.collection('changeReviews').getFullList({ filter, sort: '-created' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], changeKey: r['changeKey'], status: r['status'], note: r['note'] ?? '', reviewedBy: r['reviewedBy'] ?? '', reviewedAt: r['reviewedAt'] ?? '', created: r['created'], updated: r['updated'] } as ChangeReview));
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return [];
      return this.failed(error);
    }
  }

  async reviewChange(targetId: string, scanId: string, changeKey: string, status: ChangeReviewStatus, note: string, existingId?: string): Promise<ChangeReview> {
    if (!this.isAdmin() || !this.user()?.id) throw new Error('Only a workspace administrator can review observed changes.');
    const payload = { target: targetId, scan: scanId, changeKey, status, note, reviewedBy: this.user()!.id, reviewedAt: new Date().toISOString() };
    const r = existingId ? await this.client.collection('changeReviews').update(existingId, payload) : await this.client.collection('changeReviews').create(payload);
    return { id: r.id, target: r['target'], scan: r['scan'], changeKey: r['changeKey'], status: r['status'], note: r['note'] ?? '', reviewedBy: r['reviewedBy'] ?? '', reviewedAt: r['reviewedAt'] ?? '', created: r['created'], updated: r['updated'] } as ChangeReview;
  }

  async updateTargetContext(targetId: string, criticality: TargetCriticality, tags: string[]): Promise<void> {
    if (!this.isAdmin()) throw new Error('Only a workspace administrator can change asset context.');
    await this.client.collection('targets').update(targetId, { criticality, tags: [...new Set(tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].slice(0, 20) });
  }

  async observationSchedules(targetId?: string): Promise<ObservationSchedule[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : '';
      const records = await this.client.collection('observationSchedules').getFullList({ filter, sort: 'created' });
      return records.map((r) => ({
        id: r.id, target: r['target'], enabled: Boolean(r['enabled']), cadence: r['cadence'], mode: r['mode'],
        nextRunAt: r['nextRunAt'] ?? '', lastQueuedAt: r['lastQueuedAt'] ?? '', lastRequest: r['lastRequest'] ?? '',
        created: r['created'], updated: r['updated']
      } as ObservationSchedule));
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return [];
      return this.failed(error);
    }
  }

  async saveObservationSchedule(targetId: string, cadence: ObservationCadence, mode: ScheduledScanMode, existingId?: string): Promise<ObservationSchedule | null> {
    if (!this.isAdmin()) throw new Error('Only a workspace administrator can schedule observations.');
    if (cadence === 'off' && !existingId) return null;
    const enabled = cadence !== 'off';
    const payload = {
      target: targetId, enabled, cadence: cadence === 'off' ? 'daily' : cadence, mode,
      nextRunAt: enabled ? nextScheduledAt(cadence) : ''
    };
    const r = existingId
      ? await this.client.collection('observationSchedules').update(existingId, payload)
      : await this.client.collection('observationSchedules').create(payload);
    return {
      id: r.id, target: r['target'], enabled: Boolean(r['enabled']), cadence: r['cadence'], mode: r['mode'],
      nextRunAt: r['nextRunAt'] ?? '', lastQueuedAt: r['lastQueuedAt'] ?? '', lastRequest: r['lastRequest'] ?? '',
      created: r['created'], updated: r['updated']
    } as ObservationSchedule;
  }

  async knowledgeObservations(targetId?: string): Promise<KnowledgeObservation[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : '';
      const records = await this.client.collection('knowledgeObservations').getFullList({ filter, sort: '-observedAt' });
      return records.map((r) => ({
        id: r.id, target: r['target'], scan: r['scan'], patternKey: r['patternKey'], category: r['category'], technology: r['technology'],
        findingTitle: r['findingTitle'], severity: r['severity'], assetKey: r['assetKey'] ?? '', assetKind: r['assetKind'] || 'unknown',
        weaknessIds: r['weaknessIds'] ?? [], frameworkControls: r['frameworkControls'] ?? [], configurationSignals: r['configurationSignals'] ?? [],
        observedAt: r['observedAt'], created: r['created']
      } as KnowledgeObservation));
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return [];
      return this.failed(error);
    }
  }

  async publicIdentities(targetId: string): Promise<PublicIdentity[]> {
    const records = await this.client.collection('publicIdentities').getFullList({ filter: this.client.filter('target = {:target}', { target: targetId }), sort: '-created' });
    return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], key: r['key'], kind: r['kind'], displayName: r['displayName'], email: r['email'], publicLinks: r['publicLinks'] ?? [], sourceUrls: r['sourceUrls'] ?? [], evidence: r['evidence'] ?? [], sourceAssetKey: r['sourceAssetKey'], confidence: r['confidence'], employmentStatus: r['employmentStatus'], reviewNote: r['reviewNote'] ?? '', confirmedBy: r['confirmedBy'] ?? '', confirmedAt: r['confirmedAt'] ?? '', created: r['created'] } as PublicIdentity));
  }

  async reviewPublicIdentity(identity: PublicIdentity, employmentStatus: PublicIdentity['employmentStatus'], reviewNote: string): Promise<void> {
    if (!this.isAdmin() || !this.user()?.id) throw new Error('Only a workspace administrator can confirm identity status.');
    await this.client.collection('publicIdentities').update(identity.id, { employmentStatus, reviewNote, confirmedBy: this.user()!.id, confirmedAt: new Date().toISOString() });
  }

  async addTargetScope(targetId: string, hostname: string, reason: string): Promise<TargetScope> {
    if (!this.isAdmin()) throw new Error('Only a workspace administrator can authorize a related hostname.');
    const r = await this.client.collection('targetScopes').create({
      target: targetId, hostname, kind: 'exact_host', reason, enabled: true, authorizedAt: new Date().toISOString()
    });
    return { id: r.id, target: r['target'], hostname: r['hostname'], kind: r['kind'], reason: r['reason'], enabled: r['enabled'], authorizedAt: r['authorizedAt'] } as TargetScope;
  }
}
