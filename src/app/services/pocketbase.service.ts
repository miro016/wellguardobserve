import { Injectable, computed, signal } from '@angular/core';
import PocketBase, { RecordModel } from 'pocketbase';
import { AgentActionRecord, AgentMessageRecord, AssetRecord, AssetRelationRecord, ChangeReview, ChangeReviewStatus, CreateTargetInput, Finding, FindingFeedback, ImprovementProposal, KnowledgeObservation, ObservationCadence, ObservationSchedule, PublicIdentity, Scan, ScanEvaluation, ScanMode, ScanRequest, ScheduledScanMode, Target, TargetCriticality, TargetScope, TlsObservation, Workspace, WorkspaceMember, WorkspaceRole, WorkspaceUser } from '../models';
import { nextScheduledAt } from './observation-schedule';

@Injectable({ providedIn: 'root' })
export class PocketBaseService {
  readonly client = new PocketBase(window.location.origin);
  readonly connected = signal(false);
  readonly user = signal<RecordModel | null>(this.client.authStore.record);
  readonly lastError = signal('');
  readonly workspaces = signal<Workspace[]>([]);
  readonly memberships = signal<WorkspaceMember[]>([]);
  readonly activeWorkspaceId = signal('');
  readonly activeWorkspace = computed(() => this.workspaces().find((workspace) => workspace.id === this.activeWorkspaceId()) || null);
  readonly activeWorkspaceRole = computed<WorkspaceRole | 'platform-admin' | ''>(() => {
    if (this.isAdmin()) return 'platform-admin';
    return this.memberships().find((member) => member.workspace === this.activeWorkspaceId() && member.user === this.user()?.id && member.enabled)?.role || '';
  });
  private readonly targetCache = signal<Target[]>([]);
  private workspaceContextPromise?: Promise<void>;

  constructor() {
    this.client.autoCancellation(false);
    this.client.authStore.onChange(() => {
      this.user.set(this.client.authStore.record);
      this.workspaceContextPromise = undefined;
      this.workspaces.set([]); this.memberships.set([]); this.activeWorkspaceId.set(''); this.targetCache.set([]);
    });
  }

  async signIn(email: string, password: string): Promise<void> {
    await this.client.collection('users').authWithPassword(email, password);
    this.connected.set(true);
    await this.loadWorkspaceContext(true);
  }
  signOut(): void { this.client.authStore.clear(); }
  private failed(error: unknown): never {
    this.lastError.set(error instanceof Error ? error.message : 'PocketBase request failed.');
    throw error;
  }

  private target(record: RecordModel, authorizedHosts: string[] = []): Target {
    return {
      id: record.id, workspace: String(record['workspace'] || ''), name: record['name'], hostname: record['hostname'], hostHints: record['hostHints'] ?? [], authorizedHosts,
      authorizationStatus: record['authorizationStatus'], status: record['status'], lastScanAt: record['lastScanAt'],
      assetCount: record['assetCount'] ?? 0, findingCount: record['findingCount'] ?? 0, posture: record['posture'] ?? 100,
      criticality: record['criticality'] || 'standard', tags: Array.isArray(record['tags']) ? record['tags'] : []
    } as Target;
  }

  isAdmin(): boolean { return this.user()?.['role'] === 'admin'; }

  async loadWorkspaceContext(force = false): Promise<void> {
    if (!this.client.authStore.isValid) return;
    if (!force && this.workspaceContextPromise) return this.workspaceContextPromise;
    this.workspaceContextPromise = (async () => {
      const [workspaceRecords, memberRecords] = await Promise.all([
        this.client.collection('workspaces').getFullList({ sort: 'name' }),
        this.client.collection('workspaceMembers').getFullList({ sort: 'created', expand: 'user' })
      ]);
      const workspaces = workspaceRecords.map((record) => ({
        id: record.id, name: String(record['name'] || ''), slug: String(record['slug'] || ''), description: String(record['description'] || ''),
        status: record['status'], createdBy: String(record['createdBy'] || ''), created: record['created'], updated: record['updated']
      } as Workspace));
      const memberships = memberRecords.map((record) => {
        const expanded = record.expand?.['user'] as RecordModel | undefined;
        return {
          id: record.id, workspace: String(record['workspace'] || ''), user: String(record['user'] || ''), role: record['role'], enabled: Boolean(record['enabled']),
          userName: String(expanded?.['name'] || ''), userEmail: String(expanded?.['email'] || ''), created: record['created'], updated: record['updated']
        } as WorkspaceMember;
      });
      this.workspaces.set(workspaces); this.memberships.set(memberships);
      const storageKey = this.workspaceStorageKey();
      const stored = localStorage.getItem(storageKey) || '';
      const available = workspaces.filter((workspace) => workspace.status === 'active');
      const chosen = available.find((workspace) => workspace.id === stored) || available[0] || workspaces[0];
      this.activeWorkspaceId.set(chosen?.id || '');
      if (chosen) localStorage.setItem(storageKey, chosen.id);
    })().catch((error) => {
      this.workspaceContextPromise = undefined;
      return this.failed(error);
    });
    return this.workspaceContextPromise;
  }

  activateWorkspace(workspaceId: string): void {
    if (!this.workspaces().some((workspace) => workspace.id === workspaceId)) return;
    this.activeWorkspaceId.set(workspaceId);
    this.targetCache.set([]);
    localStorage.setItem(this.workspaceStorageKey(), workspaceId);
  }

  canManageWorkspace(workspaceId: string): boolean {
    if (this.isAdmin()) return true;
    return this.memberships().some((member) => member.workspace === workspaceId && member.user === this.user()?.id && member.enabled && ['owner', 'admin'].includes(member.role));
  }

  canOperateWorkspace(workspaceId: string): boolean {
    if (this.workspaces().find((workspace) => workspace.id === workspaceId)?.status !== 'active') return false;
    if (this.isAdmin()) return true;
    return this.memberships().some((member) => member.workspace === workspaceId && member.user === this.user()?.id && member.enabled && ['owner', 'admin', 'operator'].includes(member.role));
  }

  canManageTarget(targetId: string): boolean {
    const target = this.targetCache().find((item) => item.id === targetId);
    return Boolean(target && this.canManageWorkspace(target.workspace));
  }

  private workspaceStorageKey(): string { return `wellguard-workspace:${this.user()?.id || 'anonymous'}`; }
  private async currentWorkspaceFilter(field = 'target.workspace'): Promise<string> {
    await this.loadWorkspaceContext();
    const workspace = this.activeWorkspaceId();
    return workspace ? this.client.filter(`${field} = {:workspace}`, { workspace }) : this.client.filter(`${field} = {:workspace}`, { workspace: '__none__' });
  }

  private async targetWorkspace(targetId: string): Promise<string> {
    const cached = this.targetCache().find((target) => target.id === targetId);
    if (cached) return cached.workspace;
    const record = await this.client.collection('targets').getOne(targetId);
    return String(record['workspace'] || '');
  }

  async targets(workspaceId?: string | 'all'): Promise<Target[]> {
    try {
      await this.loadWorkspaceContext();
      const selectedWorkspace = workspaceId === 'all' ? '' : workspaceId || this.activeWorkspaceId();
      if (workspaceId !== 'all' && !selectedWorkspace) return [];
      const [records, scopes] = await Promise.all([
        this.client.collection('targets').getFullList({ filter: selectedWorkspace ? this.client.filter('workspace = {:workspace}', { workspace: selectedWorkspace }) : '', sort: '-created' }),
        this.client.collection('targetScopes').getFullList({ filter: selectedWorkspace ? this.client.filter('enabled = true && target.workspace = {:workspace}', { workspace: selectedWorkspace }) : 'enabled = true', sort: 'created' })
      ]);
      this.connected.set(true);
      const targets = records.map((record) => this.target(record, scopes.filter((scope) => scope['target'] === record.id).map((scope) => String(scope['hostname']))));
      if (workspaceId !== 'all') this.targetCache.set(targets);
      return targets;
    } catch (error) { return this.failed(error); }
  }

  async createTarget(input: CreateTargetInput): Promise<Target> {
    if (!this.isAdmin() || !this.user()?.id) throw new Error('Only a workspace administrator can approve a target.');
    try {
      const record = await this.client.collection('targets').create({
        owner: this.user()!.id, workspace: input.workspace, name: input.name, hostname: input.hostname, hostHints: input.hostHints,
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
      else clauses.push(await this.currentWorkspaceFilter());
      if (scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId }));
      const filter = clauses.join(' && ');
      const records = await this.client.collection('findings').getFullList({ filter, sort: '-created' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], title: r['title'], summary: r['summary'], severity: r['severity'], confidence: r['confidence'], asset: r['asset'], evidence: r['evidence'] ?? [], remediation: r['remediation'] ?? '', sourceUrls: r['sourceUrls'] ?? [], cveIds: r['cveIds'] ?? [], weaknessIds: r['weaknessIds'] ?? [], frameworkRefs: r['frameworkRefs'] ?? [], customerNarrative: r['customerNarrative'] && typeof r['customerNarrative'] === 'object' ? r['customerNarrative'] : null, assetKey: r['assetKey'] ?? '', relatedAssetKeys: r['relatedAssetKeys'] ?? [], relationKey: r['relationKey'] ?? '', observations: Array.isArray(r['observations']) ? r['observations'] : (r['scan'] ? [{ scan: r['scan'], observedAt: r['created'] }] : []), runCount: Number(r['runCount']) || (Array.isArray(r['observations']) && r['observations'].length ? r['observations'].length : 1), created: r['created'], status: r['status'], threatContext: r['threatContext'] && typeof r['threatContext'] === 'object' ? r['threatContext'] : undefined } as Finding));
    } catch (error) { return this.failed(error); }
  }

  async reviewFinding(finding: Finding, status: Finding['status']): Promise<void> {
    await this.loadWorkspaceContext();
    const workspace = await this.targetWorkspace(finding.target);
    if (!this.canManageWorkspace(workspace)) throw new Error('Only a workspace owner or administrator can change finding disposition.');
    try { await this.client.collection('findings').update(finding.id, { status }); }
    catch (error) { return this.failed(error); }
  }

  async tls(targetId?: string, hostname?: string, scanId?: string): Promise<TlsObservation | null> {
    try {
      const clauses: string[] = [];
      if (targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId }));
      else clauses.push(await this.currentWorkspaceFilter());
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
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : await this.currentWorkspaceFilter();
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
      const filter = targetId ? this.client.filter('target = {:targetId}', { targetId }) : await this.currentWorkspaceFilter();
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
    const workspace = await this.targetWorkspace(request.target);
    if (!this.canOperateWorkspace(workspace)) throw new Error('Your workspace role cannot stop investigations.');
    await this.client.collection('scanRequests').update(request.id, { status: request.status === 'queued' ? 'cancelled' : 'cancelling' });
  }

  async agentActions(options: { targetId?: string; scanId?: string } = {}): Promise<AgentActionRecord[]> {
    try {
      const clauses: string[] = [];
      if (options.targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId: options.targetId }));
      else if (!options.scanId) clauses.push(await this.currentWorkspaceFilter());
      if (options.scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId: options.scanId }));
      const records = await this.client.collection('agentActions').getFullList({ filter: clauses.join(' && '), sort: 'occurredAt' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], tool: r['tool'], input: r['input'] ?? {}, summary: r['summary'] ?? '', occurredAt: r['occurredAt'] }));
    } catch (error) { return this.failed(error); }
  }

  async agentMessages(options: { targetId?: string; scanId?: string } = {}): Promise<AgentMessageRecord[]> {
    try {
      const clauses: string[] = [];
      if (options.targetId) clauses.push(this.client.filter('target = {:targetId}', { targetId: options.targetId }));
      else if (!options.scanId) clauses.push(await this.currentWorkspaceFilter());
      if (options.scanId) clauses.push(this.client.filter('scan = {:scanId}', { scanId: options.scanId }));
      const records = await this.client.collection('agentMessages').getFullList({ filter: clauses.join(' && '), sort: 'sequence' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], role: r['role'], content: r['content'] ?? '', toolName: r['toolName'] ?? '', sequence: r['sequence'] ?? 0, occurredAt: r['occurredAt'] }));
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return [];
      return this.failed(error);
    }
  }

  async requestScan(targetId: string, mode: ScanMode = 'standard'): Promise<string> {
    await this.loadWorkspaceContext();
    const workspace = await this.targetWorkspace(targetId);
    if (!this.canOperateWorkspace(workspace)) throw new Error('Your workspace role cannot start investigations.');
    const record = await this.client.collection('scanRequests').create({ target: targetId, mode, status: 'queued', extendedConsent: mode === 'extended' || mode === 'advanced' || mode === 'unbounded' });
    return record.id;
  }

  async targetScopes(targetId?: string): Promise<TargetScope[]> {
    const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : await this.currentWorkspaceFilter();
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
      const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : await this.currentWorkspaceFilter();
      const records = await this.client.collection('changeReviews').getFullList({ filter, sort: '-created' });
      return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], changeKey: r['changeKey'], status: r['status'], note: r['note'] ?? '', reviewedBy: r['reviewedBy'] ?? '', reviewedAt: r['reviewedAt'] ?? '', created: r['created'], updated: r['updated'] } as ChangeReview));
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return [];
      return this.failed(error);
    }
  }

  async reviewChange(targetId: string, scanId: string, changeKey: string, status: ChangeReviewStatus, note: string, existingId?: string): Promise<ChangeReview> {
    await this.loadWorkspaceContext();
    if (!this.user()?.id || !this.canManageWorkspace(await this.targetWorkspace(targetId))) throw new Error('Only a workspace owner or administrator can review observed changes.');
    const payload = { target: targetId, scan: scanId, changeKey, status, note, reviewedBy: this.user()!.id, reviewedAt: new Date().toISOString() };
    const r = existingId ? await this.client.collection('changeReviews').update(existingId, payload) : await this.client.collection('changeReviews').create(payload);
    return { id: r.id, target: r['target'], scan: r['scan'], changeKey: r['changeKey'], status: r['status'], note: r['note'] ?? '', reviewedBy: r['reviewedBy'] ?? '', reviewedAt: r['reviewedAt'] ?? '', created: r['created'], updated: r['updated'] } as ChangeReview;
  }

  async updateTargetContext(targetId: string, criticality: TargetCriticality, tags: string[]): Promise<void> {
    await this.loadWorkspaceContext();
    if (!this.canManageWorkspace(await this.targetWorkspace(targetId))) throw new Error('Only a workspace owner or administrator can change asset context.');
    await this.client.collection('targets').update(targetId, { criticality, tags: [...new Set(tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].slice(0, 20) });
  }

  async observationSchedules(targetId?: string): Promise<ObservationSchedule[]> {
    try {
      const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : await this.currentWorkspaceFilter();
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
    await this.loadWorkspaceContext();
    if (!this.canManageWorkspace(await this.targetWorkspace(targetId))) throw new Error('Only a workspace owner or administrator can schedule observations.');
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
      const filter = targetId ? this.client.filter('target = {:target}', { target: targetId }) : await this.currentWorkspaceFilter();
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

  async scanEvaluations(): Promise<ScanEvaluation[]> {
    try {
      await this.loadWorkspaceContext();
      const workspace = this.activeWorkspaceId(); if (!workspace) return [];
      const records = await this.client.collection('scanEvaluations').getList(1, 50, { filter: this.client.filter('workspace = {:workspace}', { workspace }), sort: '-created' });
      return records.items.map((r) => ({
        id: r.id, workspace: r['workspace'], target: r['target'], scan: r['scan'], model: r['model'] || '', reasoningEffort: r['reasoningEffort'] || '', profile: r['profile'] || '',
        qualityScore: Number(r['qualityScore']) || 0, toolSuccessRate: Number(r['toolSuccessRate']) || 0, evidenceCoverage: Number(r['evidenceCoverage']) || 0,
        sourceCoverage: Number(r['sourceCoverage']) || 0, assetLinkage: Number(r['assetLinkage']) || 0, toolErrors: Number(r['toolErrors']) || 0,
        duplicateCalls: Number(r['duplicateCalls']) || 0, unknownServices: Number(r['unknownServices']) || 0, cacheHits: Number(r['cacheHits']) || 0,
        cacheMisses: Number(r['cacheMisses']) || 0, originRequests: Number(r['originRequests']) || 0, signals: r['signals'] || {}, created: r['created']
      } as ScanEvaluation));
    } catch (error: unknown) { if ((error as { status?: number })?.status === 404) return []; return this.failed(error); }
  }

  async improvementProposals(): Promise<ImprovementProposal[]> {
    try {
      await this.loadWorkspaceContext();
      const workspace = this.activeWorkspaceId(); if (!workspace) return [];
      const records = await this.client.collection('improvementProposals').getFullList({ filter: this.client.filter('workspace = {:workspace}', { workspace }), sort: '-updated' });
      return records.map((r) => ({ id: r.id, workspace: r['workspace'], proposalKey: r['proposalKey'], kind: r['kind'], scopeKey: r['scopeKey'], title: r['title'], rationale: r['rationale'], evidence: r['evidence'] || {}, recommendedAction: r['recommendedAction'], parameter: r['parameter'] || {}, confidence: Number(r['confidence']) || 0, occurrences: Number(r['occurrences']) || 0, status: r['status'], reviewedBy: r['reviewedBy'] || '', reviewedAt: r['reviewedAt'] || '', reviewNote: r['reviewNote'] || '', applicationCount: Number(r['applicationCount']) || 0, lastAppliedAt: r['lastAppliedAt'] || '', created: r['created'], updated: r['updated'] } as ImprovementProposal));
    } catch (error: unknown) { if ((error as { status?: number })?.status === 404) return []; return this.failed(error); }
  }

  async findingFeedback(): Promise<FindingFeedback[]> {
    try {
      await this.loadWorkspaceContext();
      const workspace = this.activeWorkspaceId(); if (!workspace) return [];
      const records = await this.client.collection('findingFeedback').getFullList({ filter: this.client.filter('workspace = {:workspace}', { workspace }), sort: '-updated' });
      return records.map((r) => ({ id: r.id, workspace: r['workspace'], target: r['target'], finding: r['finding'], patternKey: r['patternKey'], verdict: r['verdict'], note: r['note'] || '', reviewedBy: r['reviewedBy'], created: r['created'], updated: r['updated'] } as FindingFeedback));
    } catch (error: unknown) { if ((error as { status?: number })?.status === 404) return []; return this.failed(error); }
  }

  async recordFindingFeedback(finding: Finding, patternKey: string, verdict: FindingFeedback['verdict']): Promise<FindingFeedback> {
    if (!this.user()?.id) throw new Error('Sign in to review evidence.');
    const workspace = await this.targetWorkspace(finding.target);
    if (!this.canManageWorkspace(workspace)) throw new Error('Only a workspace owner or administrator can review learning evidence.');
    let current: RecordModel | null = null;
    try { current = await this.client.collection('findingFeedback').getFirstListItem(this.client.filter('finding = {:finding} && reviewedBy = {:user}', { finding: finding.id, user: this.user()!.id })); }
    catch (error: unknown) { if ((error as { status?: number })?.status !== 404) return this.failed(error); }
    const payload = { workspace, target: finding.target, finding: finding.id, patternKey, verdict, reviewedBy: this.user()!.id };
    const r = current ? await this.client.collection('findingFeedback').update(current.id, payload) : await this.client.collection('findingFeedback').create(payload);
    return { id: r.id, workspace: r['workspace'], target: r['target'], finding: r['finding'], patternKey: r['patternKey'], verdict: r['verdict'], note: r['note'] || '', reviewedBy: r['reviewedBy'], created: r['created'], updated: r['updated'] } as FindingFeedback;
  }

  async reviewImprovementProposal(proposal: ImprovementProposal, status: 'approved' | 'rejected'): Promise<void> {
    if (!this.user()?.id || !this.canManageWorkspace(proposal.workspace)) throw new Error('Only a workspace owner or administrator can approve learning proposals.');
    await this.client.collection('improvementProposals').update(proposal.id, { status, reviewedBy: this.user()!.id, reviewedAt: new Date().toISOString() });
  }

  async publicIdentities(targetId: string): Promise<PublicIdentity[]> {
    const records = await this.client.collection('publicIdentities').getFullList({ filter: this.client.filter('target = {:target}', { target: targetId }), sort: '-created' });
    return records.map((r) => ({ id: r.id, target: r['target'], scan: r['scan'], key: r['key'], kind: r['kind'], displayName: r['displayName'], email: r['email'], publicLinks: r['publicLinks'] ?? [], sourceUrls: r['sourceUrls'] ?? [], evidence: r['evidence'] ?? [], sourceAssetKey: r['sourceAssetKey'], confidence: r['confidence'], employmentStatus: r['employmentStatus'], reviewNote: r['reviewNote'] ?? '', confirmedBy: r['confirmedBy'] ?? '', confirmedAt: r['confirmedAt'] ?? '', created: r['created'] } as PublicIdentity));
  }

  async reviewPublicIdentity(identity: PublicIdentity, employmentStatus: PublicIdentity['employmentStatus'], reviewNote: string): Promise<void> {
    await this.loadWorkspaceContext();
    if (!this.user()?.id || !this.canManageWorkspace(await this.targetWorkspace(identity.target))) throw new Error('Only a workspace owner or administrator can confirm identity status.');
    await this.client.collection('publicIdentities').update(identity.id, { employmentStatus, reviewNote, confirmedBy: this.user()!.id, confirmedAt: new Date().toISOString() });
  }

  async addTargetScope(targetId: string, hostname: string, reason: string): Promise<TargetScope> {
    await this.loadWorkspaceContext();
    if (!this.canManageWorkspace(await this.targetWorkspace(targetId))) throw new Error('Only a workspace owner or administrator can authorize a related hostname.');
    const r = await this.client.collection('targetScopes').create({
      target: targetId, hostname, kind: 'exact_host', reason, enabled: true, authorizedAt: new Date().toISOString()
    });
    return { id: r.id, target: r['target'], hostname: r['hostname'], kind: r['kind'], reason: r['reason'], enabled: r['enabled'], authorizedAt: r['authorizedAt'] } as TargetScope;
  }

  async workspaceUsers(): Promise<WorkspaceUser[]> {
    if (!this.isAdmin()) throw new Error('Platform administrator access is required.');
    const records = await this.client.collection('users').getFullList({ sort: 'name,email' });
    return records.map((record) => ({
      id: record.id, name: String(record['name'] || ''), email: String(record['email'] || ''), verified: Boolean(record['verified']), created: record['created']
    }));
  }

  async createWorkspace(input: { name: string; slug: string; description: string }): Promise<Workspace> {
    if (!this.isAdmin() || !this.user()?.id) throw new Error('Platform administrator access is required.');
    const record = await this.client.collection('workspaces').create({
      name: input.name.trim(), slug: input.slug.trim().toLowerCase(), description: input.description.trim(), status: 'active', createdBy: this.user()!.id
    });
    await this.client.collection('workspaceMembers').create({ workspace: record.id, user: this.user()!.id, role: 'owner', enabled: true });
    await this.loadWorkspaceContext(true);
    this.activateWorkspace(record.id);
    return this.workspaces().find((workspace) => workspace.id === record.id)!;
  }

  async updateWorkspaceStatus(workspaceId: string, status: Workspace['status']): Promise<void> {
    if (!this.isAdmin()) throw new Error('Platform administrator access is required.');
    await this.client.collection('workspaces').update(workspaceId, { status });
    await this.loadWorkspaceContext(true);
  }

  async createWorkspaceUser(input: { name: string; email: string; password: string }): Promise<WorkspaceUser> {
    if (!this.isAdmin()) throw new Error('Platform administrator access is required.');
    const record = await this.client.collection('users').create({
      name: input.name.trim(), email: input.email.trim().toLowerCase(), password: input.password, passwordConfirm: input.password,
      role: 'member', emailVisibility: true
    });
    return { id: record.id, name: String(record['name'] || ''), email: String(record['email'] || ''), verified: Boolean(record['verified']), created: record['created'] };
  }

  async addWorkspaceMember(workspace: string, user: string, role: WorkspaceRole): Promise<void> {
    if (!this.isAdmin()) throw new Error('Platform administrator access is required.');
    await this.client.collection('workspaceMembers').create({ workspace, user, role, enabled: true });
    await this.loadWorkspaceContext(true);
  }

  async updateWorkspaceMember(memberId: string, role: WorkspaceRole, enabled: boolean): Promise<void> {
    if (!this.isAdmin()) throw new Error('Platform administrator access is required.');
    await this.client.collection('workspaceMembers').update(memberId, { role, enabled });
    await this.loadWorkspaceContext(true);
  }

  async moveTargetToWorkspace(targetId: string, workspace: string): Promise<void> {
    if (!this.isAdmin()) throw new Error('Platform administrator access is required.');
    await this.client.collection('targets').update(targetId, { workspace });
    this.targetCache.update((targets) => targets.filter((target) => target.id !== targetId));
  }
}
