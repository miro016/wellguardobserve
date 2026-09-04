import PocketBase, { type RecordModel } from 'pocketbase';
import type { AgentAction, AgentMessage, AuthorizedTarget, InvestigationReport } from './types';

export class InvestigationStore {
  readonly client: PocketBase;

  constructor(baseUrl = process.env['POCKETBASE_URL'] || 'http://127.0.0.1:8090') {
    this.client = new PocketBase(baseUrl);
    this.client.autoCancellation(false);
  }

  async connect(): Promise<void> {
    const email = process.env['POCKETBASE_WORKER_EMAIL'];
    const password = process.env['POCKETBASE_WORKER_PASSWORD'];
    if (!email || !password) throw new Error('POCKETBASE_WORKER_EMAIL and POCKETBASE_WORKER_PASSWORD are required.');
    await this.client.collection('workers').authWithPassword(email, password, { autoRefreshThreshold: 30 * 60 });
    await this.recoverInterruptedRequests();
  }

  private async recoverInterruptedRequests(): Promise<void> {
    const interrupted = await this.client.collection('scanRequests').getFullList({ filter: 'status = "processing" || status = "cancelling"', sort: 'created' });
    const recoveredAt = new Date().toISOString();
    for (const request of interrupted) {
      const lastSignal = Date.parse(String(request['heartbeatAt'] || request['startedAt'] || request['created'] || ''));
      if (Number.isFinite(lastSignal) && Date.now() - lastSignal < 30_000) continue;
      const cancelled = request['status'] === 'cancelling';
      const status = cancelled ? 'cancelled' : 'failed';
      const phase = cancelled ? 'Cancellation completed after observer restart' : 'Interrupted by observer restart';
      const error = cancelled ? '' : 'The observer process restarted before this investigation completed. Start a new scan to continue.';
      await this.client.collection('scanRequests').update(request.id, { status, completedAt: recoveredAt, heartbeatAt: recoveredAt, phase, error });
      await this.client.collection('targets').update(request['target'], { status: 'observed' });
      try {
        const scan = await this.client.collection('scans').getFirstListItem(this.client.filter('request = {:request} && status = "running"', { request: request.id }));
        await this.client.collection('scans').update(scan.id, { status, completedAt: recoveredAt, ...(error ? { error } : { summary: 'Investigation cancellation completed after the observer restarted.' }) });
      } catch { /* A claimed request can be interrupted before its scan record is created. */ }
    }
  }

  async nextRequest(): Promise<RecordModel | null> {
    try { return await this.client.collection('scanRequests').getFirstListItem('status = "queued"', { sort: 'created' }); }
    catch { return null; }
  }

  async claim(record: RecordModel): Promise<boolean> {
    const current = await this.client.collection('scanRequests').getOne(record.id);
    if (current['status'] !== 'queued') return false;
    const startedAt = new Date().toISOString();
    await this.client.collection('scanRequests').update(record.id, { status: 'processing', startedAt, heartbeatAt: startedAt, phase: 'Preparing investigation', actionCount: 0, messageCount: 0, error: '' });
    await this.client.collection('targets').update(record['target'], { status: 'scanning' });
    return true;
  }

  async loadTarget(id: string): Promise<AuthorizedTarget> {
    const record = await this.client.collection('targets').getOne(id);
    if (!['verified', 'admin_override'].includes(record['authorizationStatus'])) throw new Error('Target is not authorized.');
    const scopes = await this.client.collection('targetScopes').getFullList({
      filter: this.client.filter('target = {:target} && enabled = true', { target: record.id }), sort: 'created'
    });
    return {
      id: record.id, hostname: record['hostname'], hostHints: record['hostHints'] ?? [],
      authorizedHosts: scopes.map((scope) => String(scope['hostname'] || '')).filter(Boolean),
      authorizationStatus: record['authorizationStatus'], allowPrivateAddresses: record['allowPrivateAddresses']
    };
  }

  async createScan(targetId: string, requestId: string): Promise<RecordModel> {
    return await this.client.collection('scans').create({ target: targetId, request: requestId, status: 'running', startedAt: new Date().toISOString(), summary: '' });
  }

  async saveAction(targetId: string, scanId: string, action: AgentAction): Promise<void> {
    await this.client.collection('agentActions').create({ target: targetId, scan: scanId, tool: action.tool, input: action.input, summary: action.summary, occurredAt: action.at });
  }

  async saveMessage(targetId: string, scanId: string, message: AgentMessage): Promise<void> {
    await this.client.collection('agentMessages').create({ target: targetId, scan: scanId, role: message.role, content: message.content, toolName: message.toolName, sequence: message.sequence, occurredAt: message.at });
  }

  async heartbeat(requestId: string, phase: string, actionCount?: number, messageCount?: number): Promise<void> {
    await this.client.collection('scanRequests').update(requestId, {
      heartbeatAt: new Date().toISOString(), phase: phase.slice(0, 200),
      ...(typeof actionCount === 'number' ? { actionCount } : {}), ...(typeof messageCount === 'number' ? { messageCount } : {})
    });
  }

  async isCancellationRequested(requestId: string): Promise<boolean> {
    const request = await this.client.collection('scanRequests').getOne(requestId);
    return request['status'] === 'cancelling' || request['status'] === 'cancelled';
  }

  async cancel(request: RecordModel, scan: RecordModel | null): Promise<void> {
    const completedAt = new Date().toISOString();
    await this.client.collection('scanRequests').update(request.id, { status: 'cancelled', completedAt, heartbeatAt: completedAt, phase: 'Stopped by user', error: '' });
    await this.client.collection('targets').update(request['target'], { status: 'observed' });
    if (scan) await this.client.collection('scans').update(scan.id, { status: 'cancelled', completedAt, summary: 'Investigation stopped by the user.' });
  }

  async complete(request: RecordModel, scan: RecordModel, report: InvestigationReport): Promise<void> {
    for (const asset of report.assets) {
      await this.client.collection('assets').create({ target: report.target.id, scan: scan.id, ...asset });
    }
    for (const relation of report.relations) {
      await this.client.collection('assetRelations').create({ target: report.target.id, scan: scan.id, ...relation });
    }
    for (const identity of report.identities) {
      let ownerReview: Record<string, unknown> = {};
      if (identity.employmentStatus === 'unknown') {
        try {
          const previous = await this.client.collection('publicIdentities').getFirstListItem(
            this.client.filter('target = {:target} && key = {:key}', { target: report.target.id, key: identity.key }), { sort: '-created' }
          );
          if (['current', 'former'].includes(previous['employmentStatus'])) ownerReview = {
            employmentStatus: previous['employmentStatus'], reviewNote: previous['reviewNote'] || '',
            confirmedBy: previous['confirmedBy'] || '', confirmedAt: previous['confirmedAt'] || ''
          };
        } catch { /* First observation has no owner review to carry forward. */ }
      }
      await this.client.collection('publicIdentities').create({ target: report.target.id, scan: scan.id, ...identity, ...ownerReview });
    }
    for (const finding of report.findings) {
      await this.client.collection('findings').create({
        target: report.target.id, scan: scan.id, title: finding.title, summary: finding.summary,
        severity: finding.severity, confidence: finding.confidence, asset: finding.asset,
        evidence: finding.evidence, remediation: finding.remediation, sourceUrls: finding.sourceUrls,
        cveIds: finding.cveIds, weaknessIds: finding.weaknessIds, assetKey: finding.assetKey || '',
        relatedAssetKeys: finding.relatedAssetKeys || [], relationKey: finding.relationKey || '', status: 'open'
      });
    }
    for (const tls of report.tls) {
      await this.client.collection('tlsObservations').create({ target: report.target.id, scan: scan.id, hostname: tls.hostname, valid: tls.valid, expiresAt: tls.validTo, details: tls });
    }
    const posture = Math.max(0, 100 - report.findings.reduce((sum, finding) => sum + ({ critical: 35, high: 22, medium: 11, low: 4, info: 0 })[finding.severity], 0));
    await this.client.collection('targets').update(report.target.id, { lastScanAt: report.completedAt, findingCount: report.findings.filter((item) => item.severity !== 'info').length, assetCount: Math.max(1, report.assets.length), posture, status: 'observed' });
    await this.client.collection('scans').update(scan.id, { status: 'completed', completedAt: report.completedAt, summary: report.summary });
    await this.client.collection('scanRequests').update(request.id, { status: 'completed', completedAt: report.completedAt, heartbeatAt: report.completedAt, phase: 'Evidence retained' });
  }

  async fail(request: RecordModel, scan: RecordModel | null, error: unknown): Promise<void> {
    const message = error instanceof Error ? error.message : String(error);
    const completedAt = new Date().toISOString();
    await this.client.collection('scanRequests').update(request.id, { status: 'failed', completedAt, heartbeatAt: completedAt, phase: 'Investigation failed', error: message.slice(0, 500) });
    await this.client.collection('targets').update(request['target'], { status: 'observed' });
    if (scan) await this.client.collection('scans').update(scan.id, { status: 'failed', completedAt: new Date().toISOString(), error: message.slice(0, 500) });
  }
}
