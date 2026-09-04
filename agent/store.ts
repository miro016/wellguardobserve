import PocketBase, { type RecordModel } from 'pocketbase';
import type { AgentAction, AgentMessage, AuthorizedTarget, InvestigationReport } from './types';

export class InvestigationStore {
  readonly client: PocketBase;

  constructor(baseUrl = process.env['POCKETBASE_URL'] || 'http://127.0.0.1:8090') {
    this.client = new PocketBase(baseUrl);
    this.client.autoCancellation(false);
  }

  async connect(): Promise<void> {
    const email = process.env['POCKETBASE_SUPERUSER_EMAIL'];
    const password = process.env['POCKETBASE_SUPERUSER_PASSWORD'];
    if (!email || !password) throw new Error('PocketBase worker credentials are not configured.');
    await this.client.collection('_superusers').authWithPassword(email, password, { autoRefreshThreshold: 30 * 60 });
  }

  async nextRequest(): Promise<RecordModel | null> {
    try { return await this.client.collection('scanRequests').getFirstListItem('status = "queued"', { sort: 'created' }); }
    catch { return null; }
  }

  async claim(record: RecordModel): Promise<boolean> {
    const current = await this.client.collection('scanRequests').getOne(record.id);
    if (current['status'] !== 'queued') return false;
    await this.client.collection('scanRequests').update(record.id, { status: 'processing', startedAt: new Date().toISOString(), error: '' });
    await this.client.collection('targets').update(record['target'], { status: 'scanning' });
    return true;
  }

  async loadTarget(id: string): Promise<AuthorizedTarget> {
    const record = await this.client.collection('targets').getOne(id);
    if (!['verified', 'admin_override'].includes(record['authorizationStatus'])) throw new Error('Target is not authorized.');
    return { id: record.id, hostname: record['hostname'], hostHints: record['hostHints'] ?? [], authorizationStatus: record['authorizationStatus'], allowPrivateAddresses: record['allowPrivateAddresses'] };
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

  async isCancellationRequested(requestId: string): Promise<boolean> {
    const request = await this.client.collection('scanRequests').getOne(requestId);
    return request['status'] === 'cancelling' || request['status'] === 'cancelled';
  }

  async cancel(request: RecordModel, scan: RecordModel | null): Promise<void> {
    const completedAt = new Date().toISOString();
    await this.client.collection('scanRequests').update(request.id, { status: 'cancelled', completedAt, error: '' });
    await this.client.collection('targets').update(request['target'], { status: 'observed' });
    if (scan) await this.client.collection('scans').update(scan.id, { status: 'cancelled', completedAt, summary: 'Investigation stopped by the user.' });
  }

  async complete(request: RecordModel, scan: RecordModel, report: InvestigationReport): Promise<void> {
    for (const finding of report.findings) {
      await this.client.collection('findings').create({
        target: report.target.id, scan: scan.id, title: finding.title, summary: finding.summary,
        severity: finding.severity, confidence: finding.confidence, asset: finding.asset,
        evidence: finding.evidence, remediation: finding.remediation, sourceUrls: finding.sourceUrls, status: 'open'
      });
    }
    for (const tls of report.tls) {
      await this.client.collection('tlsObservations').create({ target: report.target.id, scan: scan.id, hostname: tls.hostname, valid: tls.valid, expiresAt: tls.validTo, details: tls });
    }
    const posture = Math.max(0, 100 - report.findings.reduce((sum, finding) => sum + ({ critical: 35, high: 22, medium: 11, low: 4, info: 0 })[finding.severity], 0));
    const serviceAction = [...report.actions].reverse().find((action) => action.tool === 'discover_service_hosts');
    let discoveredServices = 0;
    try { discoveredServices = (JSON.parse(serviceAction?.summary || '{}')['serviceHosts'] || []).length; } catch { /* Keep the conservative root-only count. */ }
    await this.client.collection('targets').update(report.target.id, { lastScanAt: report.completedAt, findingCount: report.findings.filter((item) => item.severity !== 'info').length, assetCount: Math.max(1, discoveredServices + 1), posture, status: 'observed' });
    await this.client.collection('scans').update(scan.id, { status: 'completed', completedAt: report.completedAt, summary: report.summary });
    await this.client.collection('scanRequests').update(request.id, { status: 'completed', completedAt: report.completedAt });
  }

  async fail(request: RecordModel, scan: RecordModel | null, error: unknown): Promise<void> {
    const message = error instanceof Error ? error.message : String(error);
    await this.client.collection('scanRequests').update(request.id, { status: 'failed', completedAt: new Date().toISOString(), error: message.slice(0, 500) });
    await this.client.collection('targets').update(request['target'], { status: 'observed' });
    if (scan) await this.client.collection('scans').update(scan.id, { status: 'failed', completedAt: new Date().toISOString(), error: message.slice(0, 500) });
  }
}
