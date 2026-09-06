import PocketBase, { type RecordModel } from 'pocketbase';
import type { AgentAction, AgentMessage, AuthorizedTarget, InvestigationReport, ScanPolicySnapshot } from './types';

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

  async claim(record: RecordModel, profileSnapshot: ScanPolicySnapshot): Promise<boolean> {
    const current = await this.client.collection('scanRequests').getOne(record.id);
    if (current['status'] !== 'queued') return false;
    const startedAt = new Date().toISOString();
    await this.client.collection('scanRequests').update(record.id, { status: 'processing', startedAt, heartbeatAt: startedAt, phase: 'Preparing investigation', actionCount: 0, messageCount: 0, profileSnapshot, error: '' });
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
    await this.client.collection('agentActions').create({ target: targetId, scan: scanId, tool: action.tool, input: action.input, summary: action.summary.slice(0, 5000), occurredAt: action.at });
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


  private async runScoreboard(targetId: string, scan: RecordModel, report: InvestigationReport): Promise<string> {
    const bySeverity = (list: Array<{ severity: string }>) => {
      const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const item of list) (counts as Record<string, number>)[item.severity] = ((counts as Record<string, number>)[item.severity] || 0) + 1;
      return counts;
    };
    const current = bySeverity(report.findings as Array<{ severity: string }>);
    let previousNote = 'First recorded run for this target.';
    let previous = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let previousPortCount = 0;
    try {
      const last = await this.client.collection('scans').getFirstListItem(
        this.client.filter('target = {:target} && status = "completed" && id != {:scan}', { target: targetId, scan: scan.id }), { sort: '-completedAt' }
      );
      const priorFindings = await this.client.collection('findings').getFullList({ filter: this.client.filter('scan = {:scan}', { scan: last.id }), fields: 'severity' });
      previous = bySeverity(priorFindings as unknown as Array<{ severity: string }>);
      const priorActions = await this.client.collection('agentActions').getFullList({ filter: this.client.filter('scan = {:scan}', { scan: last.id }), fields: 'summary' });
      const priorSweep = priorActions.find((a) => String(a['summary'] || '').includes('"openPorts"'));
      if (priorSweep) previousPortCount = (String(priorSweep['summary']).match(/"openPorts":\s*\[[^\]]*\]/)?.[0]?.split(',').length) || 0;
      previousNote = `Previous run ${last.completedAt || last.created}: critical ${previous.critical}, high ${previous.high}, medium ${previous.medium}, low ${previous.low}, info ${previous.info}.`;
    } catch { /* no previous completed run */ }
    const openPorts = (report.assets as unknown as Array<Record<string, unknown>>).filter((a) => String(a['kind']) === 'port' || String(a['key'] || '').startsWith('port:')).length;
    const lines = [
      '---', '## Run scoreboard (cumulative, for comparing capability growth)',
      `This run: critical ${current.critical}, high ${current.high}, medium ${current.medium}, low ${current.low}, info ${current.info}.`,
      previousNote,
      `Assets observed this run: ${report.assets.length}. Open ports observed this run: ${openPorts || 'n/a'}${previousPortCount ? ` (previous: ${previousPortCount})` : ''}.`
    ];
    return lines.join('\n');
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
      const observation = { scan: scan.id, observedAt: report.completedAt, profile: request['mode'] || '' };
      let existing: RecordModel | null = null;
      try {
        existing = await this.client.collection('findings').getFirstListItem(
          this.client.filter('target = {:target} && title = {:title} && asset = {:asset}', { target: report.target.id, title: finding.title, asset: finding.asset })
        );
      } catch { /* first observation of this finding class */ }
      if (existing) {
        const observations = Array.isArray(existing['observations']) ? (existing['observations'] as unknown[]).filter((entry) => JSON.stringify(entry).indexOf(scan.id) === -1) : [];
        observations.push(observation);
        const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>;
        const severity = (rank[finding.severity] || 0) >= (rank[String(existing['severity'])] || 0) ? finding.severity : String(existing['severity']);
        await this.client.collection('findings').update(existing.id, {
          scan: scan.id, summary: finding.summary, severity, confidence: Math.max(Number(existing['confidence']) || 0, finding.confidence),
          evidence: finding.evidence, remediation: finding.remediation, sourceUrls: finding.sourceUrls,
          cveIds: finding.cveIds, weaknessIds: finding.weaknessIds, frameworkRefs: finding.frameworkRefs || [],
          customerNarrative: finding.customerNarrative || existing['customerNarrative'] || null,
          assetKey: finding.assetKey || '', relatedAssetKeys: finding.relatedAssetKeys || [], relationKey: finding.relationKey || '',
          observations: observations.slice(-12), runCount: (Number(existing['runCount']) || 1) + 1
        });
      } else {
        await this.client.collection('findings').create({
          target: report.target.id, scan: scan.id, title: finding.title, summary: finding.summary,
          severity: finding.severity, confidence: finding.confidence, asset: finding.asset,
          evidence: finding.evidence, remediation: finding.remediation, sourceUrls: finding.sourceUrls,
          cveIds: finding.cveIds, weaknessIds: finding.weaknessIds, frameworkRefs: finding.frameworkRefs || [], customerNarrative: finding.customerNarrative || null, assetKey: finding.assetKey || '',
          relatedAssetKeys: finding.relatedAssetKeys || [], relationKey: finding.relationKey || '', status: 'open',
          observations: [observation], runCount: 1
        });
      }
    }
    for (const tls of report.tls) {
      await this.client.collection('tlsObservations').create({ target: report.target.id, scan: scan.id, hostname: tls.hostname, valid: tls.valid, expiresAt: tls.validTo, details: tls });
    }
    const posture = Math.max(0, 100 - report.findings.reduce((sum, finding) => sum + ({ critical: 35, high: 22, medium: 11, low: 4, info: 0 })[finding.severity], 0));
    await this.client.collection('targets').update(report.target.id, { lastScanAt: report.completedAt, findingCount: report.findings.filter((item) => item.severity !== 'info').length, assetCount: Math.max(1, report.assets.length), posture, status: 'observed' });
    const scoreboard = await this.runScoreboard(report.target.id, scan, report);
    const combined = `${report.summary}\n\n${scoreboard}`;
    await this.client.collection('scans').update(scan.id, { status: 'completed', completedAt: report.completedAt, summary: combined.slice(0, 4000) });
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
