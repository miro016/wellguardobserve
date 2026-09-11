import PocketBase, { type RecordModel } from 'pocketbase';
import { createHash } from 'node:crypto';
import type { AgentAction, AgentMessage, AuthorizedTarget, InvestigationReport, ScanMode, ScanPolicySnapshot } from './types';
import { buildKnowledgeObservation } from './knowledge';
import { nextScheduledAt } from './observation-schedule';
import type { CacheTelemetry } from './external-cache';
import { evaluateScan, improvementCandidates, type LearningDirectives } from './self-improvement';
import { GENERATED_TOOL_SCHEMA_VERSION, validateGeneratedTool, type GeneratedToolDefinition, type GeneratedToolProposal } from './generated-tools';
import { AGENT_TOOL_CATALOG, type AgentToolPolicy } from './tool-catalog';

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
    await this.syncAgentTools();
    await this.recoverInterruptedRequests();
  }

  private async syncAgentTools(): Promise<void> {
    const existing = await this.client.collection('agentTools').getFullList({ sort: 'name' });
    const byName = new Map(existing.map((record) => [String(record['name']), record]));
    for (const entry of AGENT_TOOL_CATALOG) {
      const current = byName.get(entry.name);
      const metadata = { title: entry.title, summary: entry.summary, category: entry.category, source: entry.source, version: entry.version, riskLevel: entry.riskLevel, supportedProfiles: entry.defaultProfiles, essential: Boolean(entry.essential) };
      if (current) {
        if ([...Object.entries(metadata)].some(([key, value]) => current[key] !== value)) await this.client.collection('agentTools').update(current.id, metadata);
      } else {
        await this.client.collection('agentTools').create({ name: entry.name, ...metadata, enabled: true, profiles: entry.defaultProfiles });
      }
    }
  }

  async agentToolPolicies(): Promise<Map<string, AgentToolPolicy>> {
    const records = await this.client.collection('agentTools').getFullList({ fields: 'name,enabled,profiles' });
    return new Map(records.map((record) => [String(record['name']), {
      name: String(record['name']), enabled: Boolean(record['enabled']),
      profiles: Array.isArray(record['profiles']) ? record['profiles'] : []
    } as AgentToolPolicy]));
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

  async enqueueDueObservation(): Promise<RecordModel | null> {
    const now = new Date();
    let schedule: RecordModel;
    try {
      schedule = await this.client.collection('observationSchedules').getFirstListItem(
        this.client.filter('enabled = true && nextRunAt <= {:now}', { now: now.toISOString() }), { sort: 'nextRunAt' }
      );
    } catch (error: unknown) {
      if ((error as { status?: number })?.status === 404) return null;
      throw error;
    }

    const cadence = schedule['cadence'] === 'monthly' ? 'monthly' : schedule['cadence'] === 'weekly' ? 'weekly' : 'daily';
    const nextRunAt = nextScheduledAt(cadence, now);
    const target = await this.client.collection('targets').getOne(schedule['target']);
    if (!['verified', 'admin_override'].includes(String(target['authorizationStatus'])) || target['status'] === 'paused') {
      await this.client.collection('observationSchedules').update(schedule.id, { enabled: false, nextRunAt: '' });
      return null;
    }

    try {
      await this.client.collection('scanRequests').getFirstListItem(
        this.client.filter('target = {:target} && (status = "queued" || status = "processing" || status = "cancelling")', { target: schedule['target'] })
      );
      await this.client.collection('observationSchedules').update(schedule.id, { nextRunAt });
      return null;
    } catch (error: unknown) {
      if ((error as { status?: number })?.status !== 404) throw error;
    }

    const mode = schedule['mode'] === 'light' ? 'light' : 'standard';
    const request = await this.client.collection('scanRequests').create({
      target: schedule['target'], mode, status: 'queued', extendedConsent: false
    });
    await this.client.collection('observationSchedules').update(schedule.id, {
      nextRunAt, lastQueuedAt: now.toISOString(), lastRequest: request.id
    });
    return request;
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
      id: record.id, workspace: String(record['workspace'] || ''), hostname: record['hostname'], hostHints: record['hostHints'] ?? [],
      authorizedHosts: scopes.map((scope) => String(scope['hostname'] || '')).filter(Boolean),
      authorizationStatus: record['authorizationStatus'], allowPrivateAddresses: record['allowPrivateAddresses']
    };
  }

  private generatedTool(record: RecordModel): GeneratedToolDefinition {
    return {
      id: record.id, workspace: String(record['workspace'] || ''), name: String(record['name'] || ''), title: String(record['title'] || ''),
      summary: String(record['summary'] || ''), rationale: String(record['rationale'] || ''), category: record['category'],
      evidence: Array.isArray(record['evidence']) ? record['evidence'] : [], spec: record['spec'], checksum: String(record['checksum'] || ''),
      status: record['status'], minProfile: record['minProfile'], unboundedAutoUse: Boolean(record['unboundedAutoUse']),
      compatibleProfiles: Array.isArray(record['compatibleProfiles']) ? record['compatibleProfiles'] : [], requestCeiling: Number(record['requestCeiling']) || 0,
      riskLevel: record['riskLevel'], generatedByModel: String(record['generatedByModel'] || ''), sourceScan: String(record['sourceScan'] || ''),
      sourceTarget: String(record['sourceTarget'] || ''), reviewedBy: String(record['reviewedBy'] || ''), reviewedAt: String(record['reviewedAt'] || ''),
      reviewNote: String(record['reviewNote'] || ''), created: record['created'], updated: record['updated']
    } as GeneratedToolDefinition;
  }

  async generatedTools(workspace: string): Promise<GeneratedToolDefinition[]> {
    if (!workspace) return [];
    const records = await this.client.collection('generatedTools').getFullList({
      filter: this.client.filter('workspace = {:workspace} && status != "rejected" && status != "disabled"', { workspace }), sort: '-updated'
    });
    return records.map((record) => this.generatedTool(record));
  }

  async proposeGeneratedTool(input: { workspace: string; target: string; scan: string; model: string; proposal: GeneratedToolProposal }): Promise<GeneratedToolDefinition> {
    const checked = validateGeneratedTool(input.proposal);
    if (!checked.proposal || !checked.validation.valid) throw new Error(`Generated tool proposal was rejected: ${checked.validation.errors.join(' ')}`);
    try {
      const existing = await this.client.collection('generatedTools').getFirstListItem(this.client.filter('workspace = {:workspace} && checksum = {:checksum}', { workspace: input.workspace, checksum: checked.validation.checksum }));
      return this.generatedTool(existing);
    } catch (error: unknown) { if ((error as { status?: number })?.status !== 404) throw error; }

    let name = checked.proposal.name;
    try {
      await this.client.collection('generatedTools').getFirstListItem(this.client.filter('workspace = {:workspace} && name = {:name}', { workspace: input.workspace, name }));
      name = `${name.slice(0, 56).replace(/-+$/, '')}-${checked.validation.checksum.slice(0, 6)}`;
    } catch (error: unknown) { if ((error as { status?: number })?.status !== 404) throw error; }
    const record = await this.client.collection('generatedTools').create({
      workspace: input.workspace, ...checked.proposal, name, schemaVersion: GENERATED_TOOL_SCHEMA_VERSION,
      checksum: checked.validation.checksum, compatibleProfiles: checked.validation.compatibleProfiles,
      requestCeiling: checked.validation.requestCeiling, riskLevel: checked.validation.riskLevel,
      status: 'proposed', minProfile: 'unbounded', unboundedAutoUse: true, generatedByModel: input.model,
      sourceScan: input.scan, sourceTarget: input.target
    });
    return this.generatedTool(record);
  }

  async recordGeneratedToolExecution(input: { workspace: string; tool: string; target: string; scan: string; profile: ScanMode; hostname: string; status: 'completed' | 'failed'; requestCount: number; matchedAssertions: number; summary: string }): Promise<void> {
    await this.client.collection('generatedToolExecutions').create({ ...input, occurredAt: new Date().toISOString() });
  }

  async approvedLearning(workspace: string): Promise<LearningDirectives> {
    if (!workspace) return { confidenceCaps: {}, prioritizeUnknownServices: false, proposalIds: [] };
    const rows = await this.client.collection('improvementProposals').getFullList({
      filter: this.client.filter('workspace = {:workspace} && status = "approved"', { workspace }), sort: 'created'
    });
    const directives: LearningDirectives = { confidenceCaps: {}, prioritizeUnknownServices: false, proposalIds: [] };
    for (const row of rows) {
      if (row['recommendedAction'] === 'cap-confidence') {
        directives.proposalIds.push(row.id);
        const parameter = row['parameter'] && typeof row['parameter'] === 'object' ? row['parameter'] as Record<string, unknown> : {};
        directives.confidenceCaps[String(row['scopeKey'])] = Math.max(1, Math.min(100, Number(parameter['maximumConfidence']) || 60));
      }
      if (row['recommendedAction'] === 'prioritize-unknown-service') { directives.prioritizeUnknownServices = true; directives.proposalIds.push(row.id); }
    }
    return directives;
  }

  async refreshImprovementProposals(workspaceId?: string): Promise<void> {
    const workspaces = workspaceId
      ? [{ id: workspaceId }]
      : await this.client.collection('workspaces').getFullList({ filter: 'status = "active"', fields: 'id' });
    for (const workspace of workspaces) {
      const [feedback, evaluationRows] = await Promise.all([
        this.client.collection('findingFeedback').getFullList({ filter: this.client.filter('workspace = {:workspace} && verdict = "false_positive"', { workspace: workspace.id }), fields: 'patternKey' }),
        this.client.collection('scanEvaluations').getList(1, 50, { filter: this.client.filter('workspace = {:workspace}', { workspace: workspace.id }), sort: '-created', fields: 'unknownServices,toolErrors,signals' })
      ]);
      const patterns = new Map<string, number>();
      for (const item of feedback) patterns.set(String(item['patternKey']), (patterns.get(String(item['patternKey'])) || 0) + 1);
      const candidates = improvementCandidates({
        falsePositivePatterns: [...patterns].map(([patternKey, count]) => ({ patternKey, count })),
        evaluations: evaluationRows.items.map((row) => ({ unknownServices: Number(row['unknownServices']) || 0, toolErrors: Number(row['toolErrors']) || 0, signals: row['signals'] && typeof row['signals'] === 'object' ? row['signals'] as { failingTools: string[]; unknownAssetKeys: string[]; cacheBySource: Record<string, { hits: number; misses: number; originRequests: number }> } : { failingTools: [], unknownAssetKeys: [], cacheBySource: {} } }))
      });
      for (const candidate of candidates) {
        let existing: RecordModel | null = null;
        try { existing = await this.client.collection('improvementProposals').getFirstListItem(this.client.filter('workspace = {:workspace} && proposalKey = {:key}', { workspace: workspace.id, key: candidate.proposalKey })); }
        catch (error: unknown) { if ((error as { status?: number })?.status !== 404) throw error; }
        if (existing) await this.client.collection('improvementProposals').update(existing.id, { ...candidate, status: existing['status'] });
        else await this.client.collection('improvementProposals').create({ workspace: workspace.id, ...candidate, status: 'proposed', applicationCount: 0 });
      }
    }
  }

  async createScan(targetId: string, requestId: string): Promise<RecordModel> {
    return await this.client.collection('scans').create({ target: targetId, request: requestId, status: 'running', startedAt: new Date().toISOString(), summary: '' });
  }

  async saveAction(targetId: string, scanId: string, action: AgentAction): Promise<void> {
    const saved = await this.client.collection('agentActions').create({ target: targetId, scan: scanId, tool: action.tool, input: action.input, summary: action.summary.slice(0, 28_000), occurredAt: action.at });
    let output: unknown;
    try { output = JSON.parse(action.summary); } catch { output = { text: action.summary }; }
    await this.client.collection('toolOutputs').create({
      target: targetId, scan: scanId, action: saved.id, tool: action.tool, input: action.input, output,
      outputSha256: createHash('sha256').update(action.summary).digest('hex'),
      failed: Boolean(output && typeof output === 'object' && '_wellguardError' in output), occurredAt: action.at
    });
  }

  async saveMessage(targetId: string, scanId: string, message: AgentMessage): Promise<void> {
    await this.client.collection('agentMessages').create({ target: targetId, scan: scanId, role: message.role, content: message.content, reasoning: message.reasoning, toolName: message.toolName, sequence: message.sequence, occurredAt: message.at });
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

  async complete(request: RecordModel, scan: RecordModel, report: InvestigationReport, cache: CacheTelemetry, directives?: LearningDirectives): Promise<void> {
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
        const priorEvidence = Array.isArray(existing['evidence']) ? (existing['evidence'] as string[]) : [];
        const mergedEvidence = [...new Set([...priorEvidence, ...finding.evidence])].slice(-24);
        const priorSources = Array.isArray(existing['sourceUrls']) ? (existing['sourceUrls'] as string[]) : [];
        const mergedSources = [...new Set([...priorSources, ...finding.sourceUrls])].slice(-20);
        await this.client.collection('findings').update(existing.id, {
          scan: scan.id, summary: finding.summary, severity, confidence: Math.max(Number(existing['confidence']) || 0, finding.confidence),
          evidence: mergedEvidence, remediation: finding.remediation || existing['remediation'], sourceUrls: mergedSources,
          cveIds: finding.cveIds, weaknessIds: finding.weaknessIds, frameworkRefs: finding.frameworkRefs || [], threatContext: finding.threatContext || existing['threatContext'] || {},
          customerNarrative: finding.customerNarrative || existing['customerNarrative'] || null,
          assetKey: finding.assetKey || '', relatedAssetKeys: finding.relatedAssetKeys || [], relationKey: finding.relationKey || '',
          observations: observations.slice(-12), runCount: (Number(existing['runCount']) || 1) + 1,
          status: existing['status'] === 'resolved' ? 'open' : existing['status']
        });
      } else {
        await this.client.collection('findings').create({
          target: report.target.id, scan: scan.id, title: finding.title, summary: finding.summary,
          severity: finding.severity, confidence: finding.confidence, asset: finding.asset,
          evidence: finding.evidence, remediation: finding.remediation, sourceUrls: finding.sourceUrls,
          cveIds: finding.cveIds, weaknessIds: finding.weaknessIds, frameworkRefs: finding.frameworkRefs || [], threatContext: finding.threatContext || {}, customerNarrative: finding.customerNarrative || null, assetKey: finding.assetKey || '',
          relatedAssetKeys: finding.relatedAssetKeys || [], relationKey: finding.relationKey || '', status: 'open',
          observations: [observation], runCount: 1
        });
      }
      const knowledge = buildKnowledgeObservation(finding, report.assets);
      try {
        await this.client.collection('knowledgeObservations').create({
          target: report.target.id, scan: scan.id, ...knowledge, observedAt: report.completedAt
        });
      } catch (error) {
        // Knowledge is derived, secondary evidence. A duplicate or temporarily unavailable
        // knowledge store must never turn an otherwise completed investigation into a failure.
        console.warn(`Could not retain knowledge observation ${knowledge.patternKey}:`, error);
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
    try {
      const target = await this.client.collection('targets').getOne(report.target.id, { fields: 'workspace' });
      const evaluation = evaluateScan(report, cache);
      await this.client.collection('scanEvaluations').create({
        workspace: target['workspace'], target: report.target.id, scan: scan.id,
        model: process.env['OLLAMA_MODEL'] || 'glm-5.3:cloud', reasoningEffort: process.env['OLLAMA_REASONING_EFFORT'] || 'high', profile: request['mode'] || 'standard', ...evaluation
      });
      const appliedAt = new Date().toISOString();
      for (const id of directives?.proposalIds || []) {
        const proposal = await this.client.collection('improvementProposals').getOne(id, { fields: 'applicationCount' });
        await this.client.collection('improvementProposals').update(id, { applicationCount: (Number(proposal['applicationCount']) || 0) + 1, lastAppliedAt: appliedAt });
      }
      await this.refreshImprovementProposals(String(target['workspace'] || ''));
    } catch (error) {
      console.warn('Could not retain scan evaluation or refresh learning proposals:', error);
    }
  }

  async fail(request: RecordModel, scan: RecordModel | null, error: unknown): Promise<void> {
    const message = error instanceof Error ? error.message : String(error);
    const completedAt = new Date().toISOString();
    await this.client.collection('scanRequests').update(request.id, { status: 'failed', completedAt, heartbeatAt: completedAt, phase: 'Investigation failed', error: message.slice(0, 500) });
    await this.client.collection('targets').update(request['target'], { status: 'observed' });
    if (scan) await this.client.collection('scans').update(scan.id, { status: 'failed', completedAt: new Date().toISOString(), error: message.slice(0, 500) });
  }
}
