import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { ScopeGuard } from '../security/scope-guard';

const exec = promisify(execFile);
const VANGUARD_REVISION = 'd9e2b785b973bd5a44af8ec86766808542ae8cb6';
const PROFILE_PATH = process.env['WELLGUARD_VANGUARD_PROFILE'] || '/app/integrations/vanguard/profile.yaml';
const COLLECT_BIN = process.env['WELLGUARD_VANGUARD_COLLECT'] || '/usr/local/bin/vanguard-collect';
const PROJECT_BIN = process.env['WELLGUARD_VANGUARD_PROJECTIONS'] || '/usr/local/bin/vanguard-projections';

type JsonRecord = Record<string, unknown>;

function list(value: unknown): JsonRecord[] {
  return Array.isArray(value) ? value.filter((item): item is JsonRecord => Boolean(item && typeof item === 'object')) : [];
}

function boundedValue(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return value.slice(0, 500);
  if (typeof value === 'number' || typeof value === 'boolean' || value == null) return value;
  if (depth >= 3) return Array.isArray(value) ? `[${value.length} values]` : '[nested value]';
  if (Array.isArray(value)) return value.slice(0, 12).map((item) => boundedValue(item, depth + 1));
  if (typeof value === 'object') return Object.fromEntries(Object.entries(value as JsonRecord).slice(0, 24).map(([key, item]) => [key, boundedValue(item, depth + 1)]));
  return String(value).slice(0, 500);
}

function compactNode(node: JsonRecord): JsonRecord {
  return {
    id: node['id'], type: node['type'], key: node['key'], label: node['label'], scope: node['scope'], kind: node['kind'],
    referencedOnly: node['referenced_only'], primaryCurrentness: node['primary_currentness'], badges: node['badges'],
    attributes: boundedValue(node['attributes']), technologies: list(node['technologies']).slice(0, 8).map((technology) => boundedValue({ key: technology['key'], versions: technology['versions'], categories: technology['categories'], confidence: technology['confidence'], sources: technology['sources'], evidenceIds: technology['evidence_ids'] })),
    findings: list(node['findings']).slice(0, 6).map((finding) => boundedValue({ id: finding['id'], rule: finding['rule'], title: finding['title'], category: finding['category'], severity: finding['severity'], confidence: finding['confidence'], evidenceIds: finding['evidence_ids'] })),
    paths: list(node['paths']).slice(0, 8).map((path) => boundedValue({ path: path['path'], url: path['url'], statusCode: path['status_code'], title: path['title'], server: path['server'], authType: path['auth_type'], sources: path['sources'] })),
    evidenceIds: Array.isArray(node['evidence_ids']) ? node['evidence_ids'].slice(0, 10) : []
  };
}

function compactFinding(finding: JsonRecord): unknown {
  return boundedValue({ id: finding['id'], rule: finding['rule'], title: finding['title'], category: finding['category'], severity: finding['severity'], confidence: finding['confidence'], asset: finding['asset'], evidenceIds: finding['evidence_ids'] });
}

function nodeId(node: JsonRecord): string { return String(node['id'] || ''); }
function nodeHost(node: JsonRecord): string {
  const attributes = node['attributes'] && typeof node['attributes'] === 'object' ? node['attributes'] as JsonRecord : {};
  return String(attributes['host'] || node['label'] || node['key'] || '').trim().toLowerCase().replace(/\.$/, '');
}
function withinRoot(hostname: string, root: string): boolean { return !root || hostname === root || hostname.endsWith(`.${root}`); }

export function vanguardEngagement(hostname: string): string {
  const root = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(root)) throw new Error('Vanguard requires a normalized public DNS root.');
  return `customer:\n  name: "Wellguard authorized target"\nscope:\n  domains:\n    roots: ["${root}"]\n    include: []\n    exclude: []\n    restrict_discovery_to_roots: true\n  ip_ranges:\n    allow: []\n    exclude: []\n  depth_cap: 2\n  probe_provider_hosts: corroborated\nlimits:\n  max_paid_lookups_per_tool: 0\n  max_active_hosts: 40\nauthorization:\n  goscans:\n    allow_out_of_scope_http_requests: false\n`;
}

export function summarizeVanguardProjection(attack: JsonRecord, report: JsonRecord, issues: JsonRecord, manifest: JsonRecord, collectionStatus: string) {
  const rootTarget = String(attack['root_target'] || manifest['root_target'] || '').trim().toLowerCase().replace(/\.$/, '');
  const sourceDomains = list(attack['domains']); const sourceServers = list(attack['ip_addresses']); const sourceServices = list(attack['services']);
  const sourceWebSurfaces = list(attack['web_surfaces']); const sourceEdges = list(attack['edges']);
  const allDomains = rootTarget ? sourceDomains.filter((node) => withinRoot(nodeHost(node), rootTarget)) : sourceDomains;
  const admittedIds = new Set(allDomains.map(nodeId).filter(Boolean));
  const admittedAddressIds = new Set(sourceEdges.filter((edge) => admittedIds.has(String(edge['from'] || '')) && String(edge['type'] || '') === 'resolves_to').map((edge) => String(edge['to'] || '')).filter(Boolean));
  const allServers = rootTarget ? sourceServers.filter((node) => admittedAddressIds.has(nodeId(node))) : sourceServers;
  for (const node of allServers) admittedIds.add(nodeId(node));
  const admittedAddresses = new Set(allServers.flatMap((node) => [String(node['label'] || ''), String(node['key'] || '')]).filter(Boolean));
  const allWebSurfaces = rootTarget ? sourceWebSurfaces.filter((node) => withinRoot(nodeHost(node), rootTarget)) : sourceWebSurfaces;
  const allServices = rootTarget ? sourceServices.filter((node) => {
    const attributes = node['attributes'] && typeof node['attributes'] === 'object' ? node['attributes'] as JsonRecord : {};
    const host = String(attributes['host'] || '').toLowerCase().replace(/\.$/, '');
    return (host && withinRoot(host, rootTarget)) || admittedAddresses.has(String(attributes['ip'] || ''));
  }) : sourceServices;
  for (const node of [...allWebSurfaces, ...allServices]) admittedIds.add(nodeId(node));
  const allEdges = rootTarget ? sourceEdges.filter((edge) => admittedIds.has(String(edge['from'] || '')) && admittedIds.has(String(edge['to'] || ''))) : sourceEdges;
  const domains = allDomains.slice(0, 40).map(compactNode);
  const servers = allServers.slice(0, 40).map(compactNode);
  const services = allServices.slice(0, 70).map(compactNode);
  const webSurfaces = allWebSurfaces.slice(0, 40).map(compactNode);
  const edges = allEdges.slice(0, 140).map((edge) => boundedValue({ type: edge['type'], from: edge['from'], to: edge['to'], confidence: edge['confidence'], currentness: edge['currentness'], sources: edge['sources'], evidenceIds: edge['evidence_ids'] }));
  const compact = {
    integration: { name: 'Vanguard', revision: VANGUARD_REVISION, contract: 'collection plus deterministic offline projection' },
    status: collectionStatus, rootTarget, scanId: attack['scan_id'] || manifest['scan_id'],
    generatedAt: attack['generated_at'], analysisAsOf: attack['analysis_as_of'], analysisPartial: attack['analysis_partial'],
    counts: { domains: allDomains.length, servers: allServers.length, services: allServices.length, webSurfaces: allWebSurfaces.length, edges: allEdges.length },
    sourceCounts: { domains: sourceDomains.length, servers: sourceServers.length, services: sourceServices.length, webSurfaces: sourceWebSurfaces.length, edges: sourceEdges.length },
    retainedCounts: { domains: domains.length, servers: servers.length, services: services.length, webSurfaces: webSurfaces.length, edges: edges.length },
    domains, servers, services, webSurfaces, edges,
    report: { summary: boundedValue(report['summary']), risk: boundedValue(report['risk']), findings: list(report['findings']).slice(0, 30).map(compactFinding) },
    issues: { summary: boundedValue(issues['summary']), issues: list(issues['issues']).slice(0, 30).map(compactFinding) },
    integrity: boundedValue(attack['integrity']), contractionSummary: boundedValue(attack['contraction_summary']), truncated: false
  };
  const shrinkable: unknown[][] = [edges, webSurfaces, services, domains, servers, compact.report.findings, compact.issues.issues];
  while (Buffer.byteLength(JSON.stringify(compact)) > 13_000 && shrinkable.some((items) => items.length)) {
    const largest = shrinkable.filter((items) => items.length).sort((a, b) => JSON.stringify(b).length - JSON.stringify(a).length)[0];
    largest?.pop(); compact.truncated = true;
  }
  compact.retainedCounts = { domains: domains.length, servers: servers.length, services: services.length, webSurfaces: webSurfaces.length, edges: edges.length };
  return { ...compact, outputSha256: createHash('sha256').update(JSON.stringify(compact)).digest('hex') };
}

async function json(path: string): Promise<JsonRecord> {
  try { return JSON.parse(await readFile(path, 'utf8')) as JsonRecord; } catch { return {}; }
}

export async function runVanguardObservation(scope: ScopeGuard, signal?: AbortSignal) {
  signal?.throwIfAborted();
  await Promise.all([access(COLLECT_BIN), access(PROJECT_BIN), access(PROFILE_PATH)]).catch(() => { throw new Error('Vanguard runtime is not installed in this Wellguard deployment.'); });
  const work = await mkdtemp(join(tmpdir(), 'wellguard-vanguard-'));
  const engagement = join(work, 'engagement.yaml'); const collection = join(work, 'collection'); const projection = join(work, 'projection');
  await writeFile(engagement, vanguardEngagement(scope.rootHostname), { mode: 0o600 });
  let status = 'succeeded'; let collectorLog = '';
  try {
    try {
      const result = await exec(COLLECT_BIN, ['run', '-engagement', engagement, '-profile', PROFILE_PATH, '-destination', collection], { signal, timeout: 240_000, maxBuffer: 2 * 1024 * 1024, env: process.env });
      collectorLog = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
    } catch (error) {
      const failure = error as Error & { code?: number | string; stdout?: string; stderr?: string };
      collectorLog = `${failure.stdout || ''}\n${failure.stderr || ''}`.trim();
      if (String(failure.code) !== '3') throw new Error(`Vanguard collection failed: ${collectorLog.slice(-1_500) || failure.message}`);
      status = 'degraded';
    }
    await exec(PROJECT_BIN, ['build', '-collection', collection, '-destination', projection], { signal, timeout: 120_000, maxBuffer: 2 * 1024 * 1024, env: process.env });
    const [attack, report, issues, manifest] = await Promise.all([
      json(join(projection, 'graphs', 'attack-surface.json')), json(join(projection, 'reports', 'report.json')),
      json(join(projection, 'reports', 'issues.json')), json(join(collection, 'manifest.json'))
    ]);
    return { ...summarizeVanguardProjection(attack, report, issues, manifest, status), collectorLog: collectorLog.split('\n').slice(-8).map((line) => line.slice(0, 300)) };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
