import type { ScopeGuard } from '../security/scope-guard';
import { inspectHttp } from './http';
import type { TechnologySignal } from './http';

const DEFAULT_LABELS = [
  'auth', 'sso', 'keycloak', 'keycloak1', 'identity', 'login', 'accounts', 'admin', 'panel', 'api',
  'dev', 'staging', 'test', 'monitor', 'status', 'grafana', 'prometheus', 'jenkins', 'git', 'registry',
  'vpn', 'mail'
];
const PRODUCT_PATTERN = /\b(keycloak|easypanel|grafana|prometheus|jenkins|gitlab|kibana|rabbitmq|phpmyadmin|portainer|traefik|swagger|openapi|jupyter|wordpress|beszel|excalidraw|linkwarden|logto|immich|minio)\b/gi;

interface CompactObservation {
  hostname: string;
  status: number;
  initialStatus?: number;
  title: string;
  location: string;
  server: string;
  contentType: string;
  textSample: string;
  serviceWords: string[];
  technologies: TechnologySignal[];
}

export interface ServiceHostObservation {
  hostname: string;
  status: number;
  title: string;
  location: string;
  server: string;
  productHints: string[];
  technologies: TechnologySignal[];
  evidence: string;
}

function compact(hostname: string, value: Record<string, unknown>): CompactObservation {
  const headers = (value['headers'] || {}) as Record<string, string>;
  const signals = (value['signals'] || {}) as Record<string, unknown>;
  return {
    hostname,
    status: Number(value['status'] || 0),
    title: String(signals['title'] || '').trim(),
    location: String(headers['location'] || '').trim(),
    server: String(headers['server'] || '').trim(),
    contentType: String(headers['content-type'] || '').trim(),
    textSample: String(signals['textSample'] || '').slice(0, 500),
    serviceWords: Array.isArray(signals['serviceWords']) ? signals['serviceWords'].map(String) : [],
    technologies: Array.isArray(signals['technologies']) ? signals['technologies'].flatMap((item) => {
      if (!item || typeof item !== 'object') return [];
      const value = item as Record<string, unknown>;
      return [{ name: String(value['name'] || ''), evidence: String(value['evidence'] || '') }].filter((technology) => technology.name);
    }) : []
  };
}

function normalizedIdentity(value: CompactObservation): string {
  return [value.status, value.title.toLowerCase(), value.location.toLowerCase(), value.server.toLowerCase(), value.contentType.toLowerCase()].join('|');
}

export function classifyServiceObservation(candidate: CompactObservation, root?: CompactObservation): ServiceHostObservation | null {
  const missing = candidate.status === 404 || /(?:not found|unknown host|no such (?:app|service)|application .{0,80} not found)/i.test(`${candidate.title} ${candidate.textSample}`);
  if (missing || candidate.status === 0) return null;
  const mirrorsRoot = root && normalizedIdentity(candidate) === normalizedIdentity(root);
  if (mirrorsRoot) return null;
  const identity = [candidate.title, candidate.location, ...candidate.serviceWords].join(' ');
  const productHints = [...new Set((identity.match(PRODUCT_PATTERN) || []).map((item) => item.toLowerCase()))];
  const response = candidate.initialStatus
    ? `HTTPS GET / returned ${candidate.initialStatus}, then the same-host redirect returned ${candidate.status}${candidate.title ? ` with title “${candidate.title}”` : ''}`
    : `HTTPS GET / returned ${candidate.status}${candidate.title ? ` with title “${candidate.title}”` : ''}`;
  const redirect = candidate.location ? ` and Location ${candidate.location}` : '';
  return { hostname: candidate.hostname, status: candidate.status, title: candidate.title, location: candidate.location, server: candidate.server, productHints, technologies: candidate.technologies, evidence: `${response}${redirect}.` };
}

async function observeHostname(scope: ScopeGuard, hostname: string): Promise<CompactObservation> {
  const initial = compact(hostname, await inspectHttp(scope, { hostname, tls: true, port: 443, path: '/' }));
  if (initial.status < 300 || initial.status > 399 || !initial.location.startsWith('/') || initial.location.startsWith('//')) return initial;
  try {
    const followed = compact(hostname, await inspectHttp(scope, { hostname, tls: true, port: 443, path: initial.location }));
    return { ...followed, initialStatus: initial.status, location: initial.location };
  } catch { return initial; }
}

async function passiveHosts(scope: ScopeGuard): Promise<{ hosts: string[]; status: string }> {
  try {
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(scope.rootHostname)}`, {
      headers: { 'user-agent': 'WellguardObserve/0.1 (+authorized reconnaissance)' }, signal: AbortSignal.timeout(12_000)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.text()).slice(0, 160_000);
    const hosts = [...new Set(body.split(/\r?\n/).map((line) => line.split(',')[0]?.trim().toLowerCase()).filter(Boolean))]
      .flatMap((hostname) => { try { return [scope.assertHostname(hostname)]; } catch { return []; } })
      .filter((hostname) => hostname !== scope.rootHostname);
    return { hosts, status: `HackerTarget returned ${hosts.length} in-scope passive hostname candidates.` };
  } catch (error) {
    return { hosts: [], status: `HackerTarget passive lookup unavailable: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export async function discoverServiceHosts(scope: ScopeGuard, input: { candidates?: string[] } = {}) {
  const passive = await passiveHosts(scope);
  const requested = [...(scope.target.hostHints || []), ...(input.candidates || [])]
    .flatMap((hostname) => { try { return [scope.assertHostname(hostname)]; } catch { return []; } });
  const defaults = DEFAULT_LABELS.map((label) => `${label}.${scope.rootHostname}`);
  const limit = 80;
  const candidates = [...new Set([...requested, ...passive.hosts, ...defaults])].filter((hostname) => hostname !== scope.rootHostname).slice(0, limit);

  let root: CompactObservation | undefined;
  try { root = await observeHostname(scope, scope.rootHostname); } catch { /* Discovery can continue when the root HTTP response is unavailable. */ }

  const observations = new Array<CompactObservation | null>(candidates.length).fill(null);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(5, candidates.length) }, async () => {
    while (cursor < candidates.length) {
      const index = cursor++;
      const hostname = candidates[index]!;
      try { observations[index] = await observeHostname(scope, hostname); }
      catch { observations[index] = null; }
    }
  });
  await Promise.all(workers);

  const serviceHosts = observations.flatMap((observation) => observation ? [classifyServiceObservation(observation, root)].filter((item): item is ServiceHostObservation => Boolean(item)) : [])
    .sort((a, b) => servicePriority(b) - servicePriority(a));
  const missingOrMirrored = observations.filter((observation) => observation && !classifyServiceObservation(observation, root)).length;
  const unreachable = observations.filter((observation) => !observation).length;
  return {
    root: root ? { status: root.status, title: root.title, server: root.server, serviceWords: root.serviceWords, technologies: root.technologies } : null,
    passiveSource: passive.status,
    candidatesConsidered: candidates.length,
    serviceHosts,
    excludedAsMissingOrMirrored: missingOrMirrored,
    unreachable,
    securityNote: 'Candidates are restricted to the authorized root. A hostname is retained only when its HTTPS response differs from the root and is not a generic reverse-proxy missing-route response. Discovery may follow one relative redirect on the same validated hostname to retain page identity and technology markers.'
  };
}

function servicePriority(item: ServiceHostObservation): number {
  const identity = [item.hostname, item.title, item.location, ...item.productHints].join(' ').toLowerCase();
  if (/keycloak/.test(identity)) return 120;
  if (/openid|oauth|identity|\bsso\b/.test(identity)) return 100;
  if (/admin|panel|console|monitor|grafana|prometheus|jenkins|beszel|minio/.test(identity)) return 70;
  if (item.location.startsWith('http')) return 45;
  return 10;
}
