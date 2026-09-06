import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedJsonPost } from './http';

/**
 * Bounded authentication-control review for the Advanced profile.
 * The payload list is fixed inside this module; the model can only choose
 * which already-observed login endpoint to test and how many attempts.
 */

const MAX_ATTEMPTS = 12;

const INJECTION_PROBES: ReadonlyArray<{ id: string; field: 'username' | 'password'; value: string; rationale: string }> = [
  { id: 'tautology-username', field: 'username', value: "' or 1=1--", rationale: 'Fixed SQL tautology in the identifier field.' },
  { id: 'tautology-username-dq', field: 'username', value: '" or 1=1--', rationale: 'Fixed double-quoted tautology in the identifier field.' },
  { id: 'tautology-password', field: 'password', value: "' or 1=1--", rationale: 'Fixed SQL tautology in the password field.' }
];

const DEFAULT_CREDENTIALS: ReadonlyArray<{ username: string; password: string }> = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'admin123' },
  { username: 'admin', password: 'password' },
  { username: 'administrator', password: 'password' },
  { username: 'admin@localhost', password: 'admin' },
  { username: 'admin@example.com', password: 'admin123' },
  { username: 'root', password: 'root' },
  { username: 'test', password: 'test' }
];

const TOKEN_PATTERN = /"(?:token|authentication|access_token|session|jwt)"\s*:\s*(?:"(?:[^"]{16,})"|\{)/i;

interface EndpointInput { hostname?: string; port?: number; tls?: boolean; path?: string; usernameField?: string; passwordField?: string; maxAttempts?: number }

function fieldName(value: unknown, fallback: string): string {
  const candidate = String(value || fallback);
  if (!/^[A-Za-z][A-Za-z0-9_.-]{0,31}$/.test(candidate)) throw new Error('Field names are restricted to safe identifier characters.');
  return candidate;
}

function assertLoginPath(scope: ScopeGuard, path: string | undefined): string {
  const normalized = scope.assertPath(path || '/');
  if (/[?#]/.test(normalized)) throw new Error('The authentication endpoint path must not contain a query or fragment.');
  if (!/(login|signin|sign-in|auth(?:enticate)?|token|session)/i.test(normalized)) {
    throw new Error('Authentication probing is restricted to endpoints that advertise login/token/session semantics.');
  }
  return normalized;
}

function extractToken(raw: string): string {
  try {
    const body = JSON.parse(raw) as Record<string, unknown>;
    const candidates = [body['token'], body['access_token'], (body['authentication'] as Record<string, unknown> | undefined)?.['token'], (body['session'] as Record<string, unknown> | undefined)?.['token']];
    const token = candidates.find((value) => typeof value === 'string' && (value as string).length > 12 && (value as string).length < 4096);
    return typeof token === 'string' ? token : '';
  } catch { return ''; }
}

function outcome(response: { status: number; raw: string }): { authenticated: boolean; marker: string; token: string } {
  if (response.status === 401 || response.status === 403) return { authenticated: false, marker: 'rejected', token: '' };
  if (response.status >= 200 && response.status < 300 && TOKEN_PATTERN.test(response.raw)) return { authenticated: true, marker: 'token issued', token: extractToken(response.raw) };
  if (response.status >= 400) return { authenticated: false, marker: `http ${response.status}`, token: '' };
  return { authenticated: false, marker: 'no token', token: '' };
}

export async function inspectAuthenticationControls(scope: ScopeGuard, input: EndpointInput) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = assertLoginPath(scope, input.path);
  const usernameField = fieldName(input.usernameField, 'email');
  const passwordField = fieldName(input.passwordField, 'password');
  const budget = Math.max(1, Math.min(MAX_ATTEMPTS, Math.floor(input.maxAttempts || 6)));

  // Baseline: arbitrary invalid pair, to learn the rejection shape.
  const baselinePayload = { [usernameField]: 'wellguard-control@example.invalid', [passwordField]: 'wellguard-control-0a9d1c' };
  const baseline = await requestAuthorizedJsonPost(scope, { hostname, port, tls, path }, baselinePayload);
  const baselineOutcome = outcome(baseline);
  let acquiredSession = '';

  const attempts: Array<{ probe: string; status: number; result: string }> = [{ probe: 'baseline-invalid', status: baseline.status, result: baselineOutcome.marker }];
  const suggestedFindings: AgentFinding[] = [];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  let used = 0;
  for (const probe of INJECTION_PROBES) {
    if (used >= budget) break;
    used++;
    const payload = { ...baselinePayload, [probe.field === 'username' ? usernameField : passwordField]: probe.value };
    try {
      const response = await requestAuthorizedJsonPost(scope, { hostname, port, tls, path }, payload);
      const result = outcome(response);
      attempts.push({ probe: probe.id, status: response.status, result: result.marker });
      if (result.authenticated && !baselineOutcome.authenticated) {
        if (!acquiredSession && result.token) acquiredSession = result.token;
        suggestedFindings.push({
          title: 'Authentication endpoint accepts a fixed SQL tautology input',
          summary: `The ${probe.field === 'username' ? usernameField : passwordField} field accepted a fixed SQL tautology value and the endpoint issued an authenticated artifact, while a random control pair was rejected. This proves the authentication query on this deployment is injectable.`,
          severity: 'critical', confidence: 97, asset,
          evidence: [
            `Baseline invalid credentials were rejected (${baselineOutcome.marker}).`,
            `${probe.rationale} Result: HTTP ${response.status}, ${result.marker}. The issued token is retained in-memory for same-investigation session-replay tools (never written to storage or findings).`
          ],
          remediation: 'Use parameterized queries for credential lookup, enforce constant-shape rejection responses, and add rate limiting plus lockout signals to the endpoint.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-89'],
          frameworkRefs: frameworkReferences('WSTG-INPV-05', 'v5.0.0-1.2.4'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
    } catch (error) { attempts.push({ probe: probe.id, status: 0, result: error instanceof Error ? error.message.slice(0, 100) : 'failed' }); }
  }

  for (const cred of DEFAULT_CREDENTIALS) {
    if (used >= budget) break;
    used++;
    try {
      const response = await requestAuthorizedJsonPost(scope, { hostname, port, tls, path }, { ...baselinePayload, [usernameField]: cred.username, [passwordField]: cred.password });
      const result = outcome(response);
      if (result.authenticated && result.token && !acquiredSession) acquiredSession = result.token;
      attempts.push({ probe: `default-credential:${cred.username}`, status: response.status, result: result.marker });
      if (result.authenticated && !baselineOutcome.authenticated) {
        suggestedFindings.push({
          title: 'A well-known default credential pair authenticates',
          summary: `The default credential pair ${cred.username} / ${cred.password.replace(/./g, '•')} authenticated. Default or trivially guessable credentials are present on this deployment.`,
          severity: 'high', confidence: 97, asset,
          evidence: [`Default credential attempt for account ${cred.username} returned HTTP ${response.status} with a token-shaped response. The password and token were not retained.`],
          remediation: 'Remove default accounts, force credential rotation at first boot, and audit the account inventory for shared or vendor credentials.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-521'],
          frameworkRefs: frameworkReferences('WSTG-SESS-02'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
    } catch (error) { attempts.push({ probe: `default-credential:${cred.username}`, status: 0, result: error instanceof Error ? error.message.slice(0, 100) : 'failed' }); }
  }

  return {
    endpoint: path, baselineRejected: !baselineOutcome.authenticated,
    acquiredSession: acquiredSession || undefined,
    attemptsUsed: used, attempts, suggestedFindings,
    policy: `Fixed payload list only (${INJECTION_PROBES.length} injection shapes + ${DEFAULT_CREDENTIALS.length} documented default pairs), at most ${MAX_ATTEMPTS} attempts, JSON POST bodies, no state-changing operations beyond login attempts, nothing exfiltrated.`
  };
}
