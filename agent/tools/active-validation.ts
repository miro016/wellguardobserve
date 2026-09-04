import { createHash } from 'node:crypto';
import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedBytes, requestAuthorizedHttp, type AuthorizedHttpResponse, type CookieMetadata } from './http';

const SYNTHETIC_ORIGIN = 'https://wellguard.invalid';
const CONTROL_VALUE = 'wellguard-control';
const QUOTED_VALUE = "wellguard'probe";
const BURST_CEILING = 10;
const FORWARDING_COMPARISON_CEILING = 3;
const FORWARDING_IDENTITIES = ['198.51.100.10', '198.51.100.20', '198.51.100.30'] as const;

function safeReadPath(scope: ScopeGuard, path = '/'): string {
  const normalized = scope.assertPath(path);
  if (/[?#]/.test(normalized)) throw new Error('Active validation requires a path without an existing query or fragment.');
  if (/(?:^|[\/_-])(?:logout|signout|delete|destroy|remove|create|submit|purchase|checkout|webhook)(?:[\/_-]|$)/i.test(normalized)) {
    throw new Error('The requested path resembles a state-changing operation and is excluded from active validation.');
  }
  return normalized;
}

function databaseErrorFamily(raw: string): string {
  const families: Array<[string, RegExp]> = [
    ['PostgreSQL', /(?:PG::SyntaxError|PostgreSQL[^\n]{0,80}(?:ERROR|syntax)|unterminated quoted string|syntax error at or near ["'])/i],
    ['MySQL', /(?:You have an error in your SQL syntax|SQLSTATE\[42000\]|mysqli?_(?:query|prepare)|PDOException[^\n]{0,80}SQL)/i],
    ['Microsoft SQL Server', /(?:Unclosed quotation mark after|Microsoft OLE DB Provider for SQL Server|System\.Data\.SqlClient|SQL Server[^\n]{0,80}(?:error|exception))/i],
    ['Oracle', /(?:ORA-\d{5}|Oracle error[^\n]{0,80})/i],
    ['SQLite', /(?:SQLITE_ERROR|SQLite(?:3)?::(?:SQLException|Exception)|near ["'][^\n]{0,40}["']:\s*syntax error)/i]
  ];
  return families.find(([, pattern]) => pattern.test(raw))?.[0] || '';
}

function responseObservation(response: AuthorizedHttpResponse) {
  return {
    status: response.status,
    bytesObserved: Buffer.byteLength(response.raw),
    digest: createHash('sha256').update(response.raw).digest('hex').slice(0, 16),
    databaseErrorFamily: databaseErrorFamily(response.raw),
    truncated: response.truncated
  };
}

function buildProbePath(path: string, parameter: string, value: string): string {
  const search = new URLSearchParams([[parameter, value]]);
  return `${path}?${search.toString()}`;
}

export async function inspectInputErrorHandling(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string; parameter?: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = safeReadPath(scope, input.path || '/');
  const parameter = String(input.parameter || 'q');
  if (!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(parameter)) throw new Error('The query parameter name is outside the active-validation policy.');

  const controlBefore = responseObservation(await requestAuthorizedHttp(scope, { hostname, port, tls, path: buildProbePath(path, parameter, CONTROL_VALUE) }));
  const quoted = responseObservation(await requestAuthorizedHttp(scope, { hostname, port, tls, path: buildProbePath(path, parameter, QUOTED_VALUE) }));
  const controlAfter = responseObservation(await requestAuthorizedHttp(scope, { hostname, port, tls, path: buildProbePath(path, parameter, CONTROL_VALUE) }));
  const controlStable = controlBefore.status === controlAfter.status && controlBefore.digest === controlAfter.digest;
  const databaseErrorOnlyOnQuote = Boolean(quoted.databaseErrorFamily && !controlBefore.databaseErrorFamily && !controlAfter.databaseErrorFamily);
  const strongSignal = controlStable && databaseErrorOnlyOnQuote && quoted.status >= 500;
  const differential = quoted.status !== controlBefore.status || quoted.digest !== controlBefore.digest;
  const suggestedFindings: AgentFinding[] = [];

  if (strongSignal) suggestedFindings.push({
    title: 'Quoted input triggers a database error response',
    summary: `A fixed quoted value sent to the ${parameter} query parameter produced a ${quoted.databaseErrorFamily} error marker and HTTP ${quoted.status}, while two identical control requests were stable. This proves an input-handling and database-error disclosure condition; it does not prove that SQL can be executed or data can be accessed.`,
    severity: 'medium', confidence: 99, asset: `${hostname}:${port}${path}`,
    evidence: [
      `Two control GETs returned the same status and body digest (${controlBefore.status}; ${controlBefore.digest}).`,
      `The quoted-input GET returned HTTP ${quoted.status} with a strict ${quoted.databaseErrorFamily} error-family marker.`,
      'No SQL keyword, operator, comment, timing function, stacked statement, data extraction, authentication, or state-changing method was sent.'
    ],
    remediation: 'Use parameterized database queries, validate input by expected type, return generic client errors, and keep database exception details out of public responses. Confirm the root cause with an authorized code review or isolated test environment.',
    sourceUrls: [], cveIds: [], weaknessIds: ['CWE-209'],
    frameworkRefs: frameworkReferences('WSTG-INPV-05', 'v5.0.0-1.2.4', 'CRA-I-1', 'CRA-II-3'),
    assetKey: `service:${hostname}:${port}:web`, relatedAssetKeys: [`hostname:${hostname}`, `port:${hostname}:${port}`], relationKey: ''
  });

  return {
    hostname, port, transport: tls ? 'https' : 'http', path, parameter,
    observations: { controlBefore, quoted, controlAfter },
    result: strongSignal ? 'database-error-disclosure-observed' : !controlStable ? 'control-response-unstable' : differential ? 'response-differential-only' : 'no-observable-differential',
    sqlInjectionConfirmed: false,
    suggestedFindings,
    policy: {
      version: 'quoted-input-differential-v1', requests: 3, concurrency: 1, method: 'GET',
      fixedInputs: ['neutral control', 'single quote embedded in inert text', 'neutral control repeat'],
      excluded: ['SQL keywords', 'boolean operators', 'comments', 'semicolons', 'time delays', 'stacked statements', 'data extraction', 'authentication', 'cookies', 'state-changing methods']
    },
    note: 'A changing control response makes body differences inconclusive. Any differential without a strict database error is an observation only, and no result from this tool alone establishes exploitable SQL injection.'
  };
}

function uniqueCookies(cookies: CookieMetadata[]): CookieMetadata[] {
  const seen = new Set<string>();
  return cookies.filter((cookie) => {
    const key = `${cookie.name}|${cookie.secure}|${cookie.httpOnly}|${cookie.sameSite}|${cookie.path}|${cookie.domainScoped}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}

export async function inspectBrowserSessionControls(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = safeReadPath(scope, input.path || '/');
  const baseline = await requestAuthorizedHttp(scope, { hostname, port, tls, path });
  const originProbe = await requestAuthorizedHttp(scope, { hostname, port, tls, path }, { fixedHeaders: { origin: SYNTHETIC_ORIGIN } });
  const cookies = uniqueCookies([...baseline.cookies, ...originProbe.cookies]);
  const sensitive = cookies.filter((cookie) => cookie.likelySensitive);
  const missingSecure = tls ? sensitive.filter((cookie) => !cookie.secure) : [];
  const missingHttpOnly = sensitive.filter((cookie) => !cookie.httpOnly);
  const missingSameSite = sensitive.filter((cookie) => cookie.sameSite === 'unset');
  const suggestedFindings: AgentFinding[] = [];

  if (missingSecure.length || missingHttpOnly.length || missingSameSite.length) {
    const weaknessIds = [...new Set([
      ...(missingSecure.length ? ['CWE-614'] : []),
      ...(missingHttpOnly.length ? ['CWE-1004'] : []),
      ...(missingSameSite.length ? ['CWE-1275'] : [])
    ])];
    const referenceIds: Array<'WSTG-SESS-02' | 'v5.0.0-3.3.1' | 'v5.0.0-3.3.2' | 'v5.0.0-3.3.4' | 'CRA-I-1'> = ['WSTG-SESS-02', 'CRA-I-1'];
    if (missingSecure.length) referenceIds.push('v5.0.0-3.3.1');
    if (missingSameSite.length) referenceIds.push('v5.0.0-3.3.2');
    if (missingHttpOnly.length) referenceIds.push('v5.0.0-3.3.4');
    suggestedFindings.push({
      title: 'Session-like cookies need attribute review',
      summary: `${sensitive.length} cookie${sensitive.length === 1 ? '' : 's'} with a session or authentication-like name were observed. ${missingSecure.length} lacked Secure, ${missingHttpOnly.length} lacked HttpOnly, and ${missingSameSite.length} lacked an explicit SameSite value. Cookie names are heuristic evidence; confirm each cookie's purpose before changing it.`,
      severity: missingSecure.length || missingHttpOnly.length ? 'medium' : 'low', confidence: 95, asset: `${hostname}:${port}${path}`,
      evidence: sensitive.slice(0, 12).map((cookie) => `${cookie.name}: Secure=${cookie.secure}, HttpOnly=${cookie.httpOnly}, SameSite=${cookie.sameSite}, Domain scoped=${cookie.domainScoped}.`),
      remediation: 'Classify each cookie by purpose. Protect authentication and session cookies with Secure and HttpOnly, choose an explicit SameSite mode appropriate to the flow, minimize Domain and Path scope, and prefer __Host- cookies where cross-host sharing is unnecessary.',
      sourceUrls: [], cveIds: [], weaknessIds, frameworkRefs: frameworkReferences(...referenceIds),
      assetKey: `service:${hostname}:${port}:web`, relatedAssetKeys: [`hostname:${hostname}`, `port:${hostname}:${port}`], relationKey: ''
    });
  }

  const allowOrigin = originProbe.headers['access-control-allow-origin'] || '';
  const allowCredentials = /^true$/i.test(originProbe.headers['access-control-allow-credentials'] || '');
  const reflectedCredentialedOrigin = allowOrigin === SYNTHETIC_ORIGIN && allowCredentials;
  if (reflectedCredentialedOrigin) suggestedFindings.push({
    title: 'Credentialed CORS reflects an arbitrary origin',
    summary: `A GET carrying the fixed synthetic Origin ${SYNTHETIC_ORIGIN} was answered with that exact Access-Control-Allow-Origin value and Access-Control-Allow-Credentials: true. No credentials were sent, so the sensitivity of readable authenticated responses still requires confirmation.`,
    severity: 'medium', confidence: 99, asset: `${hostname}:${port}${path}`,
    evidence: [`Origin: ${SYNTHETIC_ORIGIN} produced Access-Control-Allow-Origin: ${allowOrigin}.`, 'The same response returned Access-Control-Allow-Credentials: true.', 'The request contained no Cookie or Authorization header.'],
    remediation: 'Validate Origin against an explicit allowlist, return credential support only for trusted origins that require it, and test sensitive authenticated responses from an untrusted browser origin in an isolated authorized environment.',
    sourceUrls: [], cveIds: [], weaknessIds: ['CWE-942'], frameworkRefs: frameworkReferences('WSTG-CLNT-07', 'v5.0.0-3.4.2', 'CRA-I-2d'),
    assetKey: `service:${hostname}:${port}:web`, relatedAssetKeys: [`hostname:${hostname}`, `port:${hostname}:${port}`], relationKey: ''
  });

  return {
    hostname, port, transport: tls ? 'https' : 'http', path,
    baseline: { status: baseline.status },
    cookies,
    cors: { syntheticOrigin: SYNTHETIC_ORIGIN, status: originProbe.status, allowOrigin, allowCredentials, reflectedCredentialedOrigin },
    suggestedFindings,
    policy: { version: 'browser-session-controls-v1', requests: 2, concurrency: 1, method: 'GET', credentialsSent: false, cookieValuesRetained: false, cookiesReplayed: false },
    note: 'This checks observable cookie attributes and one fixed CORS origin. It does not authenticate, establish a session, test session fixation, or prove the sensitivity of a response.'
  };
}

function selectedRateHeaders(headers: Record<string, string>) {
  const names = ['retry-after', 'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'];
  return Object.fromEntries(names.flatMap((name) => headers[name] ? [[name, headers[name]]] : []));
}

export async function inspectRateLimitControls(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = safeReadPath(scope, input.path || '/');
  const burst: Array<{ sequence: number; status: number; elapsedMs: number; rateHeaders: Record<string, string> }> = [];
  for (let sequence = 1; sequence <= BURST_CEILING; sequence += 1) {
    const started = performance.now();
    const response = await requestAuthorizedBytes(scope, { hostname, port, tls, path, maxBodyBytes: 1 }, { timeoutMs: 5_000 });
    burst.push({ sequence, status: response.status, elapsedMs: Math.round(performance.now() - started), rateHeaders: selectedRateHeaders(response.headers) });
    if (response.status === 429) break;
  }
  const limitedAt = burst.find((item) => item.status === 429)?.sequence || 0;
  const forwardingComparison: Array<{ identity: string; status: number; rateHeaders: Record<string, string> }> = [];
  if (limitedAt) {
    for (const identity of FORWARDING_IDENTITIES.slice(0, FORWARDING_COMPARISON_CEILING)) {
      const response = await requestAuthorizedBytes(scope, { hostname, port, tls, path, maxBodyBytes: 1 }, { fixedHeaders: { 'x-forwarded-for': identity }, timeoutMs: 5_000 });
      forwardingComparison.push({ identity, status: response.status, rateHeaders: selectedRateHeaders(response.headers) });
    }
  }
  const acceptedVariants = forwardingComparison.filter((item) => item.status >= 200 && item.status < 400);
  const headerTrustSignal = limitedAt > 0 && acceptedVariants.length >= 2;
  const suggestedFindings: AgentFinding[] = [];
  if (headerTrustSignal) suggestedFindings.push({
    title: 'Client-supplied forwarding header appears to reset throttling',
    summary: `The endpoint returned HTTP 429 during a ${limitedAt}-request anonymous GET burst, then accepted ${acceptedVariants.length} of ${forwardingComparison.length} requests when only X-Forwarded-For changed to reserved documentation addresses. This is a bounded header-trust signal, not a capacity or denial-of-service test.`,
    severity: 'medium', confidence: 95, asset: `${hostname}:${port}${path}`,
    evidence: [`The original request identity reached HTTP 429 at request ${limitedAt}.`, ...forwardingComparison.map((item) => `X-Forwarded-For ${item.identity} returned HTTP ${item.status}.`), 'No Cookie, Authorization, request body, concurrency, IP rotation, or repeated evasion was used.'],
    remediation: 'At the trusted edge, replace client-provided forwarding headers and derive the original client address only from known proxies. Key throttling to a risk-appropriate combination of trusted network identity, account, session, endpoint, and device signals.',
    sourceUrls: [], cveIds: [], weaknessIds: [], frameworkRefs: frameworkReferences('v5.0.0-2.4.1', 'v5.0.0-15.3.4', 'CRA-I-2h', 'CRA-II-3'),
    assetKey: `service:${hostname}:${port}:web`, relatedAssetKeys: [`hostname:${hostname}`, `port:${hostname}:${port}`], relationKey: ''
  });

  return {
    hostname, port, transport: tls ? 'https' : 'http', path, burst, limitedAt, forwardingComparison, headerTrustSignal, suggestedFindings,
    result: headerTrustSignal ? 'forwarding-header-trust-signal' : limitedAt ? 'throttling-observed-no-bypass-signal' : 'no-throttling-observed-under-small-burst',
    policy: {
      version: 'bounded-rate-controls-v1', maximumRequests: BURST_CEILING + FORWARDING_COMPARISON_CEILING, concurrency: 1, method: 'GET',
      forwardingComparisonOnlyAfter429: true, forwardingAddresses: 'RFC 5737 documentation range',
      excluded: ['request bodies', 'credentials', 'cookies', 'authorization headers', 'concurrency', 'proxy rotation', 'continued bypass attempts', 'load or denial-of-service testing']
    },
    note: 'No HTTP 429 in ten anonymous GETs does not prove missing rate limiting or a security defect. Controls may be endpoint-, identity-, cost-, account-, or time-window-specific.'
  };
}
