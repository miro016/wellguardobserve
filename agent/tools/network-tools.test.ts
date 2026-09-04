import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createServer, type Server } from 'node:http';
import { ScopeGuard } from '../security/scope-guard';
import { extractSignals, inspectHttp } from './http';
import { cookieMetadata } from './http';
import { discoverPorts } from './ports';
import { classifyServiceObservation } from './service-hosts';
import { assessHttpConfiguration } from './configuration';
import { inspectWordPress, normalizeWordPressUsers } from './wordpress';
import { summarizeRdap } from './domain';
import { inspectWithAdapter } from '../adapters/registry';
import { analyzeFrontendBundles } from './frontend-api';
import { evaluateSafeTemplate, SAFE_WEB_TEMPLATES } from './safe-audit';
import type { AuthorizedHttpResponse } from './http';
import { inspectBrowserSessionControls, inspectInputErrorHandling, inspectRateLimitControls } from './active-validation';

let server: Server;
let port: number;
let rateRequests = 0;
let dynamicRequests = 0;
const scope = new ScopeGuard({ id: 'local-test', hostname: '127.0.0.1', authorizationStatus: 'admin_override', allowPrivateAddresses: true });

beforeAll(async () => {
  server = createServer((request, response) => {
    response.setHeader('server', 'Example-Control/2.0');
    response.setHeader('x-powered-by', 'Bun');
    if (request.url?.startsWith('/active/cookies')) {
      response.setHeader('set-cookie', 'session_id=secret-value-never-returned; Path=/; SameSite=None');
      if (request.headers.origin) {
        response.setHeader('access-control-allow-origin', request.headers.origin);
        response.setHeader('access-control-allow-credentials', 'true');
      }
      response.end('browser controls'); return;
    }
    if (request.url?.startsWith('/active/input')) {
      if (request.url.includes('%27')) { response.statusCode = 500; response.end('PostgreSQL ERROR: unterminated quoted string'); }
      else response.end('stable control');
      return;
    }
    if (request.url?.startsWith('/active/dynamic')) { dynamicRequests += 1; response.end(`dynamic ${dynamicRequests}`); return; }
    if (request.url === '/active/rate') {
      if (request.headers['x-forwarded-for']) { response.end('accepted alternate identity'); return; }
      rateRequests += 1;
      if (rateRequests >= 4) { response.statusCode = 429; response.setHeader('retry-after', '30'); response.end('slow down'); return; }
      response.end('ok'); return;
    }
    if (request.url?.includes('/realms/master/.well-known/openid-configuration')) {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ issuer: 'https://stale-origin.example.test/realms/master', authorization_endpoint: 'https://stale-origin.example.test/realms/master/protocol/openid-connect/auth' })); return;
    }
    if (request.url?.includes('/realms/master')) { response.end('{"realm":"master","public_key":"example"}'); return; }
    if (request.url?.includes('/admin/master/console')) { response.end('<title>Keycloak Administration Console</title><script>window.kcFormOptions={}</script>'); return; }
    if (request.url?.startsWith('/wp-json/wp/v2/users')) {
      response.setHeader('content-type', 'application/json'); response.setHeader('x-wp-total', '1');
      response.end(JSON.stringify([{ id: 1, name: 'owner@example.test', slug: 'ownerexample-test', link: 'https://example.test/author/owner/' }])); return;
    }
    if (request.url === '/wp-json/') { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ namespaces: ['wp/v2'], routes: { '/wp/v2/users': {} } })); return; }
    if (request.url === '/wp-login.php') { response.end('<title>Log In ‹ Example — WordPress</title>'); return; }
    if (request.url === '/readme.html') { response.end('<h1>WordPress</h1><br> Version 6.8.2'); return; }
    if (request.url === '/xmlrpc.php') { response.statusCode = 405; response.setHeader('allow', 'POST'); response.end('XML-RPC server accepts POST requests only.'); return; }
    response.end('<html><head><title>Easypanel</title></head><body>Control at https://panel.example.test and origin 203.0.113.42.</body></html>');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Test server did not bind.');
  port = address.port;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

describe('bounded network tools', () => {
  test('extracts generic identity and disclosure signals from HTTP', async () => {
    const result = await inspectHttp(scope, { hostname: '127.0.0.1', port, tls: false, path: '/' });
    expect(result['status']).toBe(200);
    const signals = result['signals'] as { title: string; serviceWords: string[]; ipv4: string[]; urls: string[] };
    expect(signals.title).toBe('Easypanel');
    expect(signals.serviceWords).toContain('easypanel');
    expect(signals.ipv4).toContain('203.0.113.42');
    expect(signals.urls).toContain('https://panel.example.test');
  });

  test('finds only the explicitly requested local port', async () => {
    const result = await discoverPorts(scope, { ports: [port] });
    expect(result.openPorts).toEqual([port]);
    expect(result.portsTested).toBe(1);
  });

  test('separates a real redirected service from wildcard missing routes', () => {
    const root = { hostname: 'example.com', status: 200, title: 'Easypanel', location: '', server: 'cloudflare', contentType: 'text/html', textSample: 'Easypanel', serviceWords: ['easypanel'], technologies: [] };
    const missing = { ...root, hostname: 'keycloak.example.com', status: 404, title: 'Not Found', textSample: 'The application keycloak was not found on Easypanel.' };
    const service = { ...root, hostname: 'keycloak1.example.com', status: 302, title: '', location: 'https://project-keycloak.provider.test/admin/', textSample: '', serviceWords: [] };
    expect(classifyServiceObservation(missing, root)).toBeNull();
    expect(classifyServiceObservation(service, root)?.productHints).toContain('keycloak');
  });

  test('retains direct framework fingerprints with their evidence', () => {
    const signals = extractSignals('<html><head><script id="__NEXT_DATA__">{}</script><script src="/_next/static/app.js"></script></head></html>', { server: 'nginx/1.26.0' });
    expect(signals.technologies.map((item) => item.name)).toContain('Next.js');
    expect(signals.technologies.map((item) => item.name)).toContain('nginx/1.26.0');
    expect(signals.assets).toContain('/_next/static/app.js');
  });

  test('does not identify a product from the candidate hostname alone', () => {
    const candidate = { hostname: 'easypanel.example.com', status: 200, title: 'Company portal', location: '', server: 'cloudflare', contentType: 'text/html', textSample: 'Welcome', serviceWords: [], technologies: [] };
    expect(classifyServiceObservation(candidate)?.productHints).not.toContain('easypanel');
  });

  test('retains framework evidence from one same-host redirect destination', () => {
    const candidate = { hostname: 'app.example.com', initialStatus: 302, status: 200, title: 'Base', location: '/en/', server: 'cloudflare', contentType: 'text/html', textSample: 'Base', serviceWords: [], technologies: [{ name: 'Angular', evidence: 'HTML contains app-root.' }] };
    const result = classifyServiceObservation(candidate);
    expect(result?.technologies[0]?.name).toBe('Angular');
    expect(result?.evidence).toContain('same-host redirect returned 200');
  });

  test('classifies missing HTTP protections as review evidence with CWE mappings', () => {
    const checks = assessHttpConfiguration({ server: 'nginx/1.20.1' }, true);
    expect(checks.find((check) => check.control === 'Framing protection')?.cweIds).toContain('CWE-1021');
    expect(checks.find((check) => check.control === 'Server identity disclosure')?.state).toBe('exposed');
  });

  test('inspects WordPress public metadata without authenticated fields', async () => {
    const result = await inspectWordPress(scope, { hostname: '127.0.0.1', port, tls: false });
    expect(result.publicUserCount).toBe(1);
    expect(result.emailLikePublicNames[0]?.name).toBe('owner@example.test');
    expect(result.evidence.login.status).toBe(200);
    expect(result.version).toBe('6.8.2');
  });

  test('uses the versioned Keycloak adapter to attribute a cross-asset disclosure', async () => {
    const result = await inspectWithAdapter(scope, 'keycloak', { hostname: '127.0.0.1', port, tls: false });
    expect(result.identified).toBeTrue();
    expect(result.relations[0]?.toKey).toBe('hostname:stale-origin.example.test');
    expect(result.suggestedFindings.some((finding) => finding.relationKey === result.relations[0]?.key)).toBeTrue();
    expect(result.suggestedFindings.some((finding) => /administration surface/i.test(finding.title))).toBeTrue();
  });

  test('normalizes only bounded public WordPress user fields', () => {
    const users = normalizeWordPressUsers([{ id: 1, name: 'Owner', slug: 'owner', roles: ['administrator'], email: 'private@example.test' }]);
    expect(users[0]).toEqual({ id: 1, name: 'Owner', slug: 'owner', link: '', description: '', url: '' });
    expect(users[0]).not.toHaveProperty('roles');
    expect(users[0]).not.toHaveProperty('email');
  });

  test('preserves RDAP redaction while extracting explicitly public registration evidence', () => {
    const result = summarizeRdap({
      ldhName: 'example.test', status: ['active'], events: [{ eventAction: 'registration', eventDate: '2024-01-01T00:00:00Z' }],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar'], ['email', {}, 'text', 'abuse@example.test']]] }],
      nameservers: [{ ldhName: 'ns1.example.test' }], secureDNS: { delegationSigned: true, dsData: [{}] }
    }, 'https://rdap.example.test/domain/example.test');
    expect(result.registrar?.names).toContain('Example Registrar');
    expect(result.publicEmails).toContain('abuse@example.test');
    expect(result.dnssec.delegationSigned).toBe(true);
  });

  test('discovers backend client markers without invoking shipped business routes', () => {
    const analysis = analyzeFrontendBundles([
      { url: 'https://app.example.test/vendor.js', raw: `// node_modules/pocketbase/dist/pocketbase.es.mjs\nconst internal='/api/settings';` },
      { url: 'https://app.example.test/profile.js', raw: `const avatar='/api/files/users/{{id}}/avatar'; const docs='/api/forms/AbstractControl';` }
    ]);
    expect(analysis.backendTechnologies[0]?.name).toBe('PocketBase client/API');
    expect(analysis.endpoints.some((item) => item.value.startsWith('/api/files/users/'))).toBeTrue();
    expect(analysis.endpoints.some((item) => item.value.includes('/api/forms/'))).toBeFalse();
    expect(analysis.endpoints.some((item) => item.value === '/api/settings')).toBeFalse();
  });

  test('safe web templates require strict signatures and reject an SPA fallback', () => {
    const template = SAFE_WEB_TEMPLATES.find((item) => item.id === 'exposed-git-head')!;
    const response = (raw: string, contentType: string): AuthorizedHttpResponse => ({ requestedUrl: 'https://app.example.test/.git/HEAD', status: 200, headers: { 'content-type': contentType }, raw, truncated: false, cookies: [] });
    expect(evaluateSafeTemplate(template, response('ref: refs/heads/main\n', 'text/plain'))).toBeTrue();
    expect(evaluateSafeTemplate(template, response('<html><app-root></app-root></html>', 'text/html'))).toBeFalse();
  });

  test('retains cookie attributes without retaining cookie values', () => {
    const result = cookieMetadata({ 'set-cookie': ['session_id=top-secret; Secure; HttpOnly; SameSite=Lax; Path=/'] });
    expect(result).toEqual([{ name: 'session_id', secure: true, httpOnly: true, sameSite: 'Lax', path: '/', domainScoped: false, persistent: false, prefix: 'none', likelySensitive: true }]);
    expect(JSON.stringify(result)).not.toContain('top-secret');
  });

  test('records strict cookie and credentialed CORS evidence without credentials', async () => {
    const result = await inspectBrowserSessionControls(scope, { hostname: '127.0.0.1', port, tls: false, path: '/active/cookies' });
    expect(result.cookies[0]?.name).toBe('session_id');
    expect(result.cors.reflectedCredentialedOrigin).toBeTrue();
    expect(result.suggestedFindings.some((finding) => finding.weaknessIds.includes('CWE-942'))).toBeTrue();
    expect(JSON.stringify(result)).not.toContain('secret-value-never-returned');
  });

  test('uses a fixed quote differential but never claims SQL injection', async () => {
    const result = await inspectInputErrorHandling(scope, { hostname: '127.0.0.1', port, tls: false, path: '/active/input', parameter: 'q' });
    expect(result.result).toBe('database-error-disclosure-observed');
    expect(result.sqlInjectionConfirmed).toBeFalse();
    expect(result.suggestedFindings[0]?.weaknessIds).toContain('CWE-209');
    expect(JSON.stringify(result.policy.excluded)).toContain('SQL keywords');
  });

  test('labels dynamic controls inconclusive before considering a body differential', async () => {
    dynamicRequests = 0;
    const result = await inspectInputErrorHandling(scope, { hostname: '127.0.0.1', port, tls: false, path: '/active/dynamic', parameter: 'q' });
    expect(result.result).toBe('control-response-unstable');
    expect(result.suggestedFindings).toHaveLength(0);
  });

  test('stops a bounded rate test and only then compares reserved forwarding identities', async () => {
    rateRequests = 0;
    const result = await inspectRateLimitControls(scope, { hostname: '127.0.0.1', port, tls: false, path: '/active/rate' });
    expect(result.limitedAt).toBe(4);
    expect(result.burst).toHaveLength(4);
    expect(result.forwardingComparison).toHaveLength(3);
    expect(result.headerTrustSignal).toBeTrue();
    expect(result.policy.maximumRequests).toBe(13);
  });
});
