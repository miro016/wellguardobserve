import { isIP } from 'node:net';
import type { ScopeGuard } from '../security/scope-guard';
import { extractSignals, requestAuthorizedHttp, type AuthorizedHttpResponse } from '../tools/http';
import type { AdapterFindingSuggestion, AdapterInput, AdapterResult, ServiceAdapter } from './types';
import { frameworkReferences } from '../compliance';

async function observe(scope: ScopeGuard, input: AdapterInput, path: string): Promise<AuthorizedHttpResponse & { error?: string }> {
  try { return await requestAuthorizedHttp(scope, { hostname: input.hostname, port: input.port, tls: input.tls, path }); }
  catch (error) { return { requestedUrl: path, status: 0, headers: {}, raw: '', truncated: false, cookies: [], error: error instanceof Error ? error.message : String(error) }; }
}

function urlHosts(value: unknown): Array<{ url: string; hostname: string }> {
  const matches = JSON.stringify(value).match(/https?:\\?\/\\?\/[^"\\\s]+/gi) || [];
  return [...new Set(matches.map((item) => item.replaceAll('\\/', '/')))].flatMap((url) => {
    try { return [{ url, hostname: new URL(url).hostname.toLowerCase() }]; } catch { return []; }
  }).slice(0, 80);
}

function embeddedJson(raw: string, id: string): Record<string, unknown> {
  const pattern = new RegExp(`<script[^>]+id=["']${id.replace(/[^a-z0-9_-]/gi, '')}["'][^>]*>([\\s\\S]*?)<\\/script>`, 'i');
  try { return JSON.parse(pattern.exec(raw)?.[1]?.trim() || '{}') as Record<string, unknown>; } catch { return {}; }
}

export const keycloakAdapter: ServiceAdapter = {
  manifest: {
    id: 'keycloak', name: 'Keycloak public configuration', version: '1.0.0', products: ['keycloak', 'openid-connect'],
    capabilities: ['product-confirmation', 'oidc-discovery', 'canonical-host-analysis', 'master-realm', 'administration-surface'],
    methods: ['GET'], maxRequests: 4, sourceUrl: 'https://www.keycloak.org/server/hostname'
  },
  async inspect(scope: ScopeGuard, input: AdapterInput): Promise<AdapterResult> {
    const hostname = scope.assertHostname(input.hostname);
    const base = scope.assertPath(input.basePath || '/').replace(/\/$/, '');
    const path = (suffix: string) => `${base}/${suffix.replace(/^\//, '')}`.replace(/\/+/g, '/');
    const [root, realm, discovery, admin] = await Promise.all([
      observe(scope, input, path('/')), observe(scope, input, path('/realms/master')),
      observe(scope, input, path('/realms/master/.well-known/openid-configuration')),
      observe(scope, input, path('/admin/master/console/'))
    ]);
    let document: Record<string, unknown> = {};
    try { document = JSON.parse(discovery.raw) as Record<string, unknown>; } catch { /* Status and bounded samples remain evidence. */ }
    let masterDocument: Record<string, unknown> = {};
    try { masterDocument = JSON.parse(realm.raw) as Record<string, unknown>; } catch { /* Status and markers remain evidence. */ }
    const adminEnvironment = embeddedJson(admin.raw, 'environment');
    const responses = [root, realm, discovery, admin];
    const signalText = responses.map((response) => `${response.raw.slice(0, 20_000)} ${response.headers['location'] || ''}`).join('\n');
    const identified = /\bkeycloak\b|\bkcFormOptions\b|\/resources\/[^\s"']+\/login\//i.test(signalText) || typeof document['issuer'] === 'string';
    const advertised = urlHosts({ document, masterDocument, adminEnvironment, responseLocations: responses.map((response) => response.headers['location'] || '').filter(Boolean) });
    const differentHosts = [...new Set(advertised.map((item) => item.hostname).filter((item) => item !== hostname))];
    const addresses = [...new Set(advertised.map((item) => item.hostname).filter((item) => isIP(item) !== 0))];
    const serviceKey = `service:${hostname}:${input.port || (input.tls === false ? 80 : 443)}:keycloak`;
    const relations = differentHosts.map((other) => {
      const toKey = isIP(other) ? `server:${other}` : `hostname:${other}`;
      const key = `advertises:${serviceKey}:${toKey}`;
      return { key, fromKey: serviceKey, toKey, type: 'advertises', label: 'advertises endpoint', confidence: 100, basis: 'observed' as const,
        evidence: advertised.filter((item) => item.hostname === other).slice(0, 8).map((item) => `OIDC discovery returned ${item.url}.`), state: 'warning' as const };
    });
    const suggestedFindings: AdapterFindingSuggestion[] = [];
    if (identified && differentHosts.length) {
      const relation = relations[0]!;
      suggestedFindings.push({
        title: 'Keycloak advertises a different public host or origin',
        summary: `The public Keycloak discovery document on ${hostname} advertises endpoint URLs on ${differentHosts.join(', ')}. This may be intentional, but it can also disclose a stale origin or incorrect hostname configuration after a migration.`,
        severity: addresses.length ? 'medium' as const : 'low' as const, confidence: 100, asset: hostname, assetKey: serviceKey,
        relatedAssetKeys: relations.map((item) => item.toKey), relationKey: relation.key,
        evidence: relations.flatMap((item) => item.evidence).slice(0, 12),
        remediation: 'Review KC_HOSTNAME, KC_HOSTNAME_ADMIN, proxy headers, realm frontend URLs and backchannel settings. Keep only intentional canonical URLs and remove stale origin references.',
        sourceUrls: [this.manifest.sourceUrl], cveIds: [], weaknessIds: ['CWE-200'], frameworkRefs: frameworkReferences('CRA-I-1', 'CRA-I-2j')
      });
    }
    const adminSignals = extractSignals(admin.raw, admin.headers);
    const adminReachable = identified && admin.status > 0 && admin.status !== 404 && (admin.status < 400 || /keycloak|administration console/i.test(`${adminSignals.title} ${admin.raw.slice(0, 2000)}`));
    if (adminReachable) suggestedFindings.push({
      title: 'Keycloak administration surface is publicly reachable',
      summary: 'An unauthenticated request reached the Keycloak administration-console surface. A login page is not an authentication bypass, but the exposure should be explicitly intended and protected at the reverse proxy when public administration is unnecessary.',
      severity: 'low', confidence: 100, asset: hostname, assetKey: serviceKey, relatedAssetKeys: [], relationKey: '',
      evidence: [`GET ${admin.requestedUrl} returned ${admin.status}${adminSignals.title ? ` with title “${adminSignals.title}”` : ''}.`],
      remediation: 'Restrict administration routes at the reverse proxy or a trusted access layer, keep strong administrator authentication enabled, and use a dedicated KC_HOSTNAME_ADMIN when appropriate.',
      sourceUrls: [this.manifest.sourceUrl], cveIds: [], weaknessIds: ['CWE-284'], frameworkRefs: frameworkReferences('CRA-I-2d', 'CRA-I-2j')
    });
    const masterMetadataReachable = identified && realm.status === 200 && cleanRealm(masterDocument['realm']) === 'master' && discovery.status === 200;
    if (masterMetadataReachable) suggestedFindings.push({
      title: 'Keycloak master realm metadata is publicly reachable',
      summary: 'Anonymous requests returned both the master-realm representation and its OpenID Connect discovery document. These endpoints are commonly public when the realm is enabled, but the master realm is the privileged administration realm and its internet exposure should be an explicit decision.',
      severity: 'low', confidence: 100, asset: hostname, assetKey: serviceKey, relatedAssetKeys: [], relationKey: '',
      evidence: [`GET ${realm.requestedUrl} returned 200 for realm “master”.`, `GET ${discovery.requestedUrl} returned 200 with issuer ${String(document['issuer'] || 'not returned')}.`],
      remediation: 'Confirm that internet-based master-realm administration is required. Otherwise restrict the administration hostname or paths through a trusted access layer and use non-master realms for applications.',
      sourceUrls: [this.manifest.sourceUrl], cveIds: [], weaknessIds: ['CWE-284'], frameworkRefs: frameworkReferences('CRA-I-2d', 'CRA-I-2j')
    });
    return {
      adapter: { id: this.manifest.id, version: this.manifest.version, name: this.manifest.name }, hostname, identified, product: 'Keycloak',
      observations: {
        root: { url: root.requestedUrl, status: root.status, title: extractSignals(root.raw, root.headers).title, location: root.headers['location'] || '', error: root.error || '' },
        masterRealm: { url: realm.requestedUrl, status: realm.status, realm: cleanRealm(masterDocument['realm']), publicKeyPublished: Boolean(masterDocument['public_key']), title: extractSignals(realm.raw, realm.headers).title, location: realm.headers['location'] || '', error: realm.error || '' },
        discovery: { url: discovery.requestedUrl, status: discovery.status, issuer: String(document['issuer'] || ''), advertisedEndpointCount: advertised.length, advertisedHosts: [...new Set(advertised.map((item) => item.hostname))], error: discovery.error || '' },
        administration: { url: admin.requestedUrl, status: admin.status, title: adminSignals.title, location: admin.headers['location'] || '', reachable: adminReachable,
          environment: Object.fromEntries(['serverBaseUrl', 'adminBaseUrl', 'authUrl', 'realm', 'clientId', 'consoleBaseUrl', 'masterRealm', 'resourceVersion'].flatMap((key) => typeof adminEnvironment[key] === 'string' ? [[key, String(adminEnvironment[key]).slice(0, 500)]] : [])), error: admin.error || '' }
      }, relations, suggestedFindings,
      note: 'Only four bounded anonymous GET requests were made. A public OIDC discovery document or login page is not by itself an authentication vulnerability.'
    };
  }
};

function cleanRealm(value: unknown): string { return String(value ?? '').trim().slice(0, 120); }
