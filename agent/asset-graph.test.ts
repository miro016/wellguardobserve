import { describe, expect, test } from 'bun:test';
import { buildAssetGraph } from './asset-graph';
import type { AgentAction, AgentFinding, AuthorizedTarget } from './types';

const target: AuthorizedTarget = {
  id: 'target', hostname: 'example.com', authorizedHosts: ['identity.shared-provider.test'], authorizationStatus: 'admin_override'
};

function action(tool: string, input: Record<string, unknown>, output: unknown): AgentAction {
  return { tool, input, summary: JSON.stringify(output), at: '2026-09-04T12:00:00.000Z' };
}

describe('explicit asset graph', () => {
  test('turns every distinct discovered host into a technology-aware service node', () => {
    const findings: AgentFinding[] = [
      {
        title: 'Keycloak administration surface is publicly reachable', summary: 'A direct request reached the observed Keycloak administration surface.', severity: 'low', confidence: 100,
        asset: 'login.example.com', assetKey: 'hostname:login.example.com', relatedAssetKeys: [], relationKey: '', evidence: ['GET /admin returned 200.'], remediation: 'Restrict the administration route.', sourceUrls: [], cveIds: [], weaknessIds: ['CWE-284']
      },
      {
        title: 'Mail posture should be reviewed', summary: 'The root domain does not publish an enforcing DMARC policy.', severity: 'low', confidence: 100,
        asset: 'example.com', assetKey: 'hostname:example.com', relatedAssetKeys: [], relationKey: '', evidence: ['DMARC was observed in monitoring mode.'], remediation: 'Review the intended mail policy.', sourceUrls: [], cveIds: [], weaknessIds: []
      }
    ];
    const graph = buildAssetGraph(target, [action('discover_service_hosts', {}, {
      root: { status: 200, title: 'Easypanel', serviceWords: ['easypanel'], technologies: [{ name: 'Cloudflare' }] },
      serviceHosts: [
        { hostname: 'login.example.com', status: 302, title: '', productHints: ['keycloak'], technologies: [{ name: 'Cloudflare' }], evidence: 'HTTPS GET / returned 302 to /admin/.' },
        { hostname: 'client.example.com', status: 200, title: 'Client', productHints: [], technologies: [{ name: 'Angular' }, { name: 'Cloudflare' }], evidence: 'HTML contained an Angular app-root marker.' },
        { hostname: 'links.example.com', status: 200, title: 'Linkwarden', productHints: ['linkwarden'], technologies: [{ name: 'Next.js' }], evidence: 'HTTPS GET / returned the Linkwarden page.' }
      ]
    })], findings, []);

    expect(graph.assets.find((asset) => asset.key === 'service:login.example.com:443:keycloak')?.label).toBe('Keycloak');
    expect(graph.assets.find((asset) => asset.key === 'service:client.example.com:443:angular')?.details.some((detail) => detail.value.includes('Angular'))).toBeTrue();
    expect(graph.assets.find((asset) => asset.key === 'service:links.example.com:443:linkwarden')?.details.some((detail) => detail.value.includes('Next.js'))).toBeTrue();
    expect(findings[0]?.assetKey).toBe('service:login.example.com:443:keycloak');
    expect(findings[1]?.assetKey).toBe('domain:example.com');
    expect(graph.assets.find((asset) => asset.key === 'domain:example.com')?.state).toBe('warning');
    expect(graph.relations.some((relation) => relation.type === 'within_authorized_root' && relation.toKey === 'hostname:login.example.com')).toBeTrue();
  });

  test('attaches a service disclosure to the relationship and both participating assets', () => {
    const serviceKey = 'service:identity.shared-provider.test:443:keycloak';
    const relatedKey = 'server:203.0.113.42';
    const relationKey = `advertises:${serviceKey}:${relatedKey}`;
    const actions = [action('inspect_service_adapter', { hostname: 'identity.shared-provider.test', port: 443 }, {
      hostname: 'identity.shared-provider.test', product: 'Keycloak', adapter: { id: 'keycloak', version: '1.0.0', name: 'Keycloak public configuration' },
      relations: [{ key: relationKey, fromKey: serviceKey, toKey: relatedKey, type: 'advertises', label: 'advertises endpoint', state: 'warning', confidence: 100, basis: 'observed', evidence: ['OIDC discovery returned https://203.0.113.42/realms/master.'] }]
    })];
    const findings: AgentFinding[] = [{
      title: 'Keycloak advertises a different public origin', summary: 'The OIDC document explicitly returned another origin address.', severity: 'medium', confidence: 100,
      asset: 'identity.shared-provider.test', assetKey: serviceKey, relatedAssetKeys: [relatedKey], relationKey,
      evidence: ['OIDC discovery returned https://203.0.113.42/realms/master.'], remediation: 'Correct the canonical hostname configuration.', sourceUrls: [], cveIds: [], weaknessIds: ['CWE-200']
    }];
    const graph = buildAssetGraph(target, actions, findings, []);
    expect(graph.assets.find((asset) => asset.key === serviceKey)?.state).toBe('warning');
    expect(graph.assets.find((asset) => asset.key === relatedKey)?.label).toBe('203.0.113.42');
    expect(graph.relations.find((relation) => relation.key === relationKey)?.findingTitles).toContain(findings[0]!.title);
  });

  test('retains only directly published identity evidence', () => {
    const actions = [
      action('inspect_wordpress', { hostname: 'blog.example.com', port: 443 }, {
        hostname: 'blog.example.com', evidence: { publicUsers: { url: 'https://blog.example.com/wp-json/wp/v2/users', users: [{ id: 7, name: 'Jane Doe', slug: 'jane', link: 'https://blog.example.com/author/jane/' }] } }
      }),
      action('inspect_public_metadata', { hostname: 'example.com', port: 443 }, {
        hostname: 'example.com', observations: [{ requestedUrl: 'https://example.com/.well-known/security.txt', contacts: ['Contact: mailto:security@example.com'] }]
      })
    ];
    const graph = buildAssetGraph(target, actions, [], []);
    expect(graph.identities.find((identity) => identity.displayName === 'Jane Doe')?.publicLinks).toEqual(['https://blog.example.com/author/jane/']);
    expect(graph.identities.find((identity) => identity.email === 'security@example.com')?.employmentStatus).toBe('not_applicable');
    expect(graph.identities.some((identity) => identity.publicLinks.some((link) => link.includes('linkedin.com')))).toBeFalse();
  });

  test('maps a frontend-discovered backend as a service-to-service API relationship', () => {
    const actions = [
      action('discover_service_hosts', {}, { root: { status: 200, title: 'Portal', serviceWords: [], technologies: [{ name: 'Angular' }] }, serviceHosts: [] }),
      action('inspect_frontend_api', { hostname: 'example.com', port: 443 }, {
        hostname: 'example.com', page: 'https://example.com/',
        backendTechnologies: [{ name: 'PocketBase API', confidence: 100, evidence: 'GET /api/health returned the PocketBase-compatible health document.' }],
        endpoints: [{ value: '/api/files/users/{dynamic}', kind: 'same-origin path', evidence: 'main.js contains this route.' }]
      })
    ];
    const graph = buildAssetGraph(target, actions, [], []);
    const api = graph.assets.find((asset) => asset.label === 'PocketBase API');
    expect(api?.details.some((detail) => detail.label === 'Frontend API references')).toBeTrue();
    expect(graph.relations.some((relation) => relation.type === 'calls_api' && relation.toKey === api?.key)).toBeTrue();
  });

  test('upgrades an unknown web node with a corroboratable recognition hypothesis', () => {
    const actions = [
      action('discover_service_hosts', {}, { root: { hostname: 'example.com', status: 200, title: '', serviceWords: [], technologies: [], evidence: 'A generic page responded.' }, serviceHosts: [] }),
      action('inspect_unknown_web_service', { hostname: 'example.com', port: 443 }, {
        hostname: 'example.com', port: 443, hypotheses: [{ product: 'Metabase', confidence: 92, evidence: 'Favicon MD5 matched a pinned Rapid7 Recog fingerprint.' }],
        favicon: { requestedUrl: 'https://example.com/favicon.ico', bytes: 5430, sha256: 'a'.repeat(64) }
      })
    ];
    const graph = buildAssetGraph(target, actions, [], []);
    const service = graph.assets.find((asset) => asset.kind === 'service' && asset.subtitle === 'example.com');
    expect(service?.label).toBe('Metabase');
    expect(service?.details.some((detail) => detail.label === 'Favicon SHA-256')).toBeTrue();
  });

  test('corrects a model-supplied service key when the finding names another observed port', () => {
    const actions = [
      action('discover_service_hosts', {}, { root: { hostname: 'example.com', status: 200, title: 'App', serviceWords: [], technologies: [{ name: 'Angular' }] }, serviceHosts: [] }),
      action('inspect_service_banner', { hostname: 'example.com', port: 22 }, { hostname: 'example.com', port: 22, protocolHint: 'ssh', note: 'Only a passive banner was retained.', fingerprinting: { matches: [] } })
    ];
    const findings: AgentFinding[] = [{
      title: 'SSH service publicly reachable', summary: 'The passive SSH banner was visible.', severity: 'info', confidence: 100,
      asset: 'example.com:22', assetKey: 'service:example.com:443:angular', relatedAssetKeys: ['service:example.com:443:not-real'], relationKey: 'not-real',
      evidence: ['SSH banner on port 22.'], remediation: 'Review whether SSH must be public.', sourceUrls: [], cveIds: [], weaknessIds: ['CWE-200']
    }];
    const graph = buildAssetGraph(target, actions, findings, []);
    expect(findings[0]?.assetKey).toBe('service:example.com:22:unknown-ssh-service');
    expect(findings[0]?.relatedAssetKeys).toEqual([]);
    expect(findings[0]?.relationKey).toBe('');
    expect(graph.assets.find((asset) => asset.key === findings[0]?.assetKey)?.state).toBe('observed');
  });
});
