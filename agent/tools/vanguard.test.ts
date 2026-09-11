import { describe, expect, test } from 'bun:test';
import { summarizeVanguardProjection, vanguardEngagement } from './vanguard';

describe('Vanguard integration', () => {
  test('generates a tightly scoped engagement with no paid or out-of-scope grant', () => {
    const yaml = vanguardEngagement('Shop.Example.test.');
    expect(yaml).toContain('roots: ["shop.example.test"]');
    expect(yaml).toContain('max_paid_lookups_per_tool: 0');
    expect(yaml).toContain('allow_out_of_scope_http_requests: false');
    expect(() => vanguardEngagement('https://example.test/path')).toThrow();
  });

  test('compacts deterministic projection data for the agent and retained output', () => {
    const output = summarizeVanguardProjection({ root_target: 'example.test', domains: [{ id: 'd1', type: 'domain', label: 'example.test' }], ip_addresses: [{ id: 'i1', type: 'ip', label: '192.0.2.1' }], services: [{ id: 's1', type: 'service', label: 'https', attributes: { ip: '192.0.2.1', port: 443 } }], web_surfaces: [], edges: [{ type: 'resolves_to', from: 'd1', to: 'i1' }] }, {}, {}, { scan_id: 'scan-1' }, 'succeeded');
    expect(output.counts).toEqual({ domains: 1, servers: 1, services: 1, webSurfaces: 0, edges: 1 });
    expect(output.retainedCounts).toEqual(output.counts);
    expect(output.outputSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  test('does not expose provider-parent or reverse-DNS reference nodes outside the authorized root', () => {
    const output = summarizeVanguardProjection({
      root_target: 'shop.tenant.example',
      domains: [{ id: 'root', label: 'shop.tenant.example' }, { id: 'parent', label: 'tenant.example' }, { id: 'ptr', label: 'host.provider.example' }],
      ip_addresses: [{ id: 'ip', label: '203.0.113.30' }],
      web_surfaces: [{ id: 'web', attributes: { host: 'shop.tenant.example' } }],
      edges: [{ type: 'resolves_to', from: 'root', to: 'ip' }, { type: 'parent', from: 'root', to: 'parent' }, { type: 'reverse_dns', from: 'ip', to: 'ptr' }]
    }, {}, {}, {}, 'succeeded');
    expect(output.domains.map((node) => node['label'])).toEqual(['shop.tenant.example']);
    expect(output.servers.map((node) => node['label'])).toEqual(['203.0.113.30']);
    expect(output.counts.domains).toBe(1);
    expect(output.sourceCounts.domains).toBe(3);
  });

  test('retains valid bounded JSON for large external projections', () => {
    const services = Array.from({ length: 300 }, (_, index) => ({ id: `service-${index}`, attributes: { port: 443, banner: 'x'.repeat(4_000) }, paths: Array.from({ length: 30 }, () => ({ url: `https://example.test/${'x'.repeat(500)}` })) }));
    const output = summarizeVanguardProjection({ services, edges: Array.from({ length: 600 }, (_, index) => ({ type: 'serves', from: `a-${index}`, to: `b-${index}` })) }, {}, {}, {}, 'succeeded');
    expect(Buffer.byteLength(JSON.stringify(output, null, 2))).toBeLessThan(24_000);
    expect(output.truncated).toBeTrue();
    expect(output.counts.services).toBe(300);
  });
});
