import { describe, expect, test } from 'bun:test';
import { TopologyService } from '../src/app/services/topology.service';
import type { AssetRecord, AssetRelationRecord, Target } from '../src/app/models';

const target: Target = { id: 'target', workspace: 'workspace', name: 'Example', hostname: 'example.test', hostHints: [], authorizedHosts: [], authorizationStatus: 'admin_override', status: 'observed', lastScanAt: '', assetCount: 0, findingCount: 0, posture: 100, criticality: 'standard', tags: [] };
const asset = (key: string, kind: AssetRecord['kind'], label: string, subtitle = ''): AssetRecord => ({ id: key, target: 'target', scan: 'scan', key, kind, label, subtitle, state: 'observed', confidence: 100, basis: 'observed', details: [] });
const relation = (key: string, fromKey: string, toKey: string, type: string): AssetRelationRecord => ({ id: key, target: 'target', scan: 'scan', key, fromKey, toKey, type, label: type.replace(/_/g, ' '), state: 'observed', confidence: 100, basis: 'observed', evidence: [], findingTitles: [] });

describe('explicit topology normalization', () => {
  test('merges hostname-specific aliases into one machine port and derives URL assets', () => {
    const assets = [
      asset('domain:example.test', 'domain', 'example.test'),
      asset('hostname:admin.example.test', 'hostname', 'admin.example.test'),
      asset('server:203.0.113.8', 'server', '203.0.113.8'),
      asset('port:example.test:443', 'port', ':443', 'example.test'),
      asset('port:admin.example.test:443', 'port', ':443', 'admin.example.test'),
      asset('service:example.test:443:angular', 'service', 'Angular', 'example.test'),
      asset('service:admin.example.test:443:keycloak', 'service', 'Keycloak', 'admin.example.test')
    ];
    const relations = [
      relation('resolve-root', 'domain:example.test', 'server:203.0.113.8', 'resolves_to'),
      relation('resolve-admin', 'hostname:admin.example.test', 'server:203.0.113.8', 'resolves_to'),
      relation('expose-root', 'server:203.0.113.8', 'port:example.test:443', 'exposes_port'),
      relation('expose-admin', 'server:203.0.113.8', 'port:admin.example.test:443', 'exposes_port'),
      relation('run-root', 'port:example.test:443', 'service:example.test:443:angular', 'runs_service'),
      relation('run-admin', 'port:admin.example.test:443', 'service:admin.example.test:443:keycloak', 'runs_service')
    ];
    const topology = new TopologyService().build(target, [], null, [], assets, relations);
    expect(topology.nodes.filter((node) => node.kind === 'port').map((node) => node.id)).toEqual(['port:203.0.113.8:443']);
    expect(topology.nodes.filter((node) => node.kind === 'url').map((node) => node.label).sort()).toEqual(['https://admin.example.test', 'https://example.test']);
    expect(topology.edges.filter((edge) => edge.from === 'port:203.0.113.8:443' && edge.type === 'runs_service')).toHaveLength(2);
    expect(topology.edges.some((edge) => edge.from === 'url:https:admin.example.test:443' && edge.to === 'server:203.0.113.8')).toBeTrue();
  });
});
