import { describe, expect, test } from 'bun:test';
import { projectArchitectureTree } from '../src/app/services/architecture-projection';
import type { Topology } from '../src/app/services/topology.service';
import type { NodeKind, TopologyEdge, TopologyNode } from '../src/app/models';

const evidenceDetail = { label: 'Evidence', value: 'Observed', evidence: 'Direct.', confidence: 100, basis: 'observed' as const };
const node = (id: string, kind: NodeKind, label: string): TopologyNode => ({ id, kind, label, subtitle: '', state: 'observed', x: 0, y: 0, details: [evidenceDetail], findingIds: [] });
const edge = (id: string, from: string, to: string, type: string): TopologyEdge => ({ id, from, to, type, label: type, state: 'observed', confidence: 100, basis: 'observed', evidence: ['Direct.'], findingIds: [] });

describe('architecture surface projection', () => {
  test('renders target to server to port to domain to service', () => {
    const detail = evidenceDetail;
    const topology: Topology = {
      nodes: [
        { id: 'domain:example.test', kind: 'domain', label: 'example.test', subtitle: 'Authorized root', state: 'observed', x: 0, y: 0, details: [detail], findingIds: [] },
        { id: 'server:192.0.2.1', kind: 'server', label: '192.0.2.1', subtitle: 'Observed address', state: 'observed', x: 0, y: 0, details: [detail], findingIds: [] },
        { id: 'port:192.0.2.1:443', kind: 'port', label: ':443', subtitle: '192.0.2.1', state: 'observed', x: 0, y: 0, details: [detail], findingIds: [] },
        { id: 'service:shop.example.test:443:store', kind: 'service', label: 'Store', subtitle: 'shop.example.test', state: 'warning', x: 0, y: 0, details: [detail], findingIds: ['f1'] }
      ],
      edges: [
        { from: 'domain:example.test', to: 'server:192.0.2.1', type: 'resolves_to' },
        { from: 'server:192.0.2.1', to: 'port:192.0.2.1:443', type: 'exposes_port' },
        { from: 'port:192.0.2.1:443', to: 'service:shop.example.test:443:store', type: 'runs_service' }
      ]
    };
    const projected = projectArchitectureTree(topology);
    const domain = projected.nodes.find((node) => node.id.startsWith('architecture-domain:'))!;
    expect(domain.label).toBe('shop.example.test');
    expect(domain.state).toBe('warning');
    expect(projected.edges.map((edge) => `${edge.from}>${edge.to}`)).toContain(`port:192.0.2.1:443>${domain.id}`);
    expect(projected.edges.map((edge) => `${edge.from}>${edge.to}`)).toContain(`${domain.id}>service:shop.example.test:443:store`);
  });

  test('keeps portfolio servers attached to their own target host', () => {
    const topology: Topology = {
      nodes: [
        node('domain:a.example', 'domain', 'a.example'), node('domain:b.example', 'domain', 'b.example'),
        node('hostname:a.example', 'hostname', 'a.example'), node('hostname:b.example', 'hostname', 'b.example'),
        node('server:192.0.2.10', 'server', '192.0.2.10'), node('server:192.0.2.20', 'server', '192.0.2.20')
      ],
      edges: [
        edge('a-host', 'domain:a.example', 'hostname:a.example', 'contains'), edge('a-server', 'hostname:a.example', 'server:192.0.2.10', 'resolves_to'),
        edge('b-host', 'domain:b.example', 'hostname:b.example', 'contains'), edge('b-server', 'hostname:b.example', 'server:192.0.2.20', 'resolves_to')
      ]
    };
    const projected = projectArchitectureTree(topology);
    expect(projected.edges.some((item) => item.from === 'domain:a.example' && item.to === 'server:192.0.2.10')).toBeTrue();
    expect(projected.edges.some((item) => item.from === 'domain:b.example' && item.to === 'server:192.0.2.20')).toBeTrue();
    expect(projected.edges.some((item) => item.from === 'domain:a.example' && item.to === 'server:192.0.2.20')).toBeFalse();
  });
});
