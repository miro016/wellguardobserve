import { describe, expect, test } from 'bun:test';
import { traceTopologyPath } from '../src/app/services/topology-path';
import type { TopologyEdge } from '../src/app/models';

describe('surface path highlighting', () => {
  test('traces every ancestor and descendant without lighting sibling branches', () => {
    const edges: TopologyEdge[] = [
      { id: 'root-host-a', from: 'root', to: 'host-a' },
      { id: 'root-host-b', from: 'root', to: 'host-b' },
      { id: 'host-edge', from: 'host-a', to: 'edge' },
      { id: 'edge-server', from: 'edge', to: 'server' },
      { id: 'server-port', from: 'server', to: 'port' },
      { id: 'port-service', from: 'port', to: 'service' }
    ];
    const path = traceTopologyPath(edges, 'server');
    expect([...path.nodeIds]).toEqual(expect.arrayContaining(['root', 'host-a', 'edge', 'server', 'port', 'service']));
    expect(path.nodeIds.has('host-b')).toBeFalse();
    expect(path.edgeIds.has('root-host-a')).toBeTrue();
    expect(path.edgeIds.has('port-service')).toBeTrue();
    expect(path.edgeIds.has('root-host-b')).toBeFalse();
  });
});
