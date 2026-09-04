import type { TopologyEdge } from '../models';

export interface TopologyPathHighlight {
  nodeIds: Set<string>;
  edgeIds: Set<string>;
}

export function topologyEdgeId(edge: TopologyEdge): string {
  return edge.id || `${edge.from}→${edge.to}`;
}

export function traceTopologyPath(edges: TopologyEdge[], origin: string): TopologyPathHighlight {
  if (!origin) return { nodeIds: new Set(), edgeIds: new Set() };
  const nodeIds = new Set<string>([origin]);
  const edgeIds = new Set<string>();
  const incoming = new Map<string, TopologyEdge[]>();
  const outgoing = new Map<string, TopologyEdge[]>();
  for (const edge of edges) {
    incoming.set(edge.to, [...(incoming.get(edge.to) || []), edge]);
    outgoing.set(edge.from, [...(outgoing.get(edge.from) || []), edge]);
  }

  walk(origin, incoming, (edge) => edge.from, nodeIds, edgeIds);
  walk(origin, outgoing, (edge) => edge.to, nodeIds, edgeIds);
  return { nodeIds, edgeIds };
}

function walk(origin: string, index: Map<string, TopologyEdge[]>, next: (edge: TopologyEdge) => string, nodeIds: Set<string>, edgeIds: Set<string>): void {
  const visited = new Set<string>([origin]);
  const queue = [origin];
  while (queue.length) {
    const current = queue.shift()!;
    for (const edge of index.get(current) || []) {
      edgeIds.add(topologyEdgeId(edge));
      const node = next(edge);
      nodeIds.add(node);
      if (!visited.has(node)) { visited.add(node); queue.push(node); }
    }
  }
}
