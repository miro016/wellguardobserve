import { NodeState, TopologyEdge, TopologyNode } from '../models';
import type { Topology } from './topology.service';

const severityRank: Record<NodeState, number> = { observed: 0, healthy: 1, unknown: 2, warning: 3, risk: 4 };

function endpoint(service: TopologyNode): { hostname: string; port: number } {
  const match = service.id.match(/^service:(.+):(\d+):[^:]+$/);
  if (match) return { hostname: match[1]!, port: Number(match[2]) };
  const subtitle = service.subtitle.split(' · ')[0] || '';
  const portMatch = subtitle.match(/:(\d+)$/);
  return { hostname: subtitle.replace(/:\d+$/, ''), port: Number(portMatch?.[1] || 443) };
}

function strongest(left: NodeState, right: NodeState): NodeState {
  return severityRank[right] > severityRank[left] ? right : left;
}

export function projectArchitectureTree(topology: Topology): Topology {
  const roots = topology.nodes.filter((node) => node.kind === 'domain').map((node) => ({ ...node }));
  if (!roots.length) return topology;
  const original = new Map(topology.nodes.map((node) => [node.id, node]));
  const servers = topology.nodes.filter((node) => node.kind === 'server').map((node) => ({ ...node }));
  const ports = topology.nodes.filter((node) => node.kind === 'port').map((node) => ({ ...node }));
  const services = topology.nodes.filter((node) => node.kind === 'service').map((node) => ({ ...node }));
  const nodes: TopologyNode[] = [...roots, ...servers, ...ports, ...services];
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges: TopologyEdge[] = [];
  const edgeKeys = new Set<string>();
  const addEdge = (edge: TopologyEdge) => {
    const key = `${edge.from}|${edge.to}|${edge.type || ''}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key); edges.push(edge);
  };

  const incoming = new Map<string, string[]>();
  for (const edge of topology.edges) incoming.set(edge.to, [...(incoming.get(edge.to) || []), edge.from]);
  const upstreamRoots = (nodeId: string): TopologyNode[] => {
    const found = new Set<string>(); const seen = new Set([nodeId]); const queue = [nodeId];
    while (queue.length) {
      const current = queue.shift()!;
      for (const parent of incoming.get(current) || []) {
        if (seen.has(parent)) continue; seen.add(parent);
        if (roots.some((root) => root.id === parent)) found.add(parent);
        else queue.push(parent);
      }
    }
    return roots.filter((root) => found.has(root.id));
  };

  for (const server of servers) {
    const owners = upstreamRoots(server.id);
    for (const root of owners.length ? owners : roots.slice(0, 1)) {
      const direct = topology.edges.find((edge) => edge.from === root.id && edge.to === server.id);
      addEdge(direct || { id: `architecture:${root.id}:${server.id}`, from: root.id, to: server.id, type: 'observed_server', label: 'observed at', state: server.state, confidence: server.details[0]?.confidence || 90, basis: server.details[0]?.basis || 'inferred', evidence: ['This address was retained in the target evidence path.'], findingIds: [] });
    }
  }
  for (const edge of topology.edges) {
    if (original.get(edge.from)?.kind === 'server' && original.get(edge.to)?.kind === 'port') addEdge({ ...edge });
  }

  for (const service of services) {
    const serviceEndpoint = endpoint(service);
    const incomingPorts = topology.edges.filter((edge) => edge.to === service.id && original.get(edge.from)?.kind === 'port');
    const matchingPorts = incomingPorts.length ? incomingPorts : ports.filter((port) => Number(port.label.replace(/\D/g, '')) === serviceEndpoint.port).map((port) => ({ from: port.id, to: service.id } as TopologyEdge));
    for (const relation of matchingPorts) {
      const port = original.get(relation.from); if (!port) continue;
      const sourceDomain = topology.nodes.find((node) => (node.kind === 'domain' || node.kind === 'hostname') && node.label.toLowerCase().replace(/\.$/, '') === serviceEndpoint.hostname.toLowerCase().replace(/\.$/, ''));
      const domainId = `architecture-domain:${port.id}:${serviceEndpoint.hostname}`;
      let domain = nodes.find((node) => node.id === domainId);
      if (!domain) {
        domain = {
          ...(sourceDomain || service), id: domainId, kind: 'hostname', label: serviceEndpoint.hostname,
          subtitle: `Domain served on ${port.label}`, state: strongest(sourceDomain?.state || 'observed', service.state),
          details: sourceDomain ? [...sourceDomain.details] : [{ label: 'Endpoint domain', value: serviceEndpoint.hostname, evidence: `Derived from the observed service endpoint ${service.subtitle}.`, confidence: 90, basis: 'inferred' }],
          findingIds: [...new Set([...(sourceDomain?.findingIds || []), ...service.findingIds])]
        };
        nodes.push(domain); nodeIds.add(domainId);
      } else domain.state = strongest(domain.state, service.state);
      addEdge({ id: `architecture:serves-domain:${port.id}:${domainId}`, from: port.id, to: domainId, type: 'serves_domain', label: 'serves domain', state: relation.state || 'observed', confidence: relation.confidence || 90, basis: relation.basis || 'inferred', evidence: relation.evidence || [`${serviceEndpoint.hostname} was observed on ${port.label}.`], findingIds: relation.findingIds || [] });
      addEdge({ id: `architecture:presents:${domainId}:${service.id}`, from: domainId, to: service.id, type: 'presents_service', label: 'presents', state: relation.state || service.state, confidence: relation.confidence || 90, basis: relation.basis || 'observed', evidence: relation.evidence || [`${service.label} responded for ${serviceEndpoint.hostname}.`], findingIds: relation.findingIds || [] });
    }
  }

  return { nodes: nodes.filter((node) => nodeIds.has(node.id)), edges: edges.filter((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to)) };
}
