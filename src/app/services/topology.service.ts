import { Injectable } from '@angular/core';
import { AgentActionRecord, Finding, NodeState, Target, TlsObservation, TopologyEdge, TopologyNode } from '../models';

export interface Topology { nodes: TopologyNode[]; edges: TopologyEdge[]; }

const severityState = (severity?: string): NodeState => severity === 'critical' || severity === 'high' ? 'risk' : severity === 'medium' || severity === 'low' ? 'warning' : 'observed';
const clean = (value: unknown) => String(value ?? '').trim();

@Injectable({ providedIn: 'root' })
export class TopologyService {
  build(target: Target, findings: Finding[], tls: TlsObservation | null, actions: AgentActionRecord[]): Topology {
    const corpus = [target.hostname, ...findings.flatMap((f) => [f.title, f.summary, f.asset, ...f.evidence]), ...actions.flatMap((a) => [a.tool, a.summary])].join('\n');
    const lower = corpus.toLowerCase();
    const nodes: TopologyNode[] = [];
    const edges: TopologyEdge[] = [];
    const related = (term: string) => findings.filter((f) => [f.title, f.summary, f.asset, ...f.evidence].join(' ').toLowerCase().includes(term.toLowerCase()));
    const strongest = (items: Finding[]) => items.sort((a, b) => ['info','low','medium','high','critical'].indexOf(b.severity) - ['info','low','medium','high','critical'].indexOf(a.severity))[0];

    nodes.push({
      id: 'domain', kind: 'domain', label: target.hostname, subtitle: 'Authorized domain', state: target.authorizationStatus === 'pending' ? 'warning' : 'observed', x: 12, y: 48,
      details: [
        { label: 'Authorization', value: target.authorizationStatus === 'admin_override' ? 'Admin approved' : target.authorizationStatus, evidence: 'Stored target authorization record.' },
        { label: 'Registration', value: 'Not observed', evidence: 'The latest scan did not retain RDAP registration evidence.' },
        { label: 'TLS identity', value: tls?.valid ? `Valid · ${tls.daysRemaining} days left` : tls ? 'Needs attention' : 'Not observed', evidence: tls ? `${tls.issuer}; ${tls.protocol}; valid until ${tls.validTo}.` : 'No TLS observation is available.' },
        { label: 'Certificate names', value: tls?.subjectAltNames?.join(', ') || 'Not observed', evidence: tls ? 'Certificate Subject Alternative Name extension.' : 'No certificate evidence is available.' }
      ], findingIds: findings.filter((f) => /dns|certificate|tls/i.test(f.title)).map((f) => f.id)
    });

    const cloudflare = lower.includes('cloudflare');
    const edgeId = cloudflare ? 'edge-cloudflare' : 'edge-unknown';
    nodes.push({
      id: edgeId, kind: 'edge', label: cloudflare ? 'Cloudflare' : 'Public edge', subtitle: cloudflare ? 'Proxy / tunnel provider' : 'Provider unresolved', state: cloudflare ? 'healthy' : 'unknown', x: 27, y: 48,
      details: [
        { label: 'Provider', value: cloudflare ? 'Cloudflare' : 'Not identified', evidence: cloudflare ? 'DNS and HTTP observations contain Cloudflare network indicators.' : 'No provider fingerprint was retained.' },
        { label: 'Origin masking', value: cloudflare ? 'Active' : 'Unknown', evidence: cloudflare ? 'Public DNS resolves to CDN edge addresses; these are not treated as origin addresses.' : 'Origin relationship is not externally confirmed.' },
        { label: 'Rate limiting', value: 'Not externally verifiable', evidence: 'A safe recon scan does not trigger limits or send abusive traffic.' }
      ], findingIds: related('cloudflare').map((f) => f.id)
    });
    edges.push({ from: 'domain', to: edgeId, label: 'DNS / HTTPS' });

    nodes.push({
      id: 'server', kind: 'server', label: cloudflare ? 'Origin concealed' : 'Observed host', subtitle: 'Application server', state: 'unknown', x: 47, y: 48,
      details: [
        { label: 'Origin address', value: cloudflare ? 'Not exposed by this scan' : 'Not retained', evidence: cloudflare ? 'The edge provider terminates the visible connection.' : 'No direct origin evidence is available.' },
        { label: 'Physical location', value: 'Unknown', evidence: 'CDN geolocation would describe the edge, not the physical origin.' },
        { label: 'Machine type', value: 'Unknown', evidence: 'Hardware cannot be established reliably through safe external reconnaissance.' },
        { label: 'Boundary', value: cloudflare ? 'Behind public edge' : 'Direct / unresolved', evidence: 'Inferred from the observed DNS and HTTP path.' }
      ], findingIds: []
    });
    edges.push({ from: edgeId, to: 'server', label: cloudflare ? 'proxied' : 'route' });

    const portSet = new Set<number>();
    const addPort = (value: unknown) => { const port = Number(value); if (Number.isInteger(port) && port > 0 && port <= 65535) portSet.add(port); };
    const collectPorts = (value: unknown): void => {
      if (Array.isArray(value)) { value.forEach(collectPorts); return; }
      if (!value || typeof value !== 'object') return;
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        if (/^port$/i.test(key)) addPort(item);
        else if (/^ports$/i.test(key) && Array.isArray(item)) item.forEach(addPort);
        else collectPorts(item);
      }
    };
    for (const action of actions) {
      if (action.tool === 'discover_tcp_ports' || action.tool === 'inspect_http' || action.tool === 'inspect_tls') {
        collectPorts(action.input);
        try { collectPorts(JSON.parse(action.summary)); } catch { /* Retain only structured port evidence. */ }
      }
    }
    const findingPorts = new Map<string, Set<number>>();
    for (const finding of findings) {
      const observed = new Set<number>();
      const retain = (value: unknown) => { const port = Number(value); if (Number.isInteger(port) && port > 0 && port <= 65535) { observed.add(port); addPort(port); } };
      for (const match of finding.asset.matchAll(/:(\d{1,5})\b/g)) retain(match[1]);
      const text = [finding.title, finding.summary].join(' ');
      for (const match of text.matchAll(/\bports?\s+(\d{1,5})(?:\s*(?:,|and)\s*(\d{1,5}))?/gi)) { retain(match[1]); if (match[2]) retain(match[2]); }
      for (const evidence of finding.evidence) {
        for (const match of evidence.matchAll(/\b(?:GET|HEAD)\s+(https?):\/\/[^/:\s]+(?::(\d{1,5}))?/gi)) retain(match[2] || (match[1].toLowerCase() === 'https' ? 443 : 80));
      }
      if (/tls|certificate/i.test(finding.title)) observed.add(443);
      findingPorts.set(finding.id, observed);
    }
    if (tls?.port) portSet.add(tls.port); else if (tls) portSet.add(443);
    if (!portSet.size) { portSet.add(80); portSet.add(443); }
    const ports = [...portSet].sort((a, b) => a - b).slice(0, 7);
    ports.forEach((port, index) => {
      const portFindings = findings.filter((f) => findingPorts.get(f.id)?.has(port));
      const strongestFinding = strongest(portFindings);
      const portId = `port-${port}`;
      const isTls = port === 443 || port === 8443;
      nodes.push({ id: portId, kind: 'port', label: `:${port}`, subtitle: isTls ? 'HTTPS / TLS' : port === 80 ? 'HTTP' : 'TCP reachable', state: strongestFinding ? severityState(strongestFinding.severity) : (isTls && tls?.valid ? 'healthy' : 'observed'), x: 68, y: 16 + index * Math.min(15, 68 / Math.max(1, ports.length - 1)), details: [
        { label: 'Reachability', value: 'Observed at public edge', evidence: 'Bounded TCP connection result retained in the agent trace.' },
        { label: 'Attribution', value: cloudflare ? 'May be CDN edge behavior' : 'Host response', evidence: cloudflare ? 'Cloudflare can answer alternate HTTP ports; origin reachability remains unconfirmed.' : 'No intermediary was identified.' },
        { label: 'Transport', value: isTls ? (tls?.protocol || 'TLS observed') : (port === 80 ? 'Plain HTTP' : 'TCP'), evidence: isTls && tls ? `${tls.protocol}; cipher ${tls.cipher || 'not retained'}.` : 'Protocol label is inferred from the conventional port or HTTP observation.' }
      ], findingIds: portFindings.map((f) => f.id) });
      edges.push({ from: 'server', to: portId });
    });

    type ObservedService = { key: string; label: string; hostname: string; port: number; evidence: string; status?: number; location?: string; productHints?: string[] };
    const latestDiscovery = actions.filter((action) => action.tool === 'discover_service_hosts').at(-1);
    const discovered: Array<{ hostname?: string; title?: string; status?: number; location?: string; evidence?: string; productHints?: string[] }> = [];
    try { discovered.push(...(JSON.parse(latestDiscovery?.summary || '{}')['serviceHosts'] || [])); } catch { /* Older or truncated discovery output has no structured services. */ }
    const services: ObservedService[] = discovered.map((item, index) => {
      const product = item.productHints?.find((hint) => hint !== 'easypanel');
      const hostname = clean(item.hostname) || `service-${index + 1}.${target.hostname}`;
      return { key: hostname, label: product ? this.productName(product) : clean(item.title) || hostname.split('.')[0]!, hostname, port: 443, evidence: clean(item.evidence) || 'A distinct HTTPS response was verified beneath the authorized root.', status: item.status, location: clean(item.location), productHints: item.productHints || [] };
    });
    if (lower.includes('easypanel')) services.unshift({ key: 'easypanel-root', label: 'Easypanel', hostname: target.hostname, port: 443, evidence: 'The root response identifies the Easypanel management surface.' });
    if (!services.length) services.push({ key: 'web', label: 'HTTP service', hostname: target.hostname, port: ports.includes(443) ? 443 : ports[0]!, evidence: 'An HTTP response was observed by the bounded application probe.' });

    const visible = services.slice(0, services.length > 7 ? 6 : 7);
    visible.forEach((service, index) => {
      const terms = [service.hostname, service.label, ...(service.productHints || [])].filter(Boolean);
      const serviceFindings = findings.filter((finding) => terms.some((term) => [finding.title, finding.summary, finding.asset, ...finding.evidence].join(' ').toLowerCase().includes(term.toLowerCase())));
      const strongestFinding = strongest(serviceFindings);
      const id = `service-${index}`;
      nodes.push({ id, kind: 'service', label: service.label, subtitle: service.hostname, state: strongestFinding ? severityState(strongestFinding.severity) : 'observed', x: 88, y: visible.length === 1 ? 48 : 10 + index * (80 / Math.max(1, visible.length - 1)), details: [
        { label: 'Product', value: service.label, evidence: service.evidence },
        { label: 'Endpoint', value: service.hostname, evidence: `Verified as distinct from the ${target.hostname} root response.` },
        { label: 'HTTP observation', value: service.status ? `Status ${service.status}` : 'Observed', evidence: service.evidence },
        { label: 'Canonical location', value: service.location || 'No redirect observed', evidence: service.location ? 'Location header returned by the service.' : 'No canonical redirect was retained.' },
        { label: 'Version', value: this.versionNear(corpus, service.label) || 'Not observed', evidence: this.versionNear(corpus, service.label) ? 'Version-like identifier retained in scan evidence.' : 'The public response did not provide a reliable product version.' },
        { label: 'Exposure', value: strongestFinding ? strongestFinding.title : 'Public response observed', evidence: strongestFinding?.evidence[0] || service.evidence },
        { label: 'Confidence', value: strongestFinding ? `${strongestFinding.confidence}%` : 'Unscored', evidence: strongestFinding ? 'Agent-assigned confidence based on retained evidence.' : 'No linked finding is available.' }
      ], findingIds: serviceFindings.map((f) => f.id) });
      edges.push({ from: `port-${ports.includes(service.port) ? service.port : ports[0]}`, to: id });
    });
    if (services.length > visible.length) {
      const remaining = services.slice(visible.length);
      const id = 'service-more';
      nodes.push({ id, kind: 'service', label: `+${remaining.length} more`, subtitle: 'Verified service hosts', state: 'observed', x: 88, y: 94, details: [
        { label: 'Additional hosts', value: remaining.map((service) => service.hostname).join(', '), evidence: 'Each host returned a distinct non-missing HTTPS response during bounded service discovery.' }
      ], findingIds: [] });
      edges.push({ from: `port-${ports.includes(443) ? 443 : ports[0]}`, to: id });
    }
    return { nodes, edges };
  }

  private productName(value: string): string {
    return ({ keycloak: 'Keycloak', easypanel: 'Easypanel', grafana: 'Grafana', prometheus: 'Prometheus', jenkins: 'Jenkins', gitlab: 'GitLab', kibana: 'Kibana', rabbitmq: 'RabbitMQ', phpmyadmin: 'phpMyAdmin', portainer: 'Portainer', traefik: 'Traefik', swagger: 'Swagger', openapi: 'OpenAPI', jupyter: 'Jupyter', wordpress: 'WordPress', beszel: 'Beszel', excalidraw: 'Excalidraw', linkwarden: 'Linkwarden', logto: 'Logto', immich: 'Immich', minio: 'MinIO' } as Record<string, string>)[value] || value;
  }

  private versionNear(corpus: string, product: string): string {
    const escaped = product.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return clean(corpus.match(new RegExp(`${escaped}[^\\n]{0,45}?(?:v(?:ersion)?\\s*)?(\\d+\\.\\d+(?:\\.\\d+)?)`, 'i'))?.[1]);
  }
}
