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
      id: 'domain', kind: 'domain', label: target.hostname, subtitle: 'Authorized domain', state: target.authorizationStatus === 'pending' ? 'warning' : 'observed', x: 8, y: 48,
      details: [
        { label: 'Authorization', value: target.authorizationStatus === 'admin_override' ? 'Admin approved' : target.authorizationStatus, evidence: 'Stored target authorization record.' },
        { label: 'Registration', value: 'Not observed', evidence: 'The latest scan did not retain RDAP registration evidence.' },
        { label: 'TLS identity', value: tls?.valid ? `Valid · ${tls.daysRemaining} days left` : tls ? 'Needs attention' : 'Not observed', evidence: tls ? `${tls.issuer}; ${tls.protocol}; valid until ${tls.validTo}.` : 'No TLS observation is available.' },
        { label: 'Certificate names', value: tls?.subjectAltNames?.join(', ') || 'Not observed', evidence: tls ? 'Certificate Subject Alternative Name extension.' : 'No certificate evidence is available.' }
      ], findingIds: related(target.hostname).map((f) => f.id)
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
    for (const match of corpus.matchAll(/(?:port[\s"':=]*|:)(\d{2,5})\b/gi)) {
      const port = Number(match[1]); if (port > 0 && port <= 65535) portSet.add(port);
    }
    if (tls?.port) portSet.add(tls.port); else if (tls) portSet.add(443);
    if (!portSet.size) { portSet.add(80); portSet.add(443); }
    const ports = [...portSet].sort((a, b) => a - b).slice(0, 7);
    ports.forEach((port, index) => {
      const portFindings = findings.filter((f) => f.asset.includes(`:${port}`) || [f.title, f.summary, ...f.evidence].join(' ').includes(String(port)));
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

    const services: Array<{ key: string; label: string; port: number; evidence: string }> = [];
    if (lower.includes('easypanel')) services.push({ key: 'easypanel', label: 'Easypanel', port: 443, evidence: 'Page title, application assets, or API metadata identify Easypanel.' });
    if (lower.includes('keycloak')) services.push({ key: 'keycloak', label: 'Keycloak', port: 443, evidence: 'Public response metadata contains a Keycloak identifier.' });
    if (!services.length || lower.includes('http')) services.push({ key: 'web', label: services.length ? 'Web endpoint' : 'HTTP service', port: ports.includes(443) ? 443 : ports[0]!, evidence: 'An HTTP response was observed by the bounded application probe.' });
    services.slice(0, 5).forEach((service, index) => {
      const serviceFindings = related(service.key === 'web' ? 'http' : service.key);
      const strongestFinding = strongest(serviceFindings);
      const id = `service-${service.key}`;
      nodes.push({ id, kind: 'service', label: service.label, subtitle: strongestFinding?.severity === 'high' ? 'Review exposure' : 'Identified service', state: strongestFinding ? severityState(strongestFinding.severity) : 'observed', x: 88, y: 30 + index * 26, details: [
        { label: 'Product', value: service.label, evidence: service.evidence },
        { label: 'Version', value: this.versionNear(corpus, service.label) || 'Not observed', evidence: this.versionNear(corpus, service.label) ? 'Version-like identifier retained in scan evidence.' : 'The public response did not provide a reliable product version.' },
        { label: 'Exposure', value: strongestFinding ? strongestFinding.title : 'Public response observed', evidence: strongestFinding?.evidence[0] || service.evidence },
        { label: 'Confidence', value: strongestFinding ? `${strongestFinding.confidence}%` : 'Unscored', evidence: strongestFinding ? 'Agent-assigned confidence based on retained evidence.' : 'No linked finding is available.' }
      ], findingIds: serviceFindings.map((f) => f.id) });
      edges.push({ from: `port-${ports.includes(service.port) ? service.port : ports[0]}`, to: id });
    });
    return { nodes, edges };
  }

  private versionNear(corpus: string, product: string): string {
    const escaped = product.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return clean(corpus.match(new RegExp(`${escaped}[^\\n]{0,45}?(?:v(?:ersion)?\\s*)?(\\d+\\.\\d+(?:\\.\\d+)?)`, 'i'))?.[1]);
  }
}
