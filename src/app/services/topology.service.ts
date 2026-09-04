import { Injectable } from '@angular/core';
import { AgentActionRecord, AssetRecord, AssetRelationRecord, Finding, NodeKind, NodeState, Target, TlsObservation, TopologyEdge, TopologyNode } from '../models';

export interface Topology { nodes: TopologyNode[]; edges: TopologyEdge[]; }

const severityState = (severity?: string): NodeState => severity === 'critical' || severity === 'high' ? 'risk' : severity === 'medium' || severity === 'low' ? 'warning' : 'observed';
const clean = (value: unknown) => String(value ?? '').trim();

@Injectable({ providedIn: 'root' })
export class TopologyService {
  build(target: Target, findings: Finding[], tls: TlsObservation | null, actions: AgentActionRecord[], explicitAssets: AssetRecord[] = [], explicitRelations: AssetRelationRecord[] = []): Topology {
    if (explicitAssets.length) return this.buildExplicit(findings, explicitAssets, explicitRelations);
    const corpus = [target.hostname, ...findings.flatMap((f) => [f.title, f.summary, f.asset, ...f.evidence]), ...actions.flatMap((a) => [a.tool, a.summary])].join('\n');
    const lower = corpus.toLowerCase();
    const nodes: TopologyNode[] = [];
    const edges: TopologyEdge[] = [];
    const related = (term: string) => findings.filter((f) => [f.title, f.summary, f.asset, ...f.evidence].join(' ').toLowerCase().includes(term.toLowerCase()));
    const strongest = (items: Finding[]) => items.sort((a, b) => ['info','low','medium','high','critical'].indexOf(b.severity) - ['info','low','medium','high','critical'].indexOf(a.severity))[0];
    const latestEvidence = <T>(tool: string): T | null => {
      const action = actions.filter((item) => item.tool === tool).at(-1);
      try { return action ? JSON.parse(action.summary) as T : null; } catch { return null; }
    };
    const registration = latestEvidence<{ source?: string; registrar?: { names?: string[]; organizations?: string[] }; events?: Record<string, string>; nameservers?: string[]; dnssec?: { delegationSigned?: boolean | null }; publicEmails?: string[] }>('inspect_domain_registration');
    const dnsPosture = latestEvidence<{ nameservers?: string[]; mx?: Array<{ exchange?: string; priority?: number }>; emailSecurity?: { spf?: string[]; dmarc?: string[]; dmarcPolicy?: string }; dnssec?: { enabled?: boolean } }>('inspect_dns_posture');
    const rootNetworkAction = actions.filter((item) => item.tool === 'inspect_network_registration' && clean(item.input['hostname'] || target.hostname) === target.hostname).at(-1);
    let networkRegistration: { networks?: Array<{ address?: string; name?: string; handle?: string; country?: string; startAddress?: string; endAddress?: string; source?: string }> } | null = null;
    try { networkRegistration = rootNetworkAction ? JSON.parse(rootNetworkAction.summary) : null; } catch { /* No structured root network evidence is available. */ }
    const registrar = registration?.registrar?.organizations?.[0] || registration?.registrar?.names?.[0] || 'Not observed';
    const registrationEvents = registration?.events || {};
    const registrationPeriod = registrationEvents['registration'] ? `${registrationEvents['registration'].slice(0, 10)} → ${registrationEvents['expiration'] ? registrationEvents['expiration'].slice(0, 10) : 'not published'}` : 'Not observed';
    const domainEmails = [...new Set([...(registration?.publicEmails || []), ...(tls?.certificateEmails || [])])];

    nodes.push({
      id: 'domain', kind: 'domain', label: target.hostname, subtitle: 'Authorized domain', state: target.authorizationStatus === 'pending' ? 'warning' : 'observed', x: 12, y: 48,
      details: [
        { label: 'Authorization', value: target.authorizationStatus === 'admin_override' ? 'Admin approved' : target.authorizationStatus, evidence: 'Stored target authorization record.' },
        { label: 'Registrar', value: registrar, evidence: registration ? `Authoritative RDAP evidence from ${registration.source || 'the registry service'}.` : 'The latest scan did not retain RDAP registration evidence.' },
        { label: 'Registered / expires', value: registrationPeriod, evidence: registration ? 'Domain lifecycle events returned by authoritative RDAP.' : 'No RDAP lifecycle evidence is available.' },
        { label: 'Nameservers', value: (dnsPosture?.nameservers || registration?.nameservers || []).join(', ') || 'Not observed', evidence: dnsPosture ? 'Direct public NS resolution.' : registration ? 'Nameservers returned by RDAP.' : 'No nameserver evidence is available.' },
        { label: 'DNSSEC', value: dnsPosture?.dnssec?.enabled || registration?.dnssec?.delegationSigned ? 'Delegation signed' : dnsPosture || registration ? 'Not observed as enabled' : 'Not observed', evidence: dnsPosture ? 'Public DS lookup result.' : 'RDAP secureDNS metadata.' },
        { label: 'Mail policy', value: dnsPosture?.emailSecurity?.dmarcPolicy ? `DMARC ${dnsPosture.emailSecurity.dmarcPolicy} · SPF ${dnsPosture.emailSecurity.spf?.length ? 'present' : 'absent'}` : 'Not observed', evidence: dnsPosture?.emailSecurity?.dmarc?.[0] || dnsPosture?.emailSecurity?.spf?.[0] || 'No DNS mail-policy evidence is available.' },
        { label: 'Public contact email', value: domainEmails.join(', ') || 'None published', evidence: domainEmails.length ? 'Explicitly public RDAP contact or TLS certificate identity field.' : 'Neither authoritative RDAP nor the live TLS certificate published an email address.' },
        { label: 'TLS identity', value: tls?.valid ? `Valid · ${tls.daysRemaining} days left` : tls ? 'Needs attention' : 'Not observed', evidence: tls ? `${tls.issuer}; ${tls.protocol}; valid until ${tls.validTo}.` : 'No TLS observation is available.' },
        { label: 'Certificate names', value: tls?.subjectAltNames?.join(', ') || 'Not observed', evidence: tls ? 'Certificate Subject Alternative Name extension.' : 'No certificate evidence is available.' }
      ], findingIds: findings.filter((f) => /dns|certificate|tls/i.test(f.title)).map((f) => f.id)
    });

    const cloudflare = lower.includes('cloudflare');
    const network = networkRegistration?.networks?.find((item) => item.name || item.handle);
    const providerLabel = cloudflare ? 'Cloudflare' : network?.name || network?.handle || 'Public edge';
    const edgeId = cloudflare ? 'edge-cloudflare' : network ? 'edge-registered' : 'edge-unknown';
    nodes.push({
      id: edgeId, kind: 'edge', label: providerLabel, subtitle: cloudflare ? 'Proxy / tunnel provider' : network ? 'Registered public network' : 'Provider unresolved', state: cloudflare ? 'healthy' : network ? 'observed' : 'unknown', x: 27, y: 48,
      details: [
        { label: 'Provider', value: providerLabel, evidence: cloudflare ? 'DNS and HTTP observations contain Cloudflare network indicators.' : network ? 'Public IP registration returned by RDAP.' : 'No provider fingerprint was retained.' },
        { label: 'Registered network', value: network?.name || network?.handle || 'Not observed', evidence: network ? `IP RDAP for ${network.address || 'the resolved address'}; source ${network.source || 'registry service'}.` : 'No IP-registration evidence is available.' },
        { label: 'Public range', value: network?.startAddress && network?.endAddress ? `${network.startAddress} – ${network.endAddress}` : 'Not observed', evidence: network ? 'Range returned by the public IP RDAP registry.' : 'No network range was retained.' },
        { label: 'Registration country', value: network?.country || 'Not published', evidence: network ? 'Registry country metadata; this is not treated as physical server geolocation.' : 'No network registration was retained.' },
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
      if (action.tool === 'discover_tcp_ports') {
        try {
          const result = JSON.parse(action.summary) as { openPorts?: unknown[] };
          (result.openPorts || []).forEach(addPort);
        } catch { /* An unstructured legacy result cannot establish reachability. */ }
      } else if (action.tool === 'inspect_http' || action.tool === 'inspect_tls') {
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
    const ports = [...portSet].sort((a, b) => a - b);
    ports.forEach((port, index) => {
      const portFindings = findings.filter((f) => findingPorts.get(f.id)?.has(port));
      const strongestFinding = strongest(portFindings);
      const portId = `port-${port}`;
      const isTls = port === 443 || port === 8443;
      nodes.push({ id: portId, kind: 'port', label: `:${port}`, subtitle: isTls ? 'HTTPS / TLS' : port === 80 ? 'HTTP' : 'TCP reachable', state: strongestFinding ? severityState(strongestFinding.severity) : (isTls && tls?.valid ? 'healthy' : 'observed'), x: 68, y: ports.length === 1 ? 48 : 7 + index * (86 / Math.max(1, ports.length - 1)), details: [
        { label: 'Reachability', value: 'Observed at public edge', evidence: 'Bounded TCP connection result retained in the agent trace.' },
        { label: 'Attribution', value: cloudflare ? 'May be CDN edge behavior' : 'Host response', evidence: cloudflare ? 'Cloudflare can answer alternate HTTP ports; origin reachability remains unconfirmed.' : 'No intermediary was identified.' },
        { label: 'Transport', value: isTls ? (tls?.protocol || 'TLS observed') : (port === 80 ? 'Plain HTTP' : 'TCP'), evidence: isTls && tls ? `${tls.protocol}; cipher ${tls.cipher || 'not retained'}.` : 'Protocol label is inferred from the conventional port or HTTP observation.' }
      ], findingIds: portFindings.map((f) => f.id) });
      edges.push({ from: 'server', to: portId });
    });

    type Technology = { name: string; evidence: string };
    type ObservedService = { key: string; label: string; hostname: string; port: number; evidence: string; status?: number; location?: string; productHints?: string[]; technologies?: Technology[] };
    const latestDiscovery = actions.filter((action) => action.tool === 'discover_service_hosts').at(-1);
    const scanActions = latestDiscovery ? actions.filter((action) => action.scan === latestDiscovery.scan) : actions;
    const directHttpEvidence = (hostname: string) => {
      const technologies: Technology[] = [];
      let title = '';
      const evidence: string[] = [];
      for (const action of scanActions.filter((item) => item.tool === 'inspect_http' && clean(item.input['hostname'] || target.hostname) === hostname)) {
        try {
          const result = JSON.parse(action.summary) as { status?: number; requestedUrl?: string; signals?: { title?: string; technologies?: Technology[] } };
          if (result.signals?.title) title = clean(result.signals.title);
          for (const technology of result.signals?.technologies || []) {
            if (technology.name && !technologies.some((item) => item.name.toLowerCase() === technology.name.toLowerCase())) technologies.push(technology);
          }
          if (result.requestedUrl) evidence.push(`${result.requestedUrl} returned ${result.status || 'a response'}.`);
        } catch { /* Ignore unstructured legacy actions. */ }
      }
      return { title, technologies, evidence };
    };
    const discovered: Array<{ hostname?: string; title?: string; status?: number; location?: string; evidence?: string; productHints?: string[]; technologies?: Technology[] }> = [];
    let discoveredRoot: { status?: number; title?: string; serviceWords?: string[]; technologies?: Technology[] } | null = null;
    try {
      const discovery = JSON.parse(latestDiscovery?.summary || '{}');
      discovered.push(...(discovery['serviceHosts'] || []));
      discoveredRoot = discovery['root'] || null;
    } catch { /* Older or truncated discovery output has no structured services. */ }
    const services: ObservedService[] = discovered.map((item, index) => {
      const product = item.productHints?.[0];
      const hostname = clean(item.hostname) || `service-${index + 1}.${target.hostname}`;
      const deep = directHttpEvidence(hostname);
      const technologies = [...(item.technologies || [])];
      for (const technology of deep.technologies) if (!technologies.some((value) => value.name.toLowerCase() === technology.name.toLowerCase())) technologies.push(technology);
      return { key: hostname, label: product ? this.productName(product) : clean(item.title) || deep.title || hostname.split('.')[0]!, hostname, port: 443, evidence: [clean(item.evidence) || 'A distinct HTTPS response was verified beneath the authorized root.', ...deep.evidence].join(' '), status: item.status, location: clean(item.location), productHints: item.productHints || [], technologies };
    });
    if (discoveredRoot) {
      const rootProduct = discoveredRoot.serviceWords?.[0];
      const deep = directHttpEvidence(target.hostname);
      const technologies = [...(discoveredRoot.technologies || [])];
      for (const technology of deep.technologies) if (!technologies.some((value) => value.name.toLowerCase() === technology.name.toLowerCase())) technologies.push(technology);
      services.unshift({
        key: target.hostname,
        label: rootProduct ? this.productName(rootProduct) : clean(discoveredRoot.title) || deep.title || 'Web application',
        hostname: target.hostname,
        port: 443,
        evidence: `Direct HTTPS GET / returned ${discoveredRoot.status || 'a response'}${discoveredRoot.title ? ` with title “${discoveredRoot.title}”` : ''}.`,
        status: discoveredRoot.status,
        productHints: rootProduct ? [rootProduct] : [],
        technologies
      });
    }
    for (const action of scanActions.filter((item) => item.tool === 'inspect_http')) {
      try {
        const result = JSON.parse(action.summary) as { requestedUrl?: string; status?: number; headers?: Record<string, string>; signals?: { title?: string; serviceWords?: string[]; technologies?: Technology[] } };
        if (!result.requestedUrl || !result.status) continue;
        const url = new URL(result.requestedUrl);
        const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
        const product = result.signals?.serviceWords?.[0]?.toLowerCase();
        const distinctPort = port !== 80 && port !== 443;
        if (!product && !distinctPort) continue;
        const label = product ? this.productName(product) : clean(result.signals?.title) || `${url.protocol.replace(':', '').toUpperCase()} service`;
        if (product) {
          const genericIndex = services.findIndex((service) => service.hostname === url.hostname && service.port === port && !(service.productHints || []).length);
          if (genericIndex >= 0) services.splice(genericIndex, 1);
        } else if (services.some((service) => service.hostname === url.hostname && service.port === port && Boolean(service.productHints?.length))) {
          continue;
        }
        const duplicate = services.some((service) => service.hostname === url.hostname && service.port === port && (service.label.toLowerCase() === label.toLowerCase() || Boolean(product && service.productHints?.includes(product))));
        if (duplicate) continue;
        services.push({
          key: `${url.hostname}:${port}:${product || label}`, label, hostname: url.hostname, port,
          evidence: `Direct GET ${result.requestedUrl} returned ${result.status}${result.signals?.title ? ` with title “${result.signals.title}”` : ''}.`,
          status: result.status, location: clean(result.headers?.['location']), productHints: product ? [product] : [], technologies: result.signals?.technologies || []
        });
      } catch { /* Only complete structured HTTP observations can create service nodes. */ }
    }
    if (!services.length) services.push({ key: 'web', label: 'HTTP service', hostname: target.hostname, port: ports.includes(443) ? 443 : ports[0]!, evidence: 'An HTTP response was observed by the bounded application probe.' });

    services.forEach((service, index) => {
      const terms = [service.hostname === target.hostname ? '' : service.hostname, service.label, ...(service.productHints || [])].filter(Boolean);
      const serviceFindings = findings.filter((finding) => terms.some((term) => [finding.title, finding.summary, finding.asset, ...finding.evidence].join(' ').toLowerCase().includes(term.toLowerCase())));
      const strongestFinding = strongest(serviceFindings);
      const id = `service-${index}`;
      const stack = service.technologies || [];
      const endpoint = `${service.hostname}${service.port === 443 ? '' : `:${service.port}`}`;
      nodes.push({ id, kind: 'service', label: service.label, subtitle: stack.length ? `${endpoint} · ${stack.map((technology) => technology.name).join(' + ')}` : endpoint, state: strongestFinding ? severityState(strongestFinding.severity) : 'observed', x: 88, y: services.length === 1 ? 48 : 5 + index * (90 / Math.max(1, services.length - 1)), details: [
        { label: 'Product', value: service.label, evidence: service.evidence },
        { label: 'Endpoint', value: endpoint, evidence: `Verified as distinct from the ${target.hostname} root response or its default listener.` },
        { label: 'Technology stack', value: stack.length ? stack.map((technology) => technology.name).join(' · ') : 'Not observed', evidence: stack.length ? stack.map((technology) => technology.evidence).join(' ') : 'No reliable framework, generator, or server marker was retained.' },
        { label: 'HTTP observation', value: service.status ? `Status ${service.status}` : 'Observed', evidence: service.evidence },
        { label: 'Canonical location', value: service.location || 'No redirect observed', evidence: service.location ? 'Location header returned by the service.' : 'No canonical redirect was retained.' },
        { label: 'Version', value: this.versionNear(corpus, service.label) || 'Not observed', evidence: this.versionNear(corpus, service.label) ? 'Version-like identifier retained in scan evidence.' : 'The public response did not provide a reliable product version.' },
        { label: 'Exposure', value: strongestFinding ? strongestFinding.title : 'Public response observed', evidence: strongestFinding?.evidence[0] || service.evidence },
        { label: 'Confidence', value: strongestFinding ? `${strongestFinding.confidence}%` : 'Unscored', evidence: strongestFinding ? 'Agent-assigned confidence based on retained evidence.' : 'No linked finding is available.' }
      ], findingIds: serviceFindings.map((f) => f.id) });
      edges.push({ from: `port-${ports.includes(service.port) ? service.port : ports[0]}`, to: id });
    });
    return { nodes, edges };
  }

  private buildExplicit(findings: Finding[], assets: AssetRecord[], relations: AssetRelationRecord[]): Topology {
    const columns: Record<NodeKind, number> = { domain: 9, hostname: 23, edge: 36, network: 50, server: 64, port: 78, service: 91 };
    const groups = new Map<NodeKind, AssetRecord[]>();
    for (const asset of assets) groups.set(asset.kind, [...(groups.get(asset.kind) || []), asset]);
    const nodes: TopologyNode[] = [];
    for (const kind of ['domain', 'hostname', 'edge', 'network', 'server', 'port', 'service'] as NodeKind[]) {
      const items = (groups.get(kind) || []).sort((a, b) => a.label.localeCompare(b.label));
      items.forEach((asset, index) => {
        const linked = findings.filter((finding) => finding.assetKey === asset.key || finding.relatedAssetKeys.includes(asset.key));
        const primary = linked.filter((finding) => finding.assetKey === asset.key);
        const strongestFinding = primary.sort((a, b) => ['info','low','medium','high','critical'].indexOf(b.severity) - ['info','low','medium','high','critical'].indexOf(a.severity))[0];
        nodes.push({
          id: asset.key, kind, label: asset.label, subtitle: asset.subtitle,
          state: strongestFinding ? severityState(strongestFinding.severity) : asset.state,
          x: columns[kind], y: items.length === 1 ? 50 : 12 + index * (76 / Math.max(1, items.length - 1)),
          details: [
            { label: 'Evidence grade', value: `${asset.basis.replace('_', ' ')} · ${asset.confidence}%`, evidence: 'Persisted with the asset when the investigation completed.', confidence: asset.confidence, basis: asset.basis },
            ...asset.details
          ], findingIds: linked.map((finding) => finding.id)
        });
      });
    }
    const nodeKeys = new Set(nodes.map((node) => node.id));
    const edges = relations.filter((relation) => nodeKeys.has(relation.fromKey) && nodeKeys.has(relation.toKey)).map((relation) => ({
      id: relation.key, from: relation.fromKey, to: relation.toKey, label: relation.label, type: relation.type,
      state: relation.state, confidence: relation.confidence, basis: relation.basis, evidence: relation.evidence,
      findingIds: findings.filter((finding) => finding.relationKey === relation.key || relation.findingTitles.includes(finding.title)).map((finding) => finding.id)
    }));
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
