import type { AgentAction, AgentAsset, AgentAssetFact, AgentAssetRelation, AgentFinding, AgentPublicIdentity, AssetState, AuthorizedTarget, EvidenceBasis, TlsEvidence } from './types';

const clean = (value: unknown) => String(value ?? '').trim();
const slug = (value: string) => value.toLowerCase().replace(/[^a-z0-9_.:@-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 180) || 'unknown';
const parse = (action: AgentAction): Record<string, unknown> | null => { try { return JSON.parse(action.summary) as Record<string, unknown>; } catch { return null; } };
const severityState = (severity: string): AssetState => ['critical', 'high'].includes(severity) ? 'risk' : ['medium', 'low'].includes(severity) ? 'warning' : 'observed';
const stateRank: Record<AssetState, number> = { risk: 4, warning: 3, unknown: 2, healthy: 1, observed: 0 };
const strongerState = (current: AssetState, candidate: AssetState): AssetState => stateRank[candidate] > stateRank[current] ? candidate : current;
const safeLinks = (values: unknown[]): string[] => [...new Set(values.map(clean).flatMap((value) => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? [url.toString()] : []; } catch { return []; } }))].slice(0, 20);
const displayProduct = (value: string): string => /^[a-z0-9 -]+$/.test(value) ? value.replace(/\b\w/g, (letter) => letter.toUpperCase()) : value;

export function buildAssetGraph(target: AuthorizedTarget, actions: AgentAction[], findings: AgentFinding[], tls: TlsEvidence[]) {
  const assets = new Map<string, AgentAsset>();
  const relations = new Map<string, AgentAssetRelation>();
  const identities = new Map<string, AgentPublicIdentity>();
  const hostnameAddresses = new Map<string, Set<string>>();
  const hostnameEdges = new Map<string, string>();

  const fact = (label: string, value: unknown, evidence: string, confidence = 100, basis: EvidenceBasis = 'observed'): AgentAssetFact => ({ label, value: clean(value) || 'Not observed', evidence, confidence, basis });
  const ensureAsset = (asset: AgentAsset): AgentAsset => {
    const existing = assets.get(asset.key);
    if (!existing) { assets.set(asset.key, asset); return asset; }
    existing.label = existing.label === 'Web application' && asset.label !== 'Web application' ? asset.label : existing.label;
    existing.subtitle = asset.subtitle || existing.subtitle; existing.confidence = Math.max(existing.confidence, asset.confidence);
    if (existing.basis === 'inferred' && asset.basis !== 'inferred') existing.basis = asset.basis;
    for (const item of asset.details) {
      const same = existing.details.find((value) => value.label === item.label && value.value === item.value);
      if (!same) existing.details.push(item); else if (item.confidence > same.confidence) Object.assign(same, item);
    }
    return existing;
  };
  const ensureRelation = (relation: AgentAssetRelation) => {
    const existing = relations.get(relation.key);
    if (!existing) relations.set(relation.key, relation);
    else { existing.confidence = Math.max(existing.confidence, relation.confidence); existing.evidence = [...new Set([...existing.evidence, ...relation.evidence])].slice(0, 20); }
  };
  const domainKey = `domain:${target.hostname}`;
  ensureAsset({ key: domainKey, kind: 'domain', label: target.hostname, subtitle: 'Authorized root', state: 'observed', confidence: 100, basis: 'owner_confirmed', details: [fact('Authorization', target.authorizationStatus, 'Stored target authorization record.', 100, 'owner_confirmed')] });
  for (const hostname of target.authorizedHosts || []) {
    const key = `hostname:${hostname}`;
    ensureAsset({ key, kind: 'hostname', label: hostname, subtitle: 'Exact related scope', state: 'observed', confidence: 100, basis: 'owner_confirmed', details: [fact('Scope', 'Exact hostname only', 'Administrator explicitly authorized this hostname; its parent and sibling hosts remain out of scope.', 100, 'owner_confirmed')] });
    ensureRelation({ key: `authorizes:${domainKey}:${key}`, fromKey: domainKey, toKey: key, type: 'authorizes', label: 'authorized related asset', state: 'observed', confidence: 100, basis: 'owner_confirmed', evidence: ['Administrator approval record links this exact related hostname to the target.'], findingTitles: [] });
  }
  const hostKey = (hostname: string) => hostname === target.hostname ? domainKey : `hostname:${hostname}`;
  const ensureHost = (hostname: string, evidence = 'Hostname observed during the investigation.') => ensureAsset({ key: hostKey(hostname), kind: hostname === target.hostname ? 'domain' : 'hostname', label: hostname, subtitle: hostname === target.hostname ? 'Authorized root' : 'Observed hostname', state: 'observed', confidence: 100, basis: 'observed', details: [fact('Hostname', hostname, evidence)] });
  const rememberAddress = (hostname: string, address: string, evidence: string) => {
    const set = hostnameAddresses.get(hostname) || new Set<string>(); set.add(address); hostnameAddresses.set(hostname, set);
    ensureHost(hostname); const serverKey = `server:${address}`;
    ensureAsset({ key: serverKey, kind: 'server', label: address, subtitle: 'Observed public address', state: 'observed', confidence: 100, basis: 'observed', details: [fact('Public address', address, evidence)] });
    ensureRelation({ key: `resolves:${hostKey(hostname)}:${serverKey}`, fromKey: hostKey(hostname), toKey: serverKey, type: 'resolves_to', label: 'resolves to', state: 'observed', confidence: 100, basis: 'observed', evidence: [evidence], findingTitles: [] });
    const edgeKey = hostnameEdges.get(hostname);
    if (edgeKey) ensureRelation({ key: `serves:${edgeKey}:${serverKey}`, fromKey: edgeKey, toKey: serverKey, type: 'serves_from_address', label: 'serves from edge address', state: 'observed', confidence: 95, basis: 'inferred', evidence: [`${hostname} returned the edge-provider marker and resolved to ${address}. This does not identify an origin address.`], findingTitles: [] });
  };
  const ensurePort = (hostname: string, port: number, evidence: string) => {
    const key = `port:${hostname}:${port}`;
    ensureAsset({ key, kind: 'port', label: `:${port}`, subtitle: hostname, state: 'observed', confidence: 100, basis: 'observed', details: [fact('Reachability', 'TCP connection accepted', evidence)] });
    const addresses = [...(hostnameAddresses.get(hostname) || [])];
    if (addresses.length) for (const address of addresses) ensureRelation({ key: `exposes:server:${address}:${key}`, fromKey: `server:${address}`, toKey: key, type: 'exposes_port', label: 'exposes', state: 'observed', confidence: 100, basis: 'observed', evidence: [evidence], findingTitles: [] });
    else ensureRelation({ key: `exposes:${hostKey(hostname)}:${key}`, fromKey: hostKey(hostname), toKey: key, type: 'exposes_port', label: 'exposes', state: 'observed', confidence: 90, basis: 'inferred', evidence: [evidence], findingTitles: [] });
    return key;
  };
  const ensureService = (hostname: string, port: number, product: string, evidence: string, technologies: string[] = []) => {
    const endpointPrefix = `service:${hostname}:${port}:`;
    if (product === 'Web application' || product.startsWith('Unknown ')) {
      const identified = [...assets.values()].find((asset) => asset.kind === 'service' && asset.key.startsWith(endpointPrefix) && asset.label !== 'Web application' && !asset.label.startsWith('Unknown '));
      if (identified) {
        if (technologies.length && !identified.details.some((detail) => detail.label === 'Technology evidence' && detail.value === technologies.join(' · '))) identified.details.push(fact('Technology evidence', technologies.join(' · '), evidence, 85));
        return identified.key;
      }
    }
    ensureHost(hostname); const normalized = slug(product); const key = `service:${hostname}:${port}:${normalized}`; const portKey = ensurePort(hostname, port, `A direct application or protocol response was retained for ${hostname}:${port}.`);
    ensureAsset({ key, kind: 'service', label: product, subtitle: `${hostname}${port === 443 ? '' : `:${port}`}`, state: 'observed', confidence: product === 'Web application' || product.startsWith('Unknown ') ? 55 : 90, basis: product === 'Web application' || product.startsWith('Unknown ') ? 'inferred' : 'observed', details: [fact('Product', product, evidence, product === 'Web application' ? 55 : 90, product === 'Web application' ? 'inferred' : 'observed'), ...(technologies.length ? [fact('Technology evidence', technologies.join(' · '), evidence, 85)] : [])] });
    ensureRelation({ key: `runs:${portKey}:${key}`, fromKey: portKey, toKey: key, type: 'runs_service', label: 'runs', state: 'observed', confidence: product === 'Web application' ? 70 : 95, basis: product === 'Web application' ? 'inferred' : 'observed', evidence: [evidence], findingTitles: [] });
    return key;
  };

  for (const action of actions) {
    const data = parse(action); if (!data) continue;
    if (action.tool === 'inspect_dns') {
      const hostname = clean(data['hostname'] || action.input['hostname'] || target.hostname);
      for (const item of Array.isArray(data['addresses']) ? data['addresses'] : []) {
        if (item && typeof item === 'object') { const address = clean((item as Record<string, unknown>)['address']); if (address) rememberAddress(hostname, address, `Direct DNS resolution for ${hostname}.`); }
      }
    }
    if (action.tool === 'inspect_network_registration') {
      const hostname = clean(data['hostname'] || action.input['hostname'] || target.hostname); ensureHost(hostname);
      for (const raw of Array.isArray(data['networks']) ? data['networks'] : []) {
        if (!raw || typeof raw !== 'object') continue; const network = raw as Record<string, unknown>; const address = clean(network['address']); if (!address) continue;
        rememberAddress(hostname, address, `Public DNS resolution performed before IP RDAP lookup for ${hostname}.`);
        const label = clean(network['name'] || network['handle']) || 'Registered network'; const range = [clean(network['startAddress']), clean(network['endAddress'])].filter(Boolean).join(' – '); const networkKey = `network:${slug(clean(network['handle'] || range || label))}`;
        ensureAsset({ key: networkKey, kind: 'network', label, subtitle: range || 'Public network registration', state: 'observed', confidence: 100, basis: 'registry', details: [fact('Registered range', range, `IP RDAP response from ${clean(network['source']) || 'the delegated registry'}.`, 100, 'registry'), fact('Registry country', clean(network['country']) || 'Not published', 'Registry metadata; this is not physical server geolocation.', 100, 'registry'), fact('Physical location', 'Unknown', 'Network registration does not establish the physical location of a server.', 100, 'registry')] });
        const server = assets.get(`server:${address}`)!;
        server.details.push(fact('Registered network holder', label, `IP RDAP associates ${address} with ${label}; this can be a CDN or hosting network rather than the machine owner.`, 100, 'registry'));
        server.details.push(fact('Physical location', 'Unknown', `${clean(network['country']) || 'No country'} is registry metadata and is not presented as physical server location.`, 100, 'registry'));
        ensureRelation({ key: `contains:${networkKey}:server:${address}`, fromKey: networkKey, toKey: `server:${address}`, type: 'contains_address', label: 'contains address', state: 'observed', confidence: 100, basis: 'registry', evidence: [`IP RDAP associates ${address} with ${label}${range ? ` (${range})` : ''}.`], findingTitles: [] });
      }
    }
    if (action.tool === 'inspect_dns_posture') {
      const domain = clean(data['domain']) || target.hostname; const asset = ensureHost(domain);
      const emailSecurity = (data['emailSecurity'] || {}) as Record<string, unknown>; const dnssec = (data['dnssec'] || {}) as Record<string, unknown>;
      const nameservers = Array.isArray(data['nameservers']) ? data['nameservers'].map(clean).filter(Boolean) : [];
      const mx = Array.isArray(data['mx']) ? data['mx'].flatMap((item) => item && typeof item === 'object' ? [clean((item as Record<string, unknown>)['exchange'])].filter(Boolean) : []) : [];
      asset.details.push(fact('Nameservers', nameservers.join(', '), 'Direct public NS resolution.'));
      asset.details.push(fact('Mail routing', mx.join(', '), 'Direct public MX resolution.'));
      asset.details.push(fact('DNSSEC', Array.isArray(dnssec['dsRecords']) && dnssec['dsRecords'].length ? 'Delegation signed' : 'Not observed as enabled', 'Direct public DS lookup.'));
      asset.details.push(fact('DMARC', clean(emailSecurity['dmarcPolicy']) || 'Not published', 'Direct public DMARC TXT lookup.'));
    }
    if (action.tool === 'inspect_certificate_transparency') {
      const asset = ensureHost(target.hostname); const count = Number(data['certificateCount'] || 0); const names = Array.isArray(data['names']) ? data['names'].map(clean).filter(Boolean) : [];
      asset.details.push(fact('Certificate transparency', `${count} record${count === 1 ? '' : 's'}`, `Public crt.sh query retained ${names.length} authorized certificate name${names.length === 1 ? '' : 's'}.`, 100, 'registry'));
    }
    if (action.tool === 'discover_tcp_ports') {
      const hostname = clean(data['hostname'] || action.input['hostname'] || target.hostname); const address = clean(data['testedAddress']); if (address) rememberAddress(hostname, address, `TCP reachability test resolved ${hostname} to ${address}.`);
      for (const value of Array.isArray(data['openPorts']) ? data['openPorts'] : []) { const port = Number(value); if (port > 0) ensurePort(hostname, port, `Bounded TCP connection to ${hostname}:${port} succeeded.`); }
    }
    if (action.tool === 'discover_service_hosts') {
      const retain = (raw: unknown, fallbackHostname: string) => {
        if (!raw || typeof raw !== 'object') return; const item = raw as Record<string, unknown>;
        const hostname = clean(item['hostname']) || fallbackHostname; if (!hostname) return; const title = clean(item['title']);
        const hints = Array.isArray(item['productHints']) ? item['productHints'].map(clean).filter(Boolean) : Array.isArray(item['serviceWords']) ? item['serviceWords'].map(clean).filter(Boolean) : [];
        const technologies = Array.isArray(item['technologies']) ? item['technologies'].flatMap((value) => value && typeof value === 'object' ? [clean((value as Record<string, unknown>)['name'])].filter(Boolean) : []) : [];
        const applicationTechnology = technologies.find((technology) => !/^(cloudflare|akamai|fastly|amazon cloudfront)$/i.test(technology));
        const product = hints[0] || applicationTechnology || (title.length <= 60 ? title : 'Website') || 'Web application';
        const status = Number(item['status'] || 0); const evidence = clean(item['evidence']) || `Distinct HTTPS response from ${hostname} returned ${status || 'a response'}${title ? ` with title “${title}”` : ''}.`;
        const key = ensureService(hostname, 443, displayProduct(product), evidence, technologies);
        const asset = assets.get(key)!; if (title && !asset.details.some((detail) => detail.label === 'Page title' && detail.value === title)) asset.details.push(fact('Page title', title, evidence));
      };
      retain(data['root'], target.hostname);
      for (const service of Array.isArray(data['serviceHosts']) ? data['serviceHosts'] : []) retain(service, '');
    }
    if (action.tool === 'inspect_http') {
      const requestedUrl = clean(data['requestedUrl']); if (!requestedUrl) continue; let url: URL; try { url = new URL(requestedUrl); } catch { continue; }
      const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80)); const signals = (data['signals'] || {}) as Record<string, unknown>; const words = Array.isArray(signals['serviceWords']) ? signals['serviceWords'].map(clean).filter(Boolean) : [];
      const technologies = Array.isArray(signals['technologies']) ? signals['technologies'].flatMap((value) => value && typeof value === 'object' ? [clean((value as Record<string, unknown>)['name'])].filter(Boolean) : []) : [];
      const preferred = words[0] || technologies.find((item) => !/^(cloudflare|akamai|fastly|amazon cloudfront)$/i.test(item)) || 'Web application';
      const serviceKey = ensureService(url.hostname, port, displayProduct(preferred), `GET ${requestedUrl} returned ${Number(data['status'] || 0)}.`, technologies);
      const service = assets.get(serviceKey)!; const title = clean(signals['title']); if (title) service.details.push(fact('Page title', title, `Direct response from ${requestedUrl}.`));
      const fingerprints = (data['fingerprinting'] || {}) as Record<string, unknown>; if (clean(fingerprints['status'])) service.details.push(fact('Fingerprint catalogue', clean(fingerprints['status']), `Pinned fingerprint source ${clean(fingerprints['source'])}.`, 100, 'registry'));
      const headers = (data['headers'] || {}) as Record<string, unknown>;
      if (/cloudflare/i.test(clean(headers['server'])) || clean(headers['cf-ray'])) {
        const edgeKey = 'edge:cloudflare'; hostnameEdges.set(url.hostname, edgeKey);
        ensureAsset({ key: edgeKey, kind: 'edge', label: 'Cloudflare', subtitle: 'Observed public edge', state: 'observed', confidence: 100, basis: 'observed', details: [fact('Provider', 'Cloudflare', `GET ${requestedUrl} returned ${clean(headers['cf-ray']) ? 'a cf-ray marker' : 'a Cloudflare server header'}.`), fact('Origin path', 'Unknown', 'A Cloudflare response does not establish whether Tunnel or proxied DNS connects to the origin.'), fact('Rate limiting', 'Not tested', 'Safe reconnaissance does not intentionally trigger rate limits.')] });
        ensureRelation({ key: `proxied:${hostKey(url.hostname)}:${edgeKey}`, fromKey: hostKey(url.hostname), toKey: edgeKey, type: 'proxied_by', label: 'proxied by', state: 'observed', confidence: 100, basis: 'observed', evidence: [`The direct response from ${requestedUrl} returned Cloudflare-specific HTTP evidence.`], findingTitles: [] });
        for (const address of hostnameAddresses.get(url.hostname) || []) ensureRelation({ key: `serves:${edgeKey}:server:${address}`, fromKey: edgeKey, toKey: `server:${address}`, type: 'serves_from_address', label: 'serves from edge address', state: 'observed', confidence: 95, basis: 'inferred', evidence: [`${url.hostname} returned the Cloudflare marker and resolved to ${address}. This does not identify an origin address.`], findingTitles: [] });
      }
    }
    if (action.tool === 'inspect_service_banner') {
      const hostname = clean(data['hostname']); const port = Number(data['port']); const fingerprinting = (data['fingerprinting'] || {}) as Record<string, unknown>; const matches = Array.isArray(fingerprinting['matches']) ? fingerprinting['matches'] : [];
      const first = matches[0] && typeof matches[0] === 'object' ? matches[0] as Record<string, unknown> : null; const protocol = clean(data['protocolHint']) || 'TCP'; const product = clean(first?.['product']) || `Unknown ${protocol.toUpperCase()} service`;
      ensureService(hostname, port, product, clean(first?.['evidence']) || clean(data['note']) || 'Passive TCP banner observation.');
    }
    if (action.tool === 'inspect_wordpress') {
      const hostname = clean(data['hostname']); const port = Number(action.input['port'] || 443); ensureService(hostname, port, 'WordPress', 'WordPress adapter returned direct REST or page markers.');
      const evidence = (data['evidence'] || {}) as Record<string, unknown>; const publicUsers = (evidence['publicUsers'] || {}) as Record<string, unknown>; const sourceUrl = clean(publicUsers['url']);
      for (const raw of Array.isArray(publicUsers['users']) ? publicUsers['users'] : []) {
        if (!raw || typeof raw !== 'object') continue; const user = raw as Record<string, unknown>; const displayName = clean(user['name'] || user['slug']); const email = `${clean(user['name'])} ${clean(user['slug'])}`.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || '';
        const key = `identity:wordpress:${slug(hostname)}:${clean(user['id']) || slug(displayName)}`; const links = safeLinks([user['link'], user['url']]);
        identities.set(key, { key, kind: email ? 'mailbox' : 'person', displayName, email, publicLinks: links, sourceUrls: safeLinks([sourceUrl]), evidence: [`Anonymous WordPress REST view returned id=${clean(user['id']) || 'unknown'}, name=${clean(user['name']) || 'empty'}, slug=${clean(user['slug']) || 'empty'}.`], sourceAssetKey: `service:${hostname}:${port}:wordpress`, confidence: 100, employmentStatus: 'unknown', reviewNote: 'Public author metadata does not establish an administrator role or current employment.' });
      }
    }
    if (action.tool === 'inspect_public_metadata') {
      const hostname = clean(data['hostname'] || action.input['hostname'] || target.hostname);
      const port = Number(action.input['port'] || (action.input['tls'] === false ? 80 : 443));
      const sourceAssetKey = [...assets.values()].find((asset) => asset.kind === 'service' && asset.subtitle.toLowerCase().startsWith(hostname.toLowerCase()))?.key
        || ensureService(hostname, port, 'Web application', 'A fixed public metadata path returned a direct response.');
      for (const raw of Array.isArray(data['observations']) ? data['observations'] : []) {
        if (!raw || typeof raw !== 'object') continue;
        const observation = raw as Record<string, unknown>;
        const requestedUrl = clean(observation['requestedUrl']);
        for (const contact of Array.isArray(observation['contacts']) ? observation['contacts'].map(clean) : []) {
          const email = contact.match(/mailto:([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i)?.[1]?.toLowerCase() || '';
          if (!email) continue;
          const key = `identity:security-txt:${slug(hostname)}:${slug(email)}`;
          identities.set(key, {
            key, kind: 'mailbox', displayName: email, email, publicLinks: [], sourceUrls: safeLinks([requestedUrl]),
            evidence: [`The public security.txt response explicitly returned “${contact.slice(0, 300)}”.`], sourceAssetKey,
            confidence: 100, employmentStatus: 'not_applicable', reviewNote: 'Published security contact; no employment inference is made.'
          });
        }
      }
    }
    if (action.tool === 'inspect_domain_registration') {
      const emails = Array.isArray(data['publicEmails']) ? data['publicEmails'].map(clean).filter(Boolean) : [];
      const domain = clean(data['domain']) || target.hostname; const asset = ensureHost(domain); const registrar = (data['registrar'] || {}) as Record<string, unknown>; const organizations = Array.isArray(registrar['organizations']) ? registrar['organizations'].map(clean).filter(Boolean) : [];
      if (organizations.length) asset.details.push(fact('Registrar', organizations[0], `Authoritative RDAP source ${clean(data['source'])}.`, 100, 'registry'));
      for (const email of emails) identities.set(`identity:rdap:${slug(domain)}:${slug(email)}`, { key: `identity:rdap:${slug(domain)}:${slug(email)}`, kind: 'mailbox', displayName: email, email, publicLinks: [], sourceUrls: safeLinks([data['source']]), evidence: [`The delegated RDAP service explicitly published ${email}.`], sourceAssetKey: domainKey, confidence: 100, employmentStatus: 'not_applicable', reviewNote: 'Registry contact; no employment inference is made.' });
    }
    if (action.tool === 'inspect_service_adapter') {
      const hostname = clean(data['hostname']); const product = clean(data['product']) || 'Adapted service'; const port = Number(action.input['port'] || 443); ensureService(hostname, port, product, `${clean((data['adapter'] as Record<string, unknown> | undefined)?.['name']) || 'Service adapter'} returned direct product evidence.`);
      for (const raw of Array.isArray(data['relations']) ? data['relations'] : []) {
        if (!raw || typeof raw !== 'object') continue; const relation = raw as Record<string, unknown>; const toKey = clean(relation['toKey']);
        if (toKey.startsWith('hostname:')) ensureHost(toKey.slice('hostname:'.length), 'The service publicly advertised this hostname; it was not automatically probed outside approved scope.');
        if (toKey.startsWith('server:')) ensureAsset({ key: toKey, kind: 'server', label: toKey.slice('server:'.length), subtitle: 'Address advertised by a service', state: 'warning', confidence: 100, basis: 'observed', details: [fact('Disclosure source', product, 'The service returned this address in public configuration.', 100)] });
        ensureRelation({ key: clean(relation['key']), fromKey: clean(relation['fromKey']), toKey, type: clean(relation['type']), label: clean(relation['label']), state: (clean(relation['state']) || 'observed') as AssetState, confidence: Number(relation['confidence'] || 100), basis: (clean(relation['basis']) || 'observed') as EvidenceBasis, evidence: Array.isArray(relation['evidence']) ? relation['evidence'].map(clean) : [], findingTitles: [] });
      }
    }
  }

  for (const item of tls) {
    const asset = ensureHost(item.hostname, 'A hostname-validated TLS handshake completed.'); ensurePort(item.hostname, item.port, `TLS handshake on ${item.hostname}:${item.port} negotiated ${item.protocol}.`);
    asset.details.push(fact('TLS identity', item.subjectAltNames.join(', ') || item.subject, `Certificate issued by ${item.issuer}; valid until ${item.validTo}.`));
    if (item.valid) { asset.state = 'healthy'; asset.details.push(fact('Certificate state', 'Valid', `Hostname validation succeeded; ${item.daysRemaining} days remain.`)); }
  }

  const serviceForFinding = (finding: AgentFinding) => {
    const hostname = clean(finding.asset).replace(/^https?:\/\//, '').replace(/[/:].*$/, '').toLowerCase();
    const candidates = [...assets.values()].filter((asset) => asset.kind === 'service' && asset.subtitle.toLowerCase().startsWith(hostname));
    const product = candidates.find((asset) => finding.title.toLowerCase().includes(asset.label.toLowerCase()));
    return (product || candidates[0])?.key || (assets.has(hostKey(hostname)) ? hostKey(hostname) : domainKey);
  };
  for (const finding of findings) {
    if (finding.assetKey === `hostname:${target.hostname}`) finding.assetKey = domainKey;
    const suggestedAssetKey = serviceForFinding(finding);
    const requestedAsset = finding.assetKey ? assets.get(finding.assetKey) : undefined;
    const suggestedAsset = assets.get(suggestedAssetKey);
    const namesObservedService = suggestedAsset?.kind === 'service'
      && !['Web application', 'Website'].includes(suggestedAsset.label)
      && `${finding.title} ${finding.summary}`.toLowerCase().includes(suggestedAsset.label.toLowerCase());
    if (!requestedAsset || ((requestedAsset.kind === 'domain' || requestedAsset.kind === 'hostname') && namesObservedService)) finding.assetKey = suggestedAssetKey;
    finding.relatedAssetKeys ||= []; finding.relationKey ||= '';
    const asset = finding.assetKey ? assets.get(finding.assetKey) : undefined; if (asset) asset.state = strongerState(asset.state, severityState(finding.severity));
    const relation = finding.relationKey ? relations.get(finding.relationKey) : null;
    if (relation) { relation.state = strongerState(relation.state, severityState(finding.severity)); relation.findingTitles.push(finding.title); }
    for (const key of finding.relatedAssetKeys) { const related = assets.get(key); if (related && related.state === 'unknown') related.state = 'warning'; }
  }

  return { assets: [...assets.values()], relations: [...relations.values()], identities: [...identities.values()] };
}
