import { resolve, resolveCaa, resolveMx, resolveNs, resolveSoa, resolveTxt } from 'node:dns/promises';
import type { ScopeGuard } from '../security/scope-guard';

type RdapEntity = { handle?: string; roles?: string[]; vcardArray?: unknown; entities?: RdapEntity[] };
type RdapEvent = { eventAction?: string; eventDate?: string };
type RdapDocument = {
  handle?: string; ldhName?: string; status?: string[]; entities?: RdapEntity[]; events?: RdapEvent[];
  nameservers?: Array<{ ldhName?: string }>; secureDNS?: { delegationSigned?: boolean; dsData?: unknown[] };
  notices?: Array<{ title?: string; description?: string[]; links?: Array<{ href?: string }> }>;
};

function vcardProperties(entity: RdapEntity): Array<[string, unknown, string, unknown]> {
  const card = entity.vcardArray;
  if (!Array.isArray(card) || !Array.isArray(card[1])) return [];
  return card[1].filter((item): item is [string, unknown, string, unknown] => Array.isArray(item) && item.length >= 4);
}

function publicEntities(entities: RdapEntity[] = []): Array<Record<string, unknown>> {
  return entities.slice(0, 30).map((entity) => {
    const properties = vcardProperties(entity);
    const text = (name: string) => properties.filter((item) => item[0] === name).map((item) => String(item[3] || '')).filter(Boolean);
    return {
      handle: entity.handle || '', roles: entity.roles || [], names: text('fn').slice(0, 5), organizations: text('org').slice(0, 5),
      emails: text('email').slice(0, 10), phones: text('tel').slice(0, 5), nested: publicEntities(entity.entities || []).slice(0, 10)
    };
  });
}

export function summarizeRdap(document: RdapDocument, sourceUrl: string) {
  const entities = publicEntities(document.entities);
  const registrars = entities.filter((entity) => (entity['roles'] as string[]).includes('registrar'));
  const emails = [...new Set(JSON.stringify(entities).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [])].slice(0, 30);
  return {
    source: sourceUrl, domain: document.ldhName || document.handle || '', statuses: document.status || [],
    registrar: registrars[0] || null,
    events: Object.fromEntries((document.events || []).flatMap((event) => event.eventAction && event.eventDate ? [[event.eventAction, event.eventDate]] : [])),
    nameservers: (document.nameservers || []).map((item) => item.ldhName || '').filter(Boolean),
    dnssec: { delegationSigned: document.secureDNS?.delegationSigned ?? null, dsRecordCount: document.secureDNS?.dsData?.length || 0 },
    publicContacts: entities, publicEmails: emails,
    notices: (document.notices || []).slice(0, 10).map((notice) => ({ title: notice.title || '', description: (notice.description || []).join(' ').slice(0, 600), links: (notice.links || []).map((link) => link.href).filter(Boolean) })),
    privacyNote: emails.length ? 'These contact addresses were explicitly published by the authoritative RDAP service.' : 'No public registration email was returned; registry privacy or redaction is preserved.'
  };
}

let bootstrapCache: { loadedAt: number; services: Array<[string[], string[]]> } | null = null;

export async function inspectDomainRegistration(scope: ScopeGuard) {
  const domain = scope.rootHostname;
  if (!bootstrapCache || Date.now() - bootstrapCache.loadedAt > 86_400_000) {
    const response = await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(10_000), headers: { 'user-agent': 'WellguardObserve/0.1' } });
    if (!response.ok) throw new Error(`IANA RDAP bootstrap returned ${response.status}.`);
    const document = await response.json() as { services?: Array<[string[], string[]]> };
    bootstrapCache = { loadedAt: Date.now(), services: document.services || [] };
  }
  const tld = domain.split('.').at(-1)!.toLowerCase();
  const service = bootstrapCache.services.find(([tlds]) => tlds.map((item) => item.toLowerCase()).includes(tld));
  const base = service?.[1]?.find((url) => url.startsWith('https://'));
  if (!base) throw new Error(`No HTTPS RDAP service is registered for .${tld}.`);
  const sourceUrl = `${base.replace(/\/+$/, '')}/domain/${encodeURIComponent(domain)}`;
  const response = await fetch(sourceUrl, { signal: AbortSignal.timeout(12_000), headers: { accept: 'application/rdap+json,application/json', 'user-agent': 'WellguardObserve/0.1' } });
  if (!response.ok) throw new Error(`Authoritative RDAP service returned ${response.status} for ${domain}.`);
  return summarizeRdap(await response.json() as RdapDocument, sourceUrl);
}

async function optional<T>(operation: () => Promise<T>, fallback: T): Promise<T> {
  try { return await operation(); } catch { return fallback; }
}

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join('')).slice(0, 100);
}

export async function inspectDnsPosture(scope: ScopeGuard) {
  const domain = scope.rootHostname;
  const [nameservers, mx, txtRaw, caa, soa, dmarcRaw, mtaStsRaw, tlsRptRaw, ds] = await Promise.all([
    optional(() => resolveNs(domain), []), optional(() => resolveMx(domain), []), optional(() => resolveTxt(domain), []),
    optional(() => resolveCaa(domain), []), optional(() => resolveSoa(domain), null), optional(() => resolveTxt(`_dmarc.${domain}`), []),
    optional(() => resolveTxt(`_mta-sts.${domain}`), []), optional(() => resolveTxt(`_smtp._tls.${domain}`), []),
    optional(async () => await resolve(domain, 'DS') as unknown as Array<Record<string, unknown>>, [] as Array<Record<string, unknown>>)
  ]);
  const txt = flattenTxt(txtRaw);
  const dmarc = flattenTxt(dmarcRaw).filter((record) => /^v=DMARC1\b/i.test(record));
  const spf = txt.filter((record) => /^v=spf1\b/i.test(record));
  const mtaSts = flattenTxt(mtaStsRaw).filter((record) => /^v=STSv1\b/i.test(record));
  const tlsReporting = flattenTxt(tlsRptRaw).filter((record) => /^v=TLSRPTv1\b/i.test(record));
  const dmarcPolicy = dmarc[0]?.match(/(?:^|;)\s*p=([^;\s]+)/i)?.[1]?.toLowerCase() || '';
  return {
    domain, nameservers, mx: mx.sort((a, b) => a.priority - b.priority), soa, caa, txt,
    emailSecurity: {
      spf, dmarc, dmarcPolicy: dmarcPolicy || 'not published', mtaSts, tlsReporting,
      observations: [
        spf.length === 1 ? 'One SPF policy is published.' : spf.length > 1 ? 'Multiple SPF policies are published and should be reviewed.' : 'No SPF policy was observed.',
        dmarc.length ? `DMARC policy is ${dmarcPolicy || 'present but unparsed'}.` : 'No DMARC policy was observed.',
        mtaSts.length ? 'MTA-STS discovery record is published.' : 'No MTA-STS discovery record was observed.',
        tlsReporting.length ? 'SMTP TLS reporting is published.' : 'No SMTP TLS reporting record was observed.'
      ]
    },
    dnssec: { dsRecords: ds, enabled: ds.length > 0 },
    note: 'DNS records describe public routing and policy. Missing optional mail controls are review signals and are not automatically treated as vulnerabilities.'
  };
}

export async function inspectNetworkRegistration(scope: ScopeGuard, hostname?: string) {
  const host = scope.assertHostname(hostname);
  const addresses = (await scope.resolve(host)).slice(0, 6);
  const networks = await Promise.all(addresses.map(async ({ address, family }) => {
    const sourceUrl = `https://rdap-bootstrap.arin.net/bootstrap/ip/${encodeURIComponent(address)}`;
    try {
      const response = await fetch(sourceUrl, { signal: AbortSignal.timeout(12_000), headers: { accept: 'application/rdap+json,application/json', 'user-agent': 'WellguardObserve/0.1' } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const document = await response.json() as Record<string, unknown>;
      return {
        address, family, source: response.url || sourceUrl, handle: String(document['handle'] || ''), name: String(document['name'] || ''),
        type: String(document['type'] || ''), country: String(document['country'] || ''), startAddress: String(document['startAddress'] || ''),
        endAddress: String(document['endAddress'] || ''), ipVersion: String(document['ipVersion'] || ''), parentHandle: String(document['parentHandle'] || ''),
        entities: publicEntities(Array.isArray(document['entities']) ? document['entities'] as RdapEntity[] : []),
        events: Object.fromEntries((Array.isArray(document['events']) ? document['events'] as RdapEvent[] : []).flatMap((event) => event.eventAction && event.eventDate ? [[event.eventAction, event.eventDate]] : []))
      };
    } catch (error) { return { address, family, source: sourceUrl, error: error instanceof Error ? error.message : String(error) }; }
  }));
  return {
    hostname: host, networks,
    note: 'IP registration identifies the organization responsible for the observed public network range. It does not establish the physical server location or prove that a CDN address is the origin.'
  };
}
