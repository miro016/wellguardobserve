import { cachedExternalFetch } from '../external-cache';

const RECOG_REVISION = 'd3d20938da9f5f1e442c2419fe6c30cd651b6878';
const MAX_XML_BYTES = 2 * 1024 * 1024;
const packs: Record<string, string> = {
  ssh: 'ssh_banners.xml', ftp: 'ftp_banners.xml', smtp: 'smtp_banners.xml',
  favicon: 'favicons.xml', http_server: 'http_servers.xml', http_auth: 'http_wwwauth.xml'
};
const cache = new Map<string, Promise<{ rules: Rule[]; source: string; status: string }>>();

type Rule = { pattern: RegExp; description: string; product: string; versionPosition: number | null };

function decode(value: string): string {
  return value.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&#(\d+);/g, (_all, code) => String.fromCharCode(Number(code)));
}

function parse(xml: string): Rule[] {
  const rules: Rule[] = [];
  for (const item of xml.matchAll(/<fingerprint\s+[^>]*pattern="([^"]+)"[^>]*>([\s\S]*?)<\/fingerprint>/gi)) {
    const raw = decode(item[1]!).replace(/\\A/g, '^').replace(/\\z/g, '$');
    if (raw.length > 1200) continue;
    let pattern: RegExp; try { pattern = new RegExp(raw, 'i'); } catch { continue; }
    const body = item[2]!;
    const description = decode(body.match(/<description>([\s\S]*?)<\/description>/i)?.[1]?.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || 'Recognized service');
    let product = '';
    let versionPosition: number | null = null;
    for (const param of body.matchAll(/<param\s+([^>]+?)\/?\s*>/gi)) {
      const attrs = param[1]!;
      const name = attrs.match(/\bname="([^"]+)"/i)?.[1] || '';
      const value = decode(attrs.match(/\bvalue="([^"]*)"/i)?.[1] || '');
      const position = Number(attrs.match(/\bpos="(\d+)"/i)?.[1]);
      if (name === 'service.product' && value) product = value;
      if (name === 'service.version' && Number.isInteger(position)) versionPosition = position;
    }
    rules.push({ pattern, description, product, versionPosition });
  }
  return rules.slice(0, 20_000);
}

async function load(protocol: string) {
  if (!packs[protocol]) return { rules: [] as Rule[], source: '', status: `No Recog pack is enabled for ${protocol}.` };
  const source = `https://raw.githubusercontent.com/rapid7/recog/${RECOG_REVISION}/xml/${packs[protocol]}`;
  try {
    const response = await cachedExternalFetch(source, { signal: AbortSignal.timeout(12_000), headers: { 'user-agent': 'WellguardObserve/0.2', accept: 'application/xml,text/xml' } }, { source: 'Rapid7 Recog fingerprints', ttlMs: 30 * 86_400_000, staleIfErrorMs: 90 * 86_400_000 });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const length = Number(response.headers.get('content-length') || 0);
    if (length > MAX_XML_BYTES) throw new Error('fingerprint pack exceeds the size limit');
    const body = await response.text(); if (body.length > MAX_XML_BYTES) throw new Error('fingerprint pack exceeds the size limit');
    const rules = parse(body); if (!rules.length) throw new Error('no compatible fingerprint rules were parsed');
    return { rules, source, status: `${rules.length} validated Rapid7 Recog rules loaded from pinned revision ${RECOG_REVISION.slice(0, 12)}.` };
  } catch (error) {
    return { rules: [] as Rule[], source, status: `Recog fingerprint pack unavailable: ${error instanceof Error ? error.message : String(error)}.` };
  }
}

export async function fingerprintBanner(protocol: string, banner: string) {
  if (!cache.has(protocol)) cache.set(protocol, load(protocol));
  const pack = await cache.get(protocol)!;
  const matches = pack.rules.flatMap((rule) => {
    const match = rule.pattern.exec(banner); if (!match) return [];
    const version = rule.versionPosition == null ? '' : String(match[rule.versionPosition] || '');
    return [{ product: rule.product || rule.description, version, description: rule.description, confidence: 92, evidence: `${protocol.toUpperCase()} banner matched a pinned Rapid7 Recog fingerprint.`, source: pack.source }];
  }).slice(0, 8);
  return { protocol, matches, source: pack.source, status: pack.status };
}

export function recogCatalog() {
  return { id: 'rapid7-recog', version: RECOG_REVISION, source: `https://github.com/rapid7/recog/tree/${RECOG_REVISION}`, license: 'BSD-2-Clause', capabilities: ['ssh-banner', 'ftp-banner', 'smtp-banner', 'http-server-header', 'http-auth-challenge', 'favicon-md5'], trust: 'Pinned source revision; size-bounded XML and JavaScript-compatible regular expressions only.' };
}
