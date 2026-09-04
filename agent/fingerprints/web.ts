import type { TechnologySignal } from '../tools/http';

const PROJECTDISCOVERY_REVISION = '50c00c4a9dbea2a9145097714691d3c5b253177d';
const PROJECTDISCOVERY_URL = `https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/${PROJECTDISCOVERY_REVISION}/fingerprints_data.json`;
const MAX_PACK_BYTES = 6 * 1024 * 1024;

type SourceFingerprint = {
  headers?: Record<string, string>; html?: string[]; scriptSrc?: string[]; meta?: Record<string, string[]>;
  website?: string; cpe?: string; description?: string;
};
type SourcePack = { apps?: Record<string, SourceFingerprint> };
type CompiledRule = { product: string; kind: string; field: string; pattern: RegExp; website: string; cpe: string };

export interface WebFingerprintMatch extends TechnologySignal {
  confidence: number;
  cpe: string;
  website: string;
  source: string;
}

let compiledPromise: Promise<{ rules: CompiledRule[]; source: string; status: string }> | null = null;

function expression(value: string): RegExp | null {
  const raw = value.split(/\\;(?=(?:version|confidence|implies|requires|excludes):)/i)[0] || '';
  if (!raw || raw.length > 900) return null;
  try { return new RegExp(raw, 'i'); } catch { return null; }
}

function compilePack(pack: SourcePack): CompiledRule[] {
  const rules: CompiledRule[] = [];
  for (const [product, fingerprint] of Object.entries(pack.apps || {}).slice(0, 8_000)) {
    const common = { product: product.slice(0, 160), website: String(fingerprint.website || '').slice(0, 500), cpe: String(fingerprint.cpe || '').slice(0, 500) };
    for (const [field, value] of Object.entries(fingerprint.headers || {})) {
      const pattern = expression(value); if (pattern) rules.push({ ...common, kind: 'header', field: field.toLowerCase(), pattern });
    }
    for (const value of (fingerprint.html || []).slice(0, 20)) {
      const pattern = expression(value); if (pattern) rules.push({ ...common, kind: 'html', field: 'body', pattern });
    }
    for (const value of (fingerprint.scriptSrc || []).slice(0, 20)) {
      const pattern = expression(value); if (pattern) rules.push({ ...common, kind: 'script', field: 'src', pattern });
    }
    for (const [field, values] of Object.entries(fingerprint.meta || {})) for (const value of values.slice(0, 10)) {
      const pattern = expression(value); if (pattern) rules.push({ ...common, kind: 'meta', field: field.toLowerCase(), pattern });
    }
  }
  return rules.slice(0, 80_000);
}

async function loadCompiledPack() {
  try {
    const response = await fetch(PROJECTDISCOVERY_URL, { signal: AbortSignal.timeout(15_000), headers: { accept: 'application/json', 'user-agent': 'WellguardObserve/0.2' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const length = Number(response.headers.get('content-length') || 0);
    if (length > MAX_PACK_BYTES) throw new Error('fingerprint pack exceeds the size limit');
    const body = await response.text();
    if (body.length > MAX_PACK_BYTES) throw new Error('fingerprint pack exceeds the size limit');
    const rules = compilePack(JSON.parse(body) as SourcePack);
    if (rules.length < 500) throw new Error('fingerprint pack did not contain enough valid rules');
    return { rules, source: PROJECTDISCOVERY_URL, status: `${rules.length} validated ProjectDiscovery web rules loaded from pinned revision ${PROJECTDISCOVERY_REVISION.slice(0, 12)}.` };
  } catch (error) {
    return { rules: [] as CompiledRule[], source: PROJECTDISCOVERY_URL, status: `Public fingerprint pack unavailable: ${error instanceof Error ? error.message : String(error)}. Built-in service markers remain active.` };
  }
}

export async function fingerprintWebResponse(headers: Record<string, string>, raw: string): Promise<{ matches: WebFingerprintMatch[]; source: string; status: string }> {
  compiledPromise ||= loadCompiledPack();
  const pack = await compiledPromise;
  const scripts = [...raw.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)].map((match) => match[1]).join('\n');
  const metas = new Map<string, string>();
  for (const match of raw.matchAll(/<meta\b[^>]*>/gi)) {
    const name = match[0].match(/\b(?:name|property)=["']([^"']+)["']/i)?.[1]?.toLowerCase();
    const value = match[0].match(/\bcontent=["']([^"']*)["']/i)?.[1];
    if (name && value != null) metas.set(name, value);
  }
  const evidence = new Map<string, { website: string; cpe: string; items: string[] }>();
  for (const rule of pack.rules) {
    const value = rule.kind === 'header' ? headers[rule.field] || '' : rule.kind === 'html' ? raw : rule.kind === 'script' ? scripts : metas.get(rule.field) || '';
    if (!value || !rule.pattern.test(value)) continue;
    const current = evidence.get(rule.product) || { website: rule.website, cpe: rule.cpe, items: [] };
    const label = rule.kind === 'header' ? `HTTP header ${rule.field}` : rule.kind === 'meta' ? `meta ${rule.field}` : rule.kind === 'script' ? 'script source' : 'HTML marker';
    if (!current.items.includes(label)) current.items.push(label);
    evidence.set(rule.product, current);
  }
  const matches = [...evidence.entries()].map(([name, item]) => ({
    name, confidence: Math.min(98, item.items.length === 1 ? 72 : 72 + (item.items.length - 1) * 10),
    cpe: item.cpe, website: item.website, source: pack.source,
    evidence: `${item.items.join(' and ')} matched the pinned ProjectDiscovery Wappalyzer-compatible fingerprint pack.`
  })).sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name)).slice(0, 30);
  return { matches, source: pack.source, status: pack.status };
}

export function fingerprintCatalog() {
  return {
    id: 'projectdiscovery-wappalyzergo', version: PROJECTDISCOVERY_REVISION, format: 'wappalyzer-compatible',
    source: PROJECTDISCOVERY_URL, license: 'MIT', capabilities: ['http-headers', 'html', 'script-src', 'meta'],
    trust: 'Pinned source revision; size-bounded and schema-normalized before matching.'
  };
}
