import { isPrivateAddress } from '../security/scope-guard';
import { resolve4, resolve6 } from 'node:dns/promises';
import https from 'node:https';

async function assertPublicResearchUrl(raw: string): Promise<{ url: URL; address: string; family: 4 | 6 }> {
  const url = new URL(raw);
  if (url.protocol !== 'https:') throw new Error('Research pages must use HTTPS.');
  if (url.username || url.password || url.port) throw new Error('Research URL credentials and custom ports are blocked.');
  const v4 = await resolve4(url.hostname).catch(() => []);
  const v6 = await resolve6(url.hostname).catch(() => []);
  const addresses = [...v4, ...v6];
  if (!addresses.length || addresses.some(isPrivateAddress)) throw new Error('Research URL did not resolve to a permitted public address.');
  return v4.length ? { url, address: v4[0]!, family: 4 } : { url, address: v6[0]!, family: 6 };
}

export async function readPublicSource(rawUrl: string) {
  const { url, address, family } = await assertPublicResearchUrl(rawUrl);
  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    const request = https.request({
      hostname: url.hostname, path: `${url.pathname}${url.search}`, method: 'GET', servername: url.hostname,
      headers: { host: url.hostname, 'user-agent': 'WellguardObserve/0.1', accept: 'text/html,application/json,text/plain,application/xml;q=0.8' },
      lookup: (_name, options, callback) => {
        if (typeof options === 'object' && options.all) {
          const allCallback = callback as unknown as (error: null, addresses: Array<{ address: string; family: 4 | 6 }>) => void;
          allCallback(null, [{ address, family }]);
        } else callback(null, address, family);
      },
      timeout: 10_000, rejectUnauthorized: true
    }, (response) => {
      if ((response.statusCode || 500) >= 300) { response.resume(); reject(new Error(`Public source returned ${response.statusCode}; redirects are not followed.`)); return; }
      const contentType = String(response.headers['content-type'] || '');
      if (!/(text|json|xml)/i.test(contentType)) { response.resume(); reject(new Error('Only textual public sources may be read.')); return; }
      const chunks: Buffer[] = []; let size = 0; let truncated = false;
      response.on('data', (chunk: Buffer) => {
        if (size >= 48_000) { truncated = true; return; }
        const remaining = 48_000 - size; chunks.push(chunk.subarray(0, remaining)); size += Math.min(remaining, chunk.length);
        if (chunk.length > remaining) truncated = true;
      });
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8').replace(/<script[\s\S]*?<\/script>/gi, ' ').slice(0, 24_000);
        resolve({ url: url.toString(), contentType, text, truncated });
      });
    });
    request.once('timeout', () => request.destroy(new Error('Public source request timed out.')));
    request.once('error', reject);
    request.end();
  });
}

export async function queryGitHubAdvisory(identifier: string) {
  const normalized = identifier.trim().toUpperCase();
  if (!/^(CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})$/.test(normalized)) {
    throw new Error('A valid CVE or GHSA identifier is required.');
  }
  const query = normalized.startsWith('CVE-') ? `cve_id=${normalized}` : `ghsa_id=${normalized.toLowerCase()}`;
  const response = await fetch(`https://api.github.com/advisories?${query}`, {
    signal: AbortSignal.timeout(10_000), headers: { accept: 'application/vnd.github+json', 'user-agent': 'WellguardObserve/0.1', 'x-github-api-version': '2026-03-10' }
  });
  if (!response.ok) throw new Error(`GitHub Advisory API returned ${response.status}.`);
  return { source: 'GitHub reviewed security advisories', advisories: (await response.json() as unknown[]).slice(0, 10) };
}

let kevCache: { loadedAt: number; entries: Array<Record<string, string>> } | null = null;
export async function queryCisaKev(cve: string) {
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) throw new Error('A valid CVE identifier is required.');
  if (!kevCache || Date.now() - kevCache.loadedAt > 3_600_000) {
    const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: AbortSignal.timeout(12_000) });
    if (!response.ok) throw new Error(`CISA KEV feed returned ${response.status}.`);
    const data = await response.json() as { vulnerabilities: Array<Record<string, string>> };
    kevCache = { loadedAt: Date.now(), entries: data.vulnerabilities };
  }
  return { source: 'CISA Known Exploited Vulnerabilities', match: kevCache.entries.find((entry) => entry['cveID']?.toUpperCase() === cve.toUpperCase()) || null };
}

export async function queryOsv(input: { ecosystem: string; packageName: string; version: string }) {
  const response = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST', signal: AbortSignal.timeout(10_000),
    headers: { 'content-type': 'application/json', 'user-agent': 'WellguardObserve/0.1' },
    body: JSON.stringify({ package: { ecosystem: input.ecosystem, name: input.packageName }, version: input.version })
  });
  if (!response.ok) throw new Error(`OSV API returned ${response.status}.`);
  const data = await response.json() as { vulns?: unknown[] };
  return { source: 'OSV.dev', ecosystem: input.ecosystem, packageName: input.packageName, version: input.version, vulnerabilities: (data.vulns || []).slice(0, 20) };
}

export async function queryGitHubReleases(input: { owner: string; repository: string }) {
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(input.owner) || !/^[A-Za-z0-9_.-]{1,100}$/.test(input.repository)) {
    throw new Error('GitHub owner or repository is invalid.');
  }
  const response = await fetch(`https://api.github.com/repos/${input.owner}/${input.repository}/releases?per_page=10`, {
    signal: AbortSignal.timeout(10_000), headers: { accept: 'application/vnd.github+json', 'user-agent': 'WellguardObserve/0.1', 'x-github-api-version': '2026-03-10' }
  });
  if (!response.ok) throw new Error(`GitHub Releases API returned ${response.status}.`);
  const releases = await response.json() as Array<{ tag_name: string; published_at: string; html_url: string; prerelease: boolean; draft: boolean }>;
  return { source: 'GitHub Releases API', repository: `${input.owner}/${input.repository}`, releases: releases.map(({ tag_name, published_at, html_url, prerelease, draft }) => ({ tag_name, published_at, html_url, prerelease, draft })) };
}

function englishDescription(items: unknown): string {
  if (!Array.isArray(items)) return '';
  const descriptions = items.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object');
  return String(descriptions.find((item) => item['lang'] === 'en')?.['value'] || descriptions[0]?.['value'] || '').slice(0, 1_200);
}

function normalizedNvdMetric(metrics: unknown): Record<string, unknown> | null {
  if (!metrics || typeof metrics !== 'object') return null;
  const source = metrics as Record<string, unknown>;
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const entries = source[key];
    if (!Array.isArray(entries) || !entries.length || !entries[0] || typeof entries[0] !== 'object') continue;
    const metric = entries[0] as Record<string, unknown>;
    const data = metric['cvssData'] && typeof metric['cvssData'] === 'object' ? metric['cvssData'] as Record<string, unknown> : {};
    return { version: data['version'] || key.replace('cvssMetricV', ''), score: data['baseScore'] ?? null, severity: data['baseSeverity'] || metric['baseSeverity'] || '', vector: data['vectorString'] || '' };
  }
  return null;
}

function nvdCpeRanges(configurations: unknown): Array<Record<string, unknown>> {
  const ranges: Array<Record<string, unknown>> = [];
  const walk = (value: unknown): void => {
    if (ranges.length >= 30 || !value) return;
    if (Array.isArray(value)) { value.forEach(walk); return; }
    if (typeof value !== 'object') return;
    const record = value as Record<string, unknown>;
    if (typeof record['criteria'] === 'string') {
      ranges.push({
        criteria: record['criteria'], vulnerable: record['vulnerable'] ?? null,
        versionStartIncluding: record['versionStartIncluding'] || '', versionStartExcluding: record['versionStartExcluding'] || '',
        versionEndIncluding: record['versionEndIncluding'] || '', versionEndExcluding: record['versionEndExcluding'] || ''
      });
    }
    Object.values(record).forEach(walk);
  };
  walk(configurations);
  return ranges;
}

export async function queryNvdCves(input: { product: string; version: string }) {
  const product = input.product.trim();
  const version = input.version.trim();
  if (!product || !version || product.length > 120 || version.length > 80) throw new Error('An exact observed product and version are required for NVD correlation.');
  const query = new URLSearchParams({ keywordSearch: `${product} ${version}`, resultsPerPage: '10' });
  const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?${query}`, {
    signal: AbortSignal.timeout(15_000), headers: { accept: 'application/json', 'user-agent': 'WellguardObserve/0.1' }
  });
  if (!response.ok) throw new Error(`NVD CVE API returned ${response.status}.`);
  const data = await response.json() as { totalResults?: number; vulnerabilities?: Array<{ cve?: Record<string, unknown> }> };
  const candidates = (data.vulnerabilities || []).slice(0, 10).flatMap((wrapper) => {
    const cve = wrapper.cve;
    if (!cve) return [];
    const weaknesses = Array.isArray(cve['weaknesses']) ? cve['weaknesses'] as Array<Record<string, unknown>> : [];
    const references = Array.isArray(cve['references']) ? cve['references'] as Array<Record<string, unknown>> : [];
    return [{
      id: String(cve['id'] || ''), description: englishDescription(cve['descriptions']), published: cve['published'] || '', modified: cve['lastModified'] || '',
      status: cve['vulnStatus'] || '', metric: normalizedNvdMetric(cve['metrics']),
      cweIds: [...new Set(weaknesses.flatMap((weakness) => Array.isArray(weakness['description']) ? (weakness['description'] as Array<Record<string, unknown>>).map((item) => String(item['value'] || '')).filter((value) => /^CWE-\d+$/.test(value)) : []))],
      applicability: nvdCpeRanges(cve['configurations']),
      references: references.slice(0, 12).map((reference) => ({ url: String(reference['url'] || ''), source: String(reference['source'] || ''), tags: Array.isArray(reference['tags']) ? reference['tags'] : [] }))
    }];
  });
  return {
    source: 'NIST National Vulnerability Database CVE API 2.0', query: { product, version }, totalResults: data.totalResults || 0, candidates,
    correlationNote: 'These are search candidates, not confirmed findings. Confirm the observed edition and version against each NVD CPE applicability range before recording a CVE.'
  };
}

export async function queryCwe(cweId: string) {
  const normalized = cweId.trim().toUpperCase();
  const id = normalized.match(/^CWE-(\d{1,5})$/)?.[1];
  if (!id) throw new Error('A valid CWE identifier such as CWE-200 is required.');
  const response = await fetch(`https://cwe-api.mitre.org/api/v1/cwe/weakness/${id}`, {
    signal: AbortSignal.timeout(12_000), headers: { accept: 'application/json', 'user-agent': 'WellguardObserve/0.1' }
  });
  if (!response.ok) throw new Error(`MITRE CWE API returned ${response.status}; the identifier may not represent a mappable weakness.`);
  const data = await response.json() as Record<string, unknown>;
  const weaknesses = Array.isArray(data['Weaknesses']) ? data['Weaknesses'] as Array<Record<string, unknown>> : [];
  const item = weaknesses[0] || data;
  return {
    source: 'MITRE CWE REST API', id: `CWE-${id}`, name: String(item['Name'] || ''), abstraction: String(item['Abstraction'] || ''),
    status: String(item['Status'] || ''), description: String(item['Description'] || '').slice(0, 1_500),
    extendedDescription: String(item['ExtendedDescription'] || '').slice(0, 2_500), likelihoodOfExploit: String(item['LikelihoodOfExploit'] || ''),
    sourceUrl: `https://cwe.mitre.org/data/definitions/${id}.html`
  };
}
