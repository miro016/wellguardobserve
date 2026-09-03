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
