import type { ScopeGuard } from '../security/scope-guard';
import { extractSignals, requestAuthorizedHttp, type AuthorizedHttpResponse } from './http';

export interface WordPressPublicUser {
  id: number | null;
  name: string;
  slug: string;
  link: string;
  description: string;
  url: string;
}

function joinPath(basePath: string, suffix: string): string {
  const base = `/${basePath.trim().replace(/^\/+|\/+$/g, '')}`.replace(/^\/$/, '');
  return `${base}/${suffix.replace(/^\/+/, '')}`.replace(/\/+/g, '/');
}

export function normalizeWordPressUsers(value: unknown): WordPressPublicUser[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 100).flatMap((entry) => {
    if (!entry || typeof entry !== 'object') return [];
    const item = entry as Record<string, unknown>;
    return [{
      id: Number.isInteger(item['id']) ? Number(item['id']) : null,
      name: String(item['name'] || '').slice(0, 160), slug: String(item['slug'] || '').slice(0, 160),
      link: String(item['link'] || '').slice(0, 500), description: String(item['description'] || '').slice(0, 500),
      url: String(item['url'] || '').slice(0, 500)
    }];
  });
}

export function extractWordPressComponents(raw: string) {
  const generators = [...raw.matchAll(/<meta\b[^>]*\bname=["']generator["'][^>]*>/gi)].flatMap((match) => {
    const content = match[0].match(/\bcontent=["']([^"']+)["']/i)?.[1];
    return content ? [content.slice(0, 200)] : [];
  });
  const collect = (kind: 'plugins' | 'themes') => {
    const values = new Map<string, Set<string>>();
    const pattern = new RegExp(`/wp-content/${kind}/([a-z0-9_.-]+)/[^\\s"'<>]*`, 'gi');
    for (const match of raw.matchAll(pattern)) {
      const slug = String(match[1] || '').toLowerCase();
      if (!slug) continue;
      const versions = values.get(slug) || new Set<string>();
      const version = match[0].match(/[?&](?:ver|version)=([0-9]+(?:\.[0-9]+){1,3})/i)?.[1];
      if (version) versions.add(version);
      values.set(slug, versions);
    }
    return [...values].slice(0, 60).map(([slug, versions]) => ({ slug, publicAssetVersions: [...versions].slice(0, 10) }));
  };
  return { generators, plugins: collect('plugins'), themes: collect('themes') };
}

async function safeObservation(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean }, path: string): Promise<AuthorizedHttpResponse & { error?: string }> {
  try { return await requestAuthorizedHttp(scope, { ...input, path }); }
  catch (error) { return { requestedUrl: path, status: 0, headers: {} as Record<string, string>, raw: '', truncated: false, error: error instanceof Error ? error.message : String(error) }; }
}

export async function inspectWordPress(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; basePath?: string }) {
  const basePath = scope.assertPath(input.basePath || '/').replace(/\?.*$/, '');
  const paths = {
    root: joinPath(basePath, '/'),
    api: joinPath(basePath, 'wp-json/'),
    users: joinPath(basePath, 'wp-json/wp/v2/users?context=view&per_page=100&_fields=id,name,slug,link,description,url'),
    login: joinPath(basePath, 'wp-login.php'),
    readme: joinPath(basePath, 'readme.html'),
    xmlrpc: joinPath(basePath, 'xmlrpc.php')
  };
  const [root, api, usersResponse, login, readme, xmlrpc] = await Promise.all([
    safeObservation(scope, input, paths.root), safeObservation(scope, input, paths.api), safeObservation(scope, input, paths.users),
    safeObservation(scope, input, paths.login), safeObservation(scope, input, paths.readme), safeObservation(scope, input, paths.xmlrpc)
  ]);
  let apiDocument: Record<string, unknown> = {};
  let users: WordPressPublicUser[] = [];
  try { apiDocument = JSON.parse(api.raw) as Record<string, unknown>; } catch { /* A bounded or non-JSON response is retained as status-only evidence. */ }
  try { users = normalizeWordPressUsers(JSON.parse(usersResponse.raw)); } catch { /* Not a public JSON user collection. */ }
  const rootSignals = extractSignals(root.raw, root.headers);
  const components = extractWordPressComponents(root.raw);
  const readmeVersion = readme.raw.match(/Version\s+([0-9]+(?:\.[0-9]+){1,3})/i)?.[1] || '';
  const generatorVersion = [...components.generators, rootSignals.generator, ...rootSignals.technologies.map((item) => item.name)].join(' ').match(/WordPress\s+([0-9]+(?:\.[0-9]+){1,3})/i)?.[1] || '';
  let namespaces = Array.isArray(apiDocument['namespaces']) ? apiDocument['namespaces'].map(String).slice(0, 100) : [];
  if (!namespaces.length) {
    try { namespaces = JSON.parse(api.raw.match(/"namespaces"\s*:\s*(\[[^\]]*\])/)?.[1] || '[]').map(String).slice(0, 100); } catch { /* Keep the namespace list empty. */ }
  }
  const routeCount = apiDocument['routes'] && typeof apiDocument['routes'] === 'object'
    ? Object.keys(apiDocument['routes'] as Record<string, unknown>).length
    : [...api.raw.matchAll(/"\/(?:[^"\\]|\\.)+"\s*:\s*\{/g)].length;
  const emailLikeNames = users.filter((user) => /\b[^\s@]+@[^\s@]+\.[^\s@]+\b/.test(`${user.name} ${user.slug}`));
  return {
    hostname: scope.assertHostname(input.hostname),
    identified: rootSignals.technologies.some((item) => /^WordPress\b/i.test(item.name)) || /WordPress/i.test(String(root.headers['x-redirect-by'] || '')) || Boolean(apiDocument['namespaces']),
    version: readmeVersion || generatorVersion || null,
    components,
    evidence: {
      root: { url: root.requestedUrl, status: root.status, generator: rootSignals.generator, redirectBy: root.headers['x-redirect-by'] || '' },
      restIndex: { url: api.requestedUrl, status: api.status, namespaces, routeCount, truncated: api.truncated },
      publicUsers: { url: usersResponse.requestedUrl, status: usersResponse.status, totalHeader: usersResponse.headers['x-wp-total'] || '', users },
      login: { url: login.requestedUrl, status: login.status, title: extractSignals(login.raw, login.headers).title },
      readme: { url: readme.requestedUrl, status: readme.status, version: readmeVersion || null },
      xmlrpc: { url: xmlrpc.requestedUrl, status: xmlrpc.status, allow: xmlrpc.headers['allow'] || '' }
    },
    publicUserCount: users.length,
    emailLikePublicNames: emailLikeNames.map((user) => ({ id: user.id, name: user.name, slug: user.slug })),
    note: 'Only anonymous GET requests and WordPress REST view context were used. Public REST users are not assumed to be administrators because roles and private fields require authenticated edit context.'
  };
}
