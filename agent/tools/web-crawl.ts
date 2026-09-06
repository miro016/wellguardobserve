import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp } from './http';

const SKIP_PATH = /(?:^|\/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe)(?:[/?#]|$)/i;
const SKIP_EXTENSION = /\.(?:avif|bmp|css|eot|gif|ico|jpe?g|map|mp3|mp4|pdf|png|svg|ttf|webm|webp|woff2?)(?:[?#]|$)/i;

function sameOriginPath(value: string, origin: URL): string | null {
  try {
    const resolved = new URL(value, origin);
    if (resolved.origin !== origin.origin || !['http:', 'https:'].includes(resolved.protocol)) return null;
    if (SKIP_PATH.test(resolved.pathname) || SKIP_EXTENSION.test(resolved.pathname)) return null;
    return `${resolved.pathname || '/'}${resolved.search}`.slice(0, 500);
  } catch { return null; }
}

function attributes(tag: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const match of tag.matchAll(/([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*["']([^"']{0,500})["']/g)) result[match[1]!.toLowerCase()] = match[2]!;
  return result;
}

export function extractCrawlSurface(raw: string, origin: URL) {
  const links = new Set<string>();
  const hashRoutes = new Set<string>();
  for (const match of raw.matchAll(/<(?:a|area|link)[^>]+href\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
    if (match[1]!.startsWith('#/')) hashRoutes.add(match[1]!.slice(1).split('?')[0]!.slice(0, 200));
    const path = sameOriginPath(match[1]!, origin); if (path) links.add(path);
  }
  const forms: Array<{ action: string; method: string; fields: Array<{ name: string; type: string }> }> = [];
  for (const match of raw.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const form = attributes(match[1]!);
    const action = sameOriginPath(form['action'] || origin.pathname, origin) || origin.pathname;
    const fields = [...match[2]!.matchAll(/<(?:input|select|textarea)\b([^>]*)>/gi)].flatMap((field) => {
      const value = attributes(field[1]!); return value['name'] ? [{ name: value['name'].slice(0, 100), type: (value['type'] || 'text').slice(0, 40) }] : [];
    }).slice(0, 30);
    forms.push({ action, method: (form['method'] || 'GET').toUpperCase().slice(0, 10), fields });
  }
  return { links: [...links], hashRoutes: [...hashRoutes], forms: forms.slice(0, 20) };
}

export async function crawlWebApplication(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; startPath?: string; maxPages?: number; maxDepth?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const startPath = scope.assertPath(input.startPath || '/');
  const maxPages = Math.max(2, Math.min(40, Math.floor(input.maxPages || 24)));
  const maxDepth = Math.max(0, Math.min(4, Math.floor(input.maxDepth ?? 2)));
  const origin = new URL(`${tls ? 'https' : 'http'}://${hostname}${port === (tls ? 443 : 80) ? '' : `:${port}`}${startPath}`);
  const queued: Array<{ path: string; depth: number; discoveredFrom: string }> = [{ path: startPath, depth: 0, discoveredFrom: 'start' }];
  const seen = new Set<string>();
  const pages: Array<Record<string, unknown>> = [];
  const forms: Array<Record<string, unknown>> = [];
  const hashRoutes = new Set<string>();

  while (queued.length && pages.length < maxPages) {
    const next = queued.shift()!;
    if (seen.has(next.path)) continue;
    seen.add(next.path);
    try {
      const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path: next.path, maxBodyBytes: 160 * 1024 });
      const contentType = response.headers['content-type'] || '';
      const surface = /html|xhtml/i.test(contentType) || /<html|<form|<a\b/i.test(response.raw) ? extractCrawlSurface(response.raw, new URL(next.path, origin)) : { links: [], hashRoutes: [], forms: [] };
      surface.hashRoutes.forEach((route) => hashRoutes.add(route));
      surface.forms.forEach((form) => forms.push({ page: next.path, ...form }));
      const queryParameters = [...new URL(next.path, origin).searchParams.keys()];
      pages.push({ path: next.path, status: response.status, contentType, bytes: Buffer.byteLength(response.raw), title: response.raw.match(/<title[^>]*>([^<]{0,200})<\/title>/i)?.[1]?.trim() || '', depth: next.depth, discoveredFrom: next.discoveredFrom, queryParameters, linkCount: surface.links.length, formCount: surface.forms.length });
      if (next.depth < maxDepth && response.status >= 200 && response.status < 400) {
        for (const path of surface.links) if (!seen.has(path) && !queued.some((item) => item.path === path)) queued.push({ path, depth: next.depth + 1, discoveredFrom: next.path });
      }
    } catch (error) {
      pages.push({ path: next.path, error: error instanceof Error ? error.message.slice(0, 300) : 'Request failed', depth: next.depth, discoveredFrom: next.discoveredFrom });
    }
  }

  return {
    hostname, port, transport: tls ? 'https' : 'http', requestedPages: pages.length, queuedButNotVisited: queued.length,
    pages, forms: forms.slice(0, 80), hashRoutes: [...hashRoutes].sort().slice(0, 100),
    boundary: 'Same-origin GET crawl only. Logout, deletion, removal, destruction and unsubscribe paths are excluded; forms are inventoried but never submitted.'
  };
}
