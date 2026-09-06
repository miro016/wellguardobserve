import { createHash } from 'node:crypto';
import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp, type AuthorizedHttpResponse } from './http';

/**
 * Bounded common-path sweep for the Unbounded profile.
 * Requests a fixed in-module wordlist of historically sensitive paths and
 * reports status classes and redirects. GET only.
 */

const WORDLIST: string[] = [
  '/admin', '/administrator', '/admin/login', '/admin/dashboard', '/manage', '/management', '/console', '/dashboard',
  '/api', '/api/v1', '/api/v2', '/api/docs', '/api-docs', '/swagger', '/swagger.json', '/openapi.json', '/graphql',
  '/rest', '/rest/v1', '/rest/docs', '/api/session', '/api/login', '/socket.io',
  '/.git/HEAD', '/.git/config', '/.env', '/.env.local', '/.aws/credentials', '/.npmrc', '/.docker/config.json',
  '/config', '/config.json', '/configuration', '/settings', '/setup', '/install', '/debug', '/trace', '/status', '/health', '/healthz', '/readyz', '/livez',
  '/metrics', '/info', '/actuator', '/actuator/health', '/actuator/env', '/actuator/heapdump',
  '/server-status', '/server-info', '/phpinfo.php', '/elmah.axd', '/trace.axd', '/web-console', '/_profiler',
  '/backup', '/backup.zip', '/backup.tar.gz', '/db.sql', '/dump.sql', '/database.sql',
  '/wp-login.php', '/wp-admin', '/wp-json', '/xmlrpc.php',
  '/ftp', '/files', '/uploads', '/download', '/logs', '/log', '/tmp', '/temp',
  '/sitemap.xml', '/robots.txt', '/security.txt', '/.well-known/security.txt', '/humans.txt',
  '/package.json', '/composer.json', '/yarn.lock', '/package-lock.json', '/Dockerfile', '/docker-compose.yml',
  '/oauth', '/auth', '/login', '/signin', '/sso', '/token', '/callback',
  '/internal', '/private', '/secret', '/test', '/staging', '/dev', '/beta', '/old', '/new',
  '/prometheus', '/grafana', '/kibana', '/jenkins', '/git', '/gitlab', '/traefik', '/portainer'
];

const MAX_WORDS = WORDLIST.length;

export type PathResponseClassification = 'distinct-content' | 'root-fallback' | 'unexpected-html-file' | 'redirect-to-root' | 'redirect-response' | 'access-controlled' | 'non-success';

export interface PathResponseAssessment {
  contentValidated: boolean;
  classification: PathResponseClassification;
  similarityToRoot: number;
  explanation: string;
}

function contentType(response: AuthorizedHttpResponse): string {
  return (response.headers['content-type'] || '').split(';')[0]!.trim().toLowerCase();
}

function htmlResponse(response: AuthorizedHttpResponse): boolean {
  return /(?:text\/html|application\/xhtml\+xml)/i.test(contentType(response)) || /<!doctype\s+html|<html(?:\s|>)/i.test(response.raw.slice(0, 2_000));
}

function expectedNonHtmlFile(path: string): boolean {
  const pathname = path.split(/[?#]/, 1)[0]!.toLowerCase();
  const basename = pathname.split('/').at(-1) || '';
  return basename === 'dockerfile' || basename === '.npmrc' || basename === '.env' || basename.startsWith('.env.')
    || /(?:^|\/)\.git\/(?:head|config)$/.test(pathname)
    || /\.(?:json|ya?ml|toml|ini|conf|config|lock|sql|txt|xml|log|zip|gz|tgz|pem|key|crt)$/.test(pathname);
}

function normalizedTokens(raw: string): Set<string> {
  const normalized = raw.toLowerCase()
    .replace(/([._-])[a-f0-9]{6,}(?=\.(?:m?js|css)\b)/g, '$1asset-hash')
    .replace(/\b[0-9a-f]{16,}\b/g, ' dynamic-token ')
    .replace(/\b\d{4}-\d{2}-\d{2}t[\d:.+-]+z?\b/g, ' dynamic-time ')
    .replace(/\b\d{10,13}\b/g, ' dynamic-number ')
    .replace(/\s+/g, ' ');
  return new Set(normalized.match(/[a-z][a-z0-9_.:/-]{2,}/g)?.slice(0, 8_000) || []);
}

export function bodySimilarity(left: string, right: string): number {
  if (left === right) return 1;
  const a = normalizedTokens(left); const b = normalizedTokens(right);
  if (!a.size || !b.size) return 0;
  let overlap = 0;
  for (const token of a) if (b.has(token)) overlap += 1;
  return Math.round((2 * overlap / (a.size + b.size)) * 1_000) / 1_000;
}

function redirectIsRoot(response: AuthorizedHttpResponse): boolean {
  const location = response.headers['location'];
  if (!location) return false;
  try {
    const destination = new URL(location, response.requestedUrl);
    return destination.pathname === '/' && !destination.search && !destination.hash;
  } catch { return location === '/'; }
}

export function assessPathResponse(path: string, response: AuthorizedHttpResponse, root?: AuthorizedHttpResponse): PathResponseAssessment {
  const similarityToRoot = root ? bodySimilarity(response.raw, root.raw) : 0;
  const sameRootRepresentation = Boolean(root && response.status === root.status && (
    createHash('sha256').update(response.raw).digest('hex') === createHash('sha256').update(root.raw).digest('hex')
    || (htmlResponse(response) && htmlResponse(root) && similarityToRoot >= 0.94)
  ));
  if (sameRootRepresentation) return { contentValidated: false, classification: 'root-fallback', similarityToRoot, explanation: 'The response body matches the root application representation, so HTTP success does not establish this path.' };
  if (response.status >= 300 && response.status < 400) {
    if (redirectIsRoot(response)) return { contentValidated: false, classification: 'redirect-to-root', similarityToRoot, explanation: 'The server redirected this candidate to the root page.' };
    return { contentValidated: false, classification: 'redirect-response', similarityToRoot, explanation: 'A redirect was observed, but no candidate document body was returned.' };
  }
  if ((response.status === 401 || response.status === 403)) return { contentValidated: false, classification: 'access-controlled', similarityToRoot, explanation: 'Access control responded, but that alone does not prove the requested resource exists.' };
  if (response.status < 200 || response.status >= 300) return { contentValidated: false, classification: 'non-success', similarityToRoot, explanation: `HTTP ${response.status} did not return a successful document response.` };
  if (expectedNonHtmlFile(path) && htmlResponse(response)) return { contentValidated: false, classification: 'unexpected-html-file', similarityToRoot, explanation: 'This file-shaped candidate returned HTML rather than the expected data or text representation.' };
  return { contentValidated: true, classification: 'distinct-content', similarityToRoot, explanation: 'A body distinct from the root representation was read and its media type is plausible for this candidate.' };
}

function redactedPreview(raw: string): string {
  return raw
    .replace(/-----BEGIN [^-\r\n]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [^-\r\n]{0,40}PRIVATE KEY-----|$)/gi, '[private key redacted]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[aws access key redacted]')
    .replace(/(https?:\/\/[^\s:/@]+:)[^\s/@]+@/gi, '$1[credential redacted]@')
    .replace(/^([A-Za-z_][A-Za-z0-9_]{1,80}\s*=\s*).+$/gm, '$1[redacted]')
    .replace(/((?:password|passwd|secret|token|api[_-]?key|authorization)\s*["']?\s*[:=]\s*["']?)[^\s,"'<>}]{1,300}/gi, '$1[redacted]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/\s+/g, ' ').trim().slice(0, 500);
}

export async function sweepCommonPaths(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; concurrency?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const concurrency = Math.max(2, Math.min(16, Math.floor(input.concurrency || 8)));

  let root: AuthorizedHttpResponse | undefined;
  try { root = await requestAuthorizedHttp(scope, { hostname, port, tls, path: '/', maxBodyBytes: 32 * 1024 }); } catch { /* Candidate bodies still receive type/signature validation. */ }
  const hits: Array<{ path: string; status: number; location: string; bytes: number; contentType: string; bodySha256: string; title: string; bodyPreview: string; contentValidated: boolean; classification: PathResponseClassification; similarityToRoot: number; explanation: string }> = [];
  let cursor = 0;
  const worker = async () => {
    while (cursor < WORDLIST.length) {
      const path = WORDLIST[cursor++]!;
      try {
        const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path, maxBodyBytes: 32 * 1024 });
        if (response.status !== 404) {
          const assessment = assessPathResponse(path, response, root);
          hits.push({
            path, status: response.status, location: response.headers['location'] || '', bytes: Buffer.byteLength(response.raw), contentType: contentType(response),
            bodySha256: createHash('sha256').update(response.raw).digest('hex'), title: response.raw.match(/<title[^>]*>([^<]{0,200})<\/title>/i)?.[1]?.trim() || '',
            bodyPreview: redactedPreview(response.raw), ...assessment
          });
        }
      } catch { /* unreachable */ }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));

  const interesting = hits.filter((hit) => hit.contentValidated);
  return {
    wordsTested: MAX_WORDS, requestsMade: MAX_WORDS + (root ? 1 : 0), hitsFound: hits.length, validatedHits: interesting.length,
    rootBaseline: root ? { status: root.status, contentType: contentType(root), bytes: Buffer.byteLength(root.raw), bodySha256: createHash('sha256').update(root.raw).digest('hex') } : null,
    hits: hits.sort((a, b) => a.status - b.status),
    interesting: interesting.slice(0, 60),
    note: 'Fixed in-module wordlist; GET only. Every non-404 candidate body is read within the response cap. HTTP 200 alone is never a hit: root/SPA fallbacks, redirects and HTML returned for data-file candidates are classified and excluded from validatedHits. Previews are bounded and secret-shaped values are redacted.'
  };
}
