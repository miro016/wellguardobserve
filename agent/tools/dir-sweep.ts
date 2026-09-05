import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp } from './http';

/**
 * Bounded common-path sweep for the Unbounded profile.
 * Requests a fixed in-module wordlist of historically sensitive paths and
 * reports status classes and redirects. GET only.
 */

const WORDLIST: string[] = [
  '/admin', '/administrator', '/admin/login', '/admin/dashboard', '/manage', '/management', '/console', '/dashboard',
  '/api', '/api/v1', '/api/v2', '/api/docs', '/api-docs', '/swagger', '/swagger.json', '/openapi.json', '/graphql',
  '/rest', '/rest/user/login', '/rest/admin', '/rest/products/search', '/socket.io',
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

export async function sweepCommonPaths(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; concurrency?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const concurrency = Math.max(2, Math.min(16, Math.floor(input.concurrency || 8)));

  const hits: Array<{ path: string; status: number; location: string; bytes: number }> = [];
  let cursor = 0;
  const worker = async () => {
    while (cursor < WORDLIST.length) {
      const path = WORDLIST[cursor++]!;
      try {
        const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path, maxBodyBytes: 32 * 1024 });
        if (response.status !== 404) {
          hits.push({ path, status: response.status, location: response.headers['location'] || '', bytes: Buffer.byteLength(response.raw) });
        }
      } catch { /* unreachable */ }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));

  const interesting = hits.filter((hit) => hit.status >= 200 && hit.status < 400 && hit.status !== 204);
  return {
    wordsTested: MAX_WORDS, hitsFound: hits.length,
    hits: hits.sort((a, b) => a.status - b.status),
    interesting: interesting.slice(0, 60),
    note: 'Fixed in-module wordlist; GET only. 404s are suppressed. Verify hits with dedicated inspection tools before recording findings.'
  };
}
