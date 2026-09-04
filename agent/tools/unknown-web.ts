import { createHash } from 'node:crypto';
import type { ScopeGuard } from '../security/scope-guard';
import { fingerprintBanner } from '../fingerprints/recog';
import { inspectHttp, requestAuthorizedBytes } from './http';

export async function inspectUnknownWebService(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const root = await inspectHttp(scope, { hostname, port, tls, path: '/' });
  const [serverRecognition, authRecognition, faviconResponse] = await Promise.all([
    root.headers['server'] ? fingerprintBanner('http_server', root.headers['server']) : Promise.resolve(null),
    root.headers['www-authenticate'] ? fingerprintBanner('http_auth', root.headers['www-authenticate']) : Promise.resolve(null),
    requestAuthorizedBytes(scope, { hostname, port, tls, path: '/favicon.ico', maxBodyBytes: 512 * 1024 }).catch((error) => ({ error: error instanceof Error ? error.message : String(error) }))
  ]);

  let favicon: unknown = faviconResponse;
  let faviconRecognition: Awaited<ReturnType<typeof fingerprintBanner>> | null = null;
  if ('body' in faviconResponse) {
    const body = faviconResponse.body;
    const md5 = createHash('md5').update(body).digest('hex');
    const sha256 = createHash('sha256').update(body).digest('hex');
    faviconRecognition = faviconResponse.status === 200 && body.length > 0 ? await fingerprintBanner('favicon', md5) : null;
    favicon = { requestedUrl: faviconResponse.requestedUrl, status: faviconResponse.status, contentType: faviconResponse.headers['content-type'] || '', bytes: body.length, md5, sha256, truncated: faviconResponse.truncated, recognition: faviconRecognition };
  }

  const recogMatches = [serverRecognition, authRecognition, faviconRecognition].flatMap((item) => item?.matches || []);
  const technologyMatches = root.signals.technologies;
  return {
    hostname, port, transport: tls ? 'https' : 'http',
    root: { requestedUrl: root.requestedUrl, status: root.status, title: root.signals.title, server: root.headers['server'] || '', authenticate: root.headers['www-authenticate'] || '', technologies: technologyMatches, fingerprinting: root.fingerprinting },
    favicon,
    hypotheses: [
      ...technologyMatches.map((item) => ({ product: item.name, confidence: 82, evidence: item.evidence, source: 'direct web response' })),
      ...recogMatches
    ].slice(0, 16),
    unresolved: technologyMatches.length === 0 && recogMatches.length === 0,
    note: 'Unknown-service recognition used one root GET, one fixed favicon GET, selected response headers, and the pinned Rapid7 Recog pack. A fingerprint is a hypothesis unless corroborated by another direct marker.'
  };
}
