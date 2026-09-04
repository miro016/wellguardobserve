import type { ScopeGuard } from '../security/scope-guard';
import { extractSignals, requestAuthorizedHttp } from './http';

export const PUBLIC_METADATA_PATHS = [
  '/.well-known/security.txt', '/robots.txt', '/sitemap.xml', '/openapi.json', '/swagger.json', '/api-docs', '/graphql', '/actuator/health'
] as const;

export type PublicMetadataPath = typeof PUBLIC_METADATA_PATHS[number];

function summarizeJson(raw: string): Record<string, unknown> | null {
  try {
    const document = JSON.parse(raw) as Record<string, unknown>;
    const info = document['info'] && typeof document['info'] === 'object' ? document['info'] as Record<string, unknown> : {};
    const paths = document['paths'] && typeof document['paths'] === 'object' ? Object.keys(document['paths'] as Record<string, unknown>) : [];
    const servers = Array.isArray(document['servers']) ? document['servers'].slice(0, 20).flatMap((server) => server && typeof server === 'object' ? [String((server as Record<string, unknown>)['url'] || '')].filter(Boolean) : []) : [];
    return {
      topLevelKeys: Object.keys(document).slice(0, 40), specification: document['openapi'] || document['swagger'] || '',
      title: String(info['title'] || '').slice(0, 200), version: String(info['version'] || '').slice(0, 100),
      documentedPathCount: paths.length, documentedPathSamples: paths.slice(0, 30), servers
    };
  } catch { return null; }
}

export async function inspectPublicMetadata(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; paths?: PublicMetadataPath[] }) {
  const paths = [...new Set(input.paths?.length ? input.paths : PUBLIC_METADATA_PATHS)].slice(0, 8);
  const observations = await Promise.all(paths.map(async (path) => {
    let response;
    try { response = await requestAuthorizedHttp(scope, { hostname: input.hostname, port: input.port, tls: input.tls, path }); }
    catch (error) { return { path, requestedUrl: path, status: 0, error: error instanceof Error ? error.message : String(error) }; }
    const signals = extractSignals(response.raw, response.headers);
    const json = summarizeJson(response.raw);
    const contacts = path === '/.well-known/security.txt' ? [...new Set(response.raw.match(/^(?:Contact|Encryption|Acknowledgments|Policy):\s*([^\r\n]+)/gim) || [])].slice(0, 30) : [];
    const robotsRules = path === '/robots.txt' ? response.raw.split(/\r?\n/).filter((line) => /^(?:allow|disallow|sitemap):/i.test(line.trim())).slice(0, 60) : [];
    return {
      path, requestedUrl: response.requestedUrl, status: response.status, contentType: response.headers['content-type'] || '',
      location: response.headers['location'] || '', title: signals.title, technologies: signals.technologies,
      json, contacts, robotsRules, textSample: json ? '' : signals.textSample.slice(0, 500), truncated: response.truncated
    };
  }));
  return {
    hostname: scope.assertHostname(input.hostname), observations,
    note: 'Only the selected fixed metadata paths were requested with GET. A documented route name is evidence of published API metadata, not permission to invoke that route.'
  };
}
