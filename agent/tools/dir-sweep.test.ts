import { describe, expect, test } from 'bun:test';
import { assessPathResponse, bodySimilarity } from './dir-sweep';
import type { AuthorizedHttpResponse } from './http';

function response(path: string, raw: string, contentType = 'text/html', status = 200, location = ''): AuthorizedHttpResponse {
  return { requestedUrl: `https://example.test${path}`, status, raw, truncated: false, cookies: [], headers: { 'content-type': contentType, ...(location ? { location } : {}) } };
}

describe('common-path content validation', () => {
  const root = response('/', '<!doctype html><html><head><title>Portal</title><script src="/main.abc123.js"></script></head><body><app-root></app-root></body></html>');

  test('rejects an exact SPA root returned with HTTP 200 for a file candidate', () => {
    const assessed = assessPathResponse('/config.json', response('/config.json', root.raw), root);
    expect(assessed).toMatchObject({ contentValidated: false, classification: 'root-fallback', similarityToRoot: 1 });
  });

  test('rejects a slightly dynamic root representation', () => {
    const dynamic = response('/.env', root.raw.replace('abc123', 'def456'));
    expect(bodySimilarity(dynamic.raw, root.raw)).toBeGreaterThanOrEqual(0.94);
    expect(assessPathResponse('/.env', dynamic, root).classification).toBe('root-fallback');
  });

  test('rejects distinct HTML for a JSON file but accepts plausible JSON content', () => {
    expect(assessPathResponse('/package.json', response('/package.json', '<html><title>Not found</title></html>'), root).classification).toBe('unexpected-html-file');
    expect(assessPathResponse('/package.json', response('/package.json', '{"name":"public-package"}', 'application/json'), root)).toMatchObject({ contentValidated: true, classification: 'distinct-content' });
  });

  test('does not treat a redirect to root as file presence', () => {
    expect(assessPathResponse('/.git/HEAD', response('/.git/HEAD', '', 'text/plain', 302, '/'), root).classification).toBe('redirect-to-root');
  });
});
