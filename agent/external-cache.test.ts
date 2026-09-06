import { afterEach, describe, expect, test } from 'bun:test';
import { cachedExternalFetch, configureExternalCache, type ExternalCacheBackend, type ExternalCacheEntry } from './external-cache';

class MemoryCache implements ExternalCacheBackend {
  rows = new Map<string, ExternalCacheEntry>();
  async get(key: string) { return this.rows.get(key) || null; }
  async put(entry: ExternalCacheEntry) { this.rows.set(entry.cacheKey, { ...entry, id: entry.id || 'memory' }); }
  async touch(entry: ExternalCacheEntry, changes: Partial<ExternalCacheEntry>) { this.rows.set(entry.cacheKey, { ...entry, ...changes }); }
}

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; configureExternalCache(null); });

describe('persistent external resource cache', () => {
  test('reuses a fresh representation without another origin request', async () => {
    const cache = new MemoryCache(); configureExternalCache(cache); let calls = 0;
    globalThis.fetch = (async () => { calls += 1; return new Response('{"ok":true}', { headers: { 'content-type': 'application/json', etag: '"v1"' } }); }) as unknown as typeof fetch;
    const policy = { source: 'test', ttlMs: 60_000 };
    expect(await (await cachedExternalFetch('https://source.example/data', {}, policy)).json()).toEqual({ ok: true });
    expect((await cachedExternalFetch('https://source.example/data', {}, policy)).headers.get('x-wellguard-cache')).toBe('hit');
    expect(calls).toBe(1);
  });

  test('conditionally revalidates a stale ETag and keeps the cached body', async () => {
    const cache = new MemoryCache(); configureExternalCache(cache); const seen: string[] = [];
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      const etag = new Headers(init?.headers).get('if-none-match') || ''; seen.push(etag);
      if (etag) return new Response(null, { status: 304, headers: { 'cache-control': 'max-age=60' } });
      return new Response('retained', { headers: { etag: '"one"' } });
    }) as unknown as typeof fetch;
    const policy = { source: 'test', ttlMs: 1 };
    await cachedExternalFetch('https://source.example/catalogue', {}, policy);
    const row = [...cache.rows.values()][0]!; row.expiresAt = new Date(Date.now() - 1).toISOString(); cache.rows.set(row.cacheKey, row);
    expect(await (await cachedExternalFetch('https://source.example/catalogue', {}, policy)).text()).toBe('retained');
    expect(seen).toEqual(['', '"one"']);
  });

  test('does not retain no-store responses', async () => {
    const cache = new MemoryCache(); configureExternalCache(cache); let calls = 0;
    globalThis.fetch = (async () => { calls += 1; return new Response('private', { headers: { 'cache-control': 'no-store' } }); }) as unknown as typeof fetch;
    await cachedExternalFetch('https://source.example/private', {}, { source: 'test', ttlMs: 60_000 });
    await cachedExternalFetch('https://source.example/private', {}, { source: 'test', ttlMs: 60_000 });
    expect(calls).toBe(2); expect(cache.rows.size).toBe(0);
  });

  test('never caches credential-bearing requests', async () => {
    const cache = new MemoryCache(); configureExternalCache(cache); let calls = 0;
    globalThis.fetch = (async () => { calls += 1; return new Response('account data'); }) as unknown as typeof fetch;
    const init = { headers: { authorization: 'Bearer test-only' } };
    await cachedExternalFetch('https://source.example/account', init, { source: 'test', ttlMs: 60_000 });
    await cachedExternalFetch('https://source.example/account', init, { source: 'test', ttlMs: 60_000 });
    expect(calls).toBe(2); expect(cache.rows.size).toBe(0);
  });
});
