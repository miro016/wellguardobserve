import { createHash } from 'node:crypto';
import type PocketBase from 'pocketbase';

export interface ExternalCacheEntry {
  id?: string;
  cacheKey: string;
  source: string;
  method: string;
  url: string;
  statusCode: number;
  contentType: string;
  body: string;
  etag: string;
  lastModified: string;
  cacheControl: string;
  expiresAt: string;
  fetchedAt: string;
  lastAccessedAt: string;
  hitCount: number;
  revalidationCount: number;
  staleUseCount: number;
  originRequestCount: number;
}

export interface ExternalCacheBackend {
  get(cacheKey: string): Promise<ExternalCacheEntry | null>;
  put(entry: ExternalCacheEntry): Promise<void>;
  touch(entry: ExternalCacheEntry, changes: Partial<ExternalCacheEntry>): Promise<void>;
}

export interface CachePolicy {
  source: string;
  ttlMs: number;
  maxBodyBytes?: number;
  staleIfErrorMs?: number;
}

export interface CacheTelemetry {
  hits: number;
  misses: number;
  revalidations: number;
  staleUses: number;
  originRequests: number;
  skipped: number;
  bySource: Record<string, { hits: number; misses: number; originRequests: number }>;
}

let backend: ExternalCacheBackend | null = null;
let telemetry = emptyTelemetry();
const pending = new Map<string, Promise<Response>>();

function emptyTelemetry(): CacheTelemetry {
  return { hits: 0, misses: 0, revalidations: 0, staleUses: 0, originRequests: 0, skipped: 0, bySource: {} };
}

function metric(source: string, name: 'hits' | 'misses' | 'originRequests'): void {
  telemetry[name] += 1;
  const row = telemetry.bySource[source] ||= { hits: 0, misses: 0, originRequests: 0 };
  row[name] += 1;
}

export function configureExternalCache(value: ExternalCacheBackend | null): void { backend = value; }
export function resetCacheTelemetry(): void { telemetry = emptyTelemetry(); }
export function cacheTelemetrySnapshot(): CacheTelemetry { return structuredClone(telemetry); }

function responseFrom(entry: ExternalCacheEntry, cacheState: string): Response {
  return new Response(entry.body, {
    status: entry.statusCode,
    headers: {
      'content-type': entry.contentType || 'application/octet-stream',
      'x-wellguard-cache': cacheState,
      ...(entry.etag ? { etag: entry.etag } : {}),
      ...(entry.lastModified ? { 'last-modified': entry.lastModified } : {})
    }
  });
}

function requestKey(url: string, init: RequestInit): string {
  const method = String(init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  const representation = [headers.get('accept') || '', headers.get('x-github-api-version') || ''].join('\n');
  const body = typeof init.body === 'string' ? init.body : '';
  return createHash('sha256').update([method, url, representation, body].join('\n')).digest('hex');
}

function maxAge(cacheControl: string): number | null {
  const value = cacheControl.match(/(?:^|,)\s*max-age=(\d+)/i)?.[1];
  return value ? Number(value) * 1_000 : null;
}

function expiry(now: number, cacheControl: string, ttlMs: number): string {
  if (/(?:^|,)\s*no-cache(?:\s|,|$)/i.test(cacheControl)) return new Date(now).toISOString();
  const advertised = maxAge(cacheControl);
  const boundedTtl = advertised == null ? ttlMs : Math.min(ttlMs, advertised);
  return new Date(now + Math.max(0, boundedTtl)).toISOString();
}

function mayStore(response: Response, cacheControl: string): boolean {
  return response.ok && !response.headers.has('set-cookie') && !/(?:^|,)\s*(?:no-store|private)(?:\s|,|$)/i.test(cacheControl);
}

function mayUseStale(entry: ExternalCacheEntry, policy: CachePolicy, now: number): boolean {
  if (!policy.staleIfErrorMs || /(?:^|,)\s*(?:must-revalidate|no-cache|no-store)(?:\s|,|$)/i.test(entry.cacheControl)) return false;
  return now - Date.parse(entry.expiresAt) <= policy.staleIfErrorMs;
}

export async function cachedExternalFetch(url: string, init: RequestInit = {}, policy: CachePolicy): Promise<Response> {
  const parsed = new URL(url);
  const method = String(init.method || 'GET').toUpperCase();
  if (parsed.protocol !== 'https:' || !['GET', 'POST'].includes(method)) throw new Error('External cache only permits HTTPS GET and POST requests.');
  const requestHeaders = new Headers(init.headers);
  if (requestHeaders.has('authorization') || requestHeaders.has('cookie')) { telemetry.skipped += 1; metric(policy.source, 'originRequests'); return fetch(url, init); }
  if (!backend) { telemetry.skipped += 1; metric(policy.source, 'originRequests'); return fetch(url, init); }
  const cacheKey = requestKey(url, init);
  const running = pending.get(cacheKey);
  if (running) return (await running).clone();

  const operation = (async (): Promise<Response> => {
    const now = Date.now();
    let entry: ExternalCacheEntry | null = null;
    try { entry = await backend!.get(cacheKey); }
    catch (error) { console.warn(`External cache lookup failed for ${policy.source}:`, error); telemetry.skipped += 1; }
    if (entry && Date.parse(entry.expiresAt) > now) {
      metric(policy.source, 'hits');
      void backend!.touch(entry, { lastAccessedAt: new Date(now).toISOString(), hitCount: entry.hitCount + 1 }).catch(() => {});
      return responseFrom(entry, 'hit');
    }
    metric(policy.source, 'misses');
    const headers = new Headers(init.headers);
    if (entry?.etag) headers.set('if-none-match', entry.etag);
    else if (entry?.lastModified) headers.set('if-modified-since', entry.lastModified);
    metric(policy.source, 'originRequests');
    let response: Response;
    try {
      response = await fetch(url, { ...init, method, headers });
    } catch (error) {
      if (entry && mayUseStale(entry, policy, now)) {
        telemetry.staleUses += 1;
        await backend!.touch(entry, { lastAccessedAt: new Date(now).toISOString(), staleUseCount: entry.staleUseCount + 1 }).catch(() => {});
        return responseFrom(entry, 'stale-if-error');
      }
      throw error;
    }
    if (response.status === 304 && entry) {
      telemetry.revalidations += 1;
      const cacheControl = response.headers.get('cache-control') || entry.cacheControl;
      await backend!.touch(entry, {
        cacheControl, expiresAt: expiry(now, cacheControl, policy.ttlMs), fetchedAt: new Date(now).toISOString(),
        lastAccessedAt: new Date(now).toISOString(), revalidationCount: entry.revalidationCount + 1,
        originRequestCount: entry.originRequestCount + 1
      }).catch((error) => console.warn(`External cache revalidation write failed for ${policy.source}:`, error));
      return responseFrom({ ...entry, cacheControl, expiresAt: expiry(now, cacheControl, policy.ttlMs) }, 'revalidated');
    }
    const cacheControl = response.headers.get('cache-control') || '';
    if (!mayStore(response, cacheControl)) return response;
    const body = await response.clone().text();
    const maxBodyBytes = policy.maxBodyBytes ?? 6_000_000;
    if (Buffer.byteLength(body) > maxBodyBytes) { telemetry.skipped += 1; return response; }
    const stored: ExternalCacheEntry = {
      id: entry?.id, cacheKey, source: policy.source, method, url, statusCode: response.status,
      contentType: response.headers.get('content-type') || '', body,
      etag: response.headers.get('etag') || '', lastModified: response.headers.get('last-modified') || '', cacheControl,
      expiresAt: expiry(now, cacheControl, policy.ttlMs), fetchedAt: new Date(now).toISOString(), lastAccessedAt: new Date(now).toISOString(),
      hitCount: entry?.hitCount || 0, revalidationCount: entry?.revalidationCount || 0, staleUseCount: entry?.staleUseCount || 0,
      originRequestCount: (entry?.originRequestCount || 0) + 1
    };
    await backend!.put(stored).catch((error) => console.warn(`External cache write failed for ${policy.source}:`, error));
    return response;
  })();
  pending.set(cacheKey, operation);
  try { return (await operation).clone(); }
  finally { pending.delete(cacheKey); }
}

export class PocketBaseExternalCache implements ExternalCacheBackend {
  constructor(private readonly client: PocketBase) {}
  async get(cacheKey: string): Promise<ExternalCacheEntry | null> {
    try {
      const row = await this.client.collection('externalSourceCache').getFirstListItem(this.client.filter('cacheKey = {:cacheKey}', { cacheKey }));
      return { id: row.id, cacheKey: String(row['cacheKey']), source: String(row['source']), method: String(row['method']), url: String(row['url']), statusCode: Number(row['statusCode']), contentType: String(row['contentType'] || ''), body: String(row['body'] || ''), etag: String(row['etag'] || ''), lastModified: String(row['lastModified'] || ''), cacheControl: String(row['cacheControl'] || ''), expiresAt: String(row['expiresAt']), fetchedAt: String(row['fetchedAt']), lastAccessedAt: String(row['lastAccessedAt']), hitCount: Number(row['hitCount']) || 0, revalidationCount: Number(row['revalidationCount']) || 0, staleUseCount: Number(row['staleUseCount']) || 0, originRequestCount: Number(row['originRequestCount']) || 0 };
    } catch (error: unknown) { if ((error as { status?: number })?.status === 404) return null; throw error; }
  }
  async put(entry: ExternalCacheEntry): Promise<void> {
    const { id, ...payload } = entry;
    if (id) await this.client.collection('externalSourceCache').update(id, payload);
    else {
      try { await this.client.collection('externalSourceCache').create(payload); }
      catch (error: unknown) {
        if ((error as { status?: number })?.status !== 400) throw error;
        const current = await this.get(entry.cacheKey);
        if (!current?.id) throw error;
        await this.client.collection('externalSourceCache').update(current.id, payload);
      }
    }
  }
  async touch(entry: ExternalCacheEntry, changes: Partial<ExternalCacheEntry>): Promise<void> {
    if (entry.id) await this.client.collection('externalSourceCache').update(entry.id, changes);
  }
}
