import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp } from './http';

/**
 * Frontend bundle mining for the Unbounded profile.
 * Fetches same-origin JavaScript referenced by a page and extracts routes,
 * API endpoints, embedded identifiers and client-side configuration.
 */

const MAX_ASSETS = 10;
const ASSET_BYTES = 1600 * 1024;

const ENDPOINT_PATTERN = /["'`](\/(?:api|rest|socket\.io|rpc|graphql|oauth|auth|internal|admin|private|beta|dev|v[0-9]+)[^"'`\\\s]{0,160})["'`]/gi;
const ROUTE_PATTERN = /(?:path|route|url|endpoint)\s*[:=]\s*["'`]([^"'`]{2,180})["'`]/g;
const SECRET_MARKER = /(?:api[_-]?key|secret|token|password|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["'`]([A-Za-z0-9_\-/.+=]{12,})["'`]/gi;
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export async function mineFrontendBundles(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = scope.assertPath(input.path || '/');

  const landing = await requestAuthorizedHttp(scope, { hostname, port, tls, path });
  const assets = [...new Set([...landing.raw.matchAll(/(?:src|href)=["'](\/[^"']+\.m?js)[?#]?[^"']*["']/gi)].map((match) => match[1]!))].slice(0, MAX_ASSETS);

  const endpoints = new Set<string>();
  const routes = new Set<string>();
  const secretMarkers = new Set<string>();
  const emails = new Set<string>();
  const examined: Array<{ asset: string; bytes: number }> = [];

  for (const asset of assets) {
    try {
      const doc = await requestAuthorizedHttp(scope, { hostname, port, tls, path: asset, maxBodyBytes: ASSET_BYTES });
      if (doc.status !== 200) continue;
      examined.push({ asset, bytes: doc.raw.length });
      for (const match of doc.raw.matchAll(ENDPOINT_PATTERN)) endpoints.add(match[1]!);
      for (const match of doc.raw.matchAll(ROUTE_PATTERN)) { if (match[1]!.startsWith('/')) routes.add(match[1]!); }
      for (const match of doc.raw.matchAll(SECRET_MARKER)) secretMarkers.add(`${match[0]!.slice(0, 60)}… (value not retained)`);
      for (const match of doc.raw.matchAll(EMAIL_PATTERN)) { if (!/\.(png|svg|jpg)$/i.test(match[0])) emails.add(match[0].slice(0, 120)); }
    } catch { /* bounded fetch failed; skip asset */ }
  }

  return {
    assetsExamined: examined.length, assets: examined.slice(0, MAX_ASSETS),
    endpoints: [...endpoints].sort().slice(0, 120),
    routes: [...routes].sort().slice(0, 120),
    secretMarkers: [...secretMarkers].slice(0, 20),
    emails: [...emails].sort().slice(0, 40),
    note: 'Extracted from same-origin client bundles only; treat extracted paths as leads and verify with other tools before recording findings.'
  };
}
