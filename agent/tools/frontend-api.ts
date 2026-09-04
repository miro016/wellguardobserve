import type { ScopeGuard } from '../security/scope-guard';
import { extractSignals, requestAuthorizedHttp, type TechnologySignal } from './http';

const MAX_BUNDLES = 12;
const MAX_BUNDLE_BYTES = 1280 * 1024;
const MAX_ENDPOINTS = 40;

export interface FrontendApiCandidate {
  value: string;
  kind: 'same-origin path' | 'absolute URL' | 'client route pattern';
  evidence: string;
}

export interface FrontendBackendSignal {
  name: string;
  confidence: number;
  evidence: string;
}

function safeUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch { return ''; }
}

function normalizePath(value: string): string {
  const decoded = value.replace(/\\\//g, '/').replace(/\\u002f/gi, '/');
  const withoutTemplate = decoded.replace(/\{\{[^}]*\}\}|\$\{[^}]*\}/g, '{dynamic}');
  const bounded = (withoutTemplate.split(/["'`\s<>]/)[0]?.replace(/[),.;]+$/, '') || '').replace(/\{+$/, '{dynamic}');
  if (!bounded.startsWith('/') || bounded.startsWith('//') || bounded.length > 500) return '';
  if (/^\/api\/(?:forms|core|common|router)(?:\/|$)/i.test(bounded)) return '';
  return bounded;
}

function addTechnology(list: FrontendBackendSignal[], signal: FrontendBackendSignal): void {
  const existing = list.find((item) => item.name.toLowerCase() === signal.name.toLowerCase());
  if (!existing) list.push(signal);
  else if (signal.confidence > existing.confidence) Object.assign(existing, signal);
}

export function analyzeFrontendBundles(documents: Array<{ url: string; raw: string }>): {
  endpoints: FrontendApiCandidate[];
  backendTechnologies: FrontendBackendSignal[];
} {
  const endpointMap = new Map<string, FrontendApiCandidate>();
  const backendTechnologies: FrontendBackendSignal[] = [];
  const addEndpoint = (candidate: FrontendApiCandidate) => {
    if (!candidate.value || endpointMap.has(candidate.value) || endpointMap.size >= MAX_ENDPOINTS) return;
    endpointMap.set(candidate.value, candidate);
  };

  for (const document of documents) {
    const raw = document.raw.replace(/\\u002f/gi, '/').replace(/\\\//g, '/');
    const source = new URL(document.url).pathname.split('/').at(-1) || document.url;
    const containsPocketBaseSdk = /node_modules\/pocketbase\/|\bPocketBase\s*\(|\/api\/collections\//i.test(raw);
    if (containsPocketBaseSdk) {
      addTechnology(backendTechnologies, { name: 'PocketBase client/API', confidence: 88, evidence: `${source} contains the PocketBase SDK or its /api/collections request construction.` });
    }
    if (/@supabase\/supabase-js|\bcreateClient\([^)]*supabase/i.test(raw)) {
      addTechnology(backendTechnologies, { name: 'Supabase client', confidence: 82, evidence: `${source} contains a Supabase JavaScript client marker.` });
    }
    if (/firebase\/app|initializeApp\([^)]*firebaseConfig/i.test(raw)) {
      addTechnology(backendTechnologies, { name: 'Firebase client', confidence: 82, evidence: `${source} contains a Firebase client marker.` });
    }
    if (/ApolloClient|graphql-tag|\/graphql\b/i.test(raw)) {
      addTechnology(backendTechnologies, { name: 'GraphQL client/API', confidence: 72, evidence: `${source} contains a GraphQL client or endpoint marker.` });
    }

    for (const match of raw.matchAll(/https?:\/\/[^"'`\s<>\\)]+/gi)) {
      const value = safeUrl(match[0]);
      if (!value || /(?:angular|mozilla|w3\.org|whatwg|tc39|github\.com|hammerjs|cloudflare\.com\/turnstile)/i.test(value)) continue;
      if (!/(?:\/api(?:\/|$)|graphql|swagger|openapi|\/v\d+(?:\/|$))/i.test(value)) continue;
      addEndpoint({ value, kind: 'absolute URL', evidence: `Public JavaScript bundle ${source} contains this API-shaped URL.` });
    }
    if (containsPocketBaseSdk) continue;
    for (const match of raw.matchAll(/\/(?:api|graphql|swagger|openapi|v\d+)(?:\/[A-Za-z0-9._~!$&()*+,;=:@%{}-]*)*/g)) {
      const value = normalizePath(match[0]);
      if (!value || /^\/api\/?$/i.test(value) || /\.m?js$/i.test(value)) continue;
      const genericSdkRoute = /^\/api\/(?:collections|files)\/?$/i.test(value);
      addEndpoint({ value, kind: genericSdkRoute ? 'client route pattern' : 'same-origin path', evidence: `Public JavaScript bundle ${source} contains this route${genericSdkRoute ? ' constructor' : ''}.` });
    }
  }
  const endpoints = [...endpointMap.values()].filter((item, _index, all) => !(item.value.endsWith('/') && all.some((other) => other.value !== item.value && other.value.startsWith(item.value))));
  return { endpoints, backendTechnologies };
}

function scriptPath(value: string, base: URL): string {
  try {
    const url = new URL(value, base);
    if (url.origin !== base.origin || !/\.m?js(?:$|\?)/i.test(url.pathname + url.search)) return '';
    return `${url.pathname}${url.search}`;
  } catch { return ''; }
}

export async function inspectFrontendApi(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const root = await requestAuthorizedHttp(scope, { hostname, port, tls, path: input.path || '/' });
  const rootUrl = new URL(root.requestedUrl);
  const rootSignals = extractSignals(root.raw, root.headers);
  const queue = rootSignals.assets.map((asset) => scriptPath(asset, rootUrl)).filter(Boolean);
  const seen = new Set<string>();
  const documents: Array<{ url: string; raw: string }> = [];
  const bundles: Array<{ url: string; status: number; bytesAnalyzed: number; truncated: boolean }> = [];

  while (queue.length && bundles.length < MAX_BUNDLES) {
    const path = queue.shift()!;
    if (seen.has(path)) continue;
    seen.add(path);
    try {
      const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path, maxBodyBytes: MAX_BUNDLE_BYTES });
      if (response.status < 200 || response.status >= 400 || !/(?:javascript|ecmascript|text\/plain)/i.test(response.headers['content-type'] || '')) continue;
      documents.push({ url: response.requestedUrl, raw: response.raw });
      bundles.push({ url: response.requestedUrl, status: response.status, bytesAnalyzed: Buffer.byteLength(response.raw), truncated: response.truncated });
      for (const match of response.raw.matchAll(/["'`](\.?\/?(?:chunk-)?[A-Za-z0-9._/-]+\.m?js(?:\?[^"'`]*)?)["'`]/g)) {
        const nested = scriptPath(match[1]!, rootUrl);
        if (nested && !seen.has(nested)) queue.push(nested);
      }
    } catch { /* One unavailable public bundle does not invalidate the retained ones. */ }
  }

  const analysis = analyzeFrontendBundles(documents);
  const backendTechnologies = [...analysis.backendTechnologies];
  const probes: Array<{ url: string; status: number; contentType: string; observation: string }> = [];
  if (backendTechnologies.some((item) => item.name === 'PocketBase client/API')) {
    try {
      const health = await requestAuthorizedHttp(scope, { hostname, port, tls, path: '/api/health' });
      let observation = 'The response did not match a specific health document.';
      try {
        const body = JSON.parse(health.raw) as Record<string, unknown>;
        if (health.status === 200 && Number(body['code']) === 200 && /api is healthy/i.test(String(body['message'] || ''))) {
          observation = 'PocketBase-compatible public API health document observed.';
          addTechnology(backendTechnologies, { name: 'PocketBase API', confidence: 100, evidence: 'GET /api/health returned the PocketBase-compatible code/message/data health document.' });
        }
      } catch { /* Health response remains a status-only observation. */ }
      probes.push({ url: health.requestedUrl, status: health.status, contentType: health.headers['content-type'] || '', observation });
    } catch (error) {
      probes.push({ url: `${rootUrl.origin}/api/health`, status: 0, contentType: '', observation: error instanceof Error ? error.message : String(error) });
    }
  }

  const frontendTechnologies: TechnologySignal[] = rootSignals.technologies;
  return {
    hostname, page: root.requestedUrl, status: root.status, frontendTechnologies,
    bundles, endpoints: analysis.endpoints, backendTechnologies, probes,
    limits: { bundleRequests: bundles.length, maximumBundleRequests: MAX_BUNDLES, maximumEndpointsRetained: MAX_ENDPOINTS, maximumBytesPerResponse: MAX_BUNDLE_BYTES },
    note: 'Only public HTML and same-origin JavaScript bundles were read. One fixed same-origin health route is requested only when a shipped PocketBase client marker is present. No discovered business endpoint is invoked, no credentials are used, and query values are discarded.'
  };
}
