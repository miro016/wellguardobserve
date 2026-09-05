import { createHash } from 'node:crypto';
import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedMethod } from './http';

/**
 * HTTP method-surface probe for the Unbounded profile.
 * Sends empty requests with a small set of introspection methods and
 * reports which ones the origin accepts.
 */

const METHODS = ['OPTIONS', 'HEAD', 'TRACE', 'PATCH'] as const;

export async function probeHttpMethodSurface(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = scope.assertPath(input.path || '/');
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  const results: Array<{ method: string; status: number; allow: string }> = [];
  const suggestedFindings: AgentFinding[] = [];

  for (const method of METHODS) {
    try {
      const response = await requestAuthorizedMethod(scope, { hostname, port, tls, path }, method);
      results.push({ method, status: response.status, allow: response.headers['allow'] || '' });
      if (method === 'TRACE' && response.status === 200 && /^TRACE|message\/http/i.test(response.headers['content-type'] || response.raw.slice(0, 200))) {
        suggestedFindings.push({
          title: 'HTTP TRACE method is enabled on the origin',
          summary: 'The server echoes TRACE requests. TRACE can expose credentials and headers to client-side script attacks (XST) when combined with other bugs.',
          severity: 'low', confidence: 95, asset,
          evidence: [`TRACE ${path} returned HTTP ${response.status} with an echo-shaped response.`],
          remediation: 'Disable TRACE/TRACK at the web server or the front proxy.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-16'],
          frameworkRefs: frameworkReferences('WSTG-INPV-05'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
    } catch (error) {
      results.push({ method, status: 0, allow: error instanceof Error ? error.message.slice(0, 80) : 'failed' });
    }
  }

  const accepted = results.filter((item) => item.status > 0 && item.status < 400).map((item) => item.method);
  return { endpoint: path, results, acceptedMethods: accepted, suggestedFindings, note: 'Empty-body introspection methods only; no write semantics attempted.' };
}

/**
 * Offline JWT inspection utility. No network traffic.
 */
export function analyzeTokenStructure(input: { token: string }) {
  const token = String(input.token || '').trim();
  const parts = token.split('.');
  if (parts.length < 2 || parts.length > 3) return { isJwt: false, reason: 'Value does not have the JWT shape (header.payload[.signature]).' };
  const decode = (segment: string) => {
    try { return JSON.parse(Buffer.from(segment.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')) as Record<string, unknown>; }
    catch { return null; }
  };
  const header = decode(parts[0]!);
  const payload = decode(parts[1]!);
  if (!header || !payload) return { isJwt: false, reason: 'Segments are not base64url JSON.' };

  const headerJson = JSON.stringify(header).slice(0, 400);
  const payloadJson = JSON.stringify(payload).slice(0, 800);
  const warnings: string[] = [];
  if (String(header['alg']).toLowerCase() === 'none') warnings.push('Algorithm "none": a server accepting this token without a signature permits trivial forgery.');
  if (/^hs/i.test(String(header['alg']))) warnings.push('HMAC-signed token: verify the server rejects tokens with alg switched to none or RS256 and that the HMAC secret is strong and unique.');
  if (!payload['exp']) warnings.push('No exp claim: token validity window may be unbounded.');
  if (String(payload['email'] || payload['sub'] || '').includes('@')) warnings.push('Token embeds identity claims; treat as credentials and avoid logging it.');

  return {
    isJwt: true,
    header: headerJson,
    payload: payloadJson,
    signaturePresent: parts.length === 3 && parts[2]!.length > 0,
    warnings,
    note: 'Offline inspection only. The token was not sent anywhere and signature validity cannot be assessed without the key.'
  };
}

/**
 * Generic credential spray is deliberately absent: identity attacks belong
 * to the bounded authentication tool in the Advanced profile.
 */
export function unboundedToolingNote() {
  return { marker: createHash('sha256').update('wellguard-unbounded').digest('hex').slice(0, 8) };
}
