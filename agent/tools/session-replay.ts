import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedHttp } from './http';

/**
 * Authenticated replay for the Unbounded profile.
 * Reuses a session token acquired by the bounded authentication probe
 * during the same investigation to compare anonymous vs authenticated
 * responses on already-discovered paths. This detects broken access
 * control and uncovers authenticated functionality for further review.
 */

const MAX_PATHS = 20;

export async function replayWithAcquiredSession(scope: ScopeGuard, token: string, input: { hostname?: string; port?: number; tls?: boolean; paths?: string[] }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const paths = (input.paths || []).slice(0, MAX_PATHS).map((path) => {
    const normalized = scope.assertPath(path);
    if (/#/.test(normalized)) throw new Error('Replay paths must not contain fragments.');
    return normalized;
  });
  if (!paths.length) throw new Error('Provide previously discovered paths to compare.');
  if (!token) throw new Error('No session token was acquired earlier in this investigation; run the authentication probe first.');

  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;
  const comparisons: Array<{ path: string; anonymousStatus: number; authenticatedStatus: number; authenticatedBytes: number }> = [];
  const suggestedFindings: AgentFinding[] = [];
  const revealedData: string[] = [];

  for (const path of paths) {
    let anonymousStatus = 0;
    try { anonymousStatus = (await requestAuthorizedHttp(scope, { hostname, port, tls, path, maxBodyBytes: 4096 })).status; } catch { /* ignore */ }
    let authenticated;
    try {
      authenticated = await requestAuthorizedHttp(scope, { hostname, port, tls, path, maxBodyBytes: 64 * 1024 }, { bearerToken: token });
    } catch { continue; }
    comparisons.push({ path, anonymousStatus, authenticatedStatus: authenticated.status, authenticatedBytes: Buffer.byteLength(authenticated.raw) });

    if (authenticated.status === 200 && (anonymousStatus === 401 || anonymousStatus === 403)) {
      // Authenticated-only content: characterize shape without retaining bulk data.
      try {
        const parsed = JSON.parse(authenticated.raw) as Record<string, unknown>;
        const data = parsed['data'];
        if (Array.isArray(data) && data.length) {
          const sampleKeys = Object.keys(data[0] as Record<string, unknown>).slice(0, 12);
          revealedData.push(`${path}: ${data.length} records, fields: ${sampleKeys.join(', ')}`);
          const sensitive = sampleKeys.filter((key) => /password|secret|token|card|ssn|address/i.test(key));
          if (sensitive.length) {
            suggestedFindings.push({
              title: 'Authenticated endpoint returns sensitive-looking record fields',
              summary: `After authenticated replay, ${path} returned ${data.length} records including fields named ${sensitive.join(', ')}. Verify that every entry returned is scoped to the caller's account; if not, this is object-level access control failure (IDOR class).`,
              severity: 'medium', confidence: 80, asset,
              evidence: [`Anonymous request: HTTP ${anonymousStatus}. Authenticated request: HTTP 200 with ${data.length} records.`, `Record fields observed: ${sampleKeys.join(', ')}. Values were not retained.`],
              remediation: 'Enforce per-object authorization checks for every record read; never filter only on the client side.',
              sourceUrls: [], cveIds: [], weaknessIds: ['CWE-639'],
              frameworkRefs: frameworkReferences('WSTG-INPV-05'),
              assetKey, relatedAssetKeys: [], relationKey: ''
            });
          }
        }
      } catch { /* not JSON; content characterized by size only */ }
    }
  }

  return {
    pathsCompared: comparisons.length, comparisons, revealedDataShapes: revealedData,
    suggestedFindings,
    note: 'Reused the session token acquired by the authentication probe in this investigation. Anonymous vs authenticated statuses were compared on supplied paths; record values were never persisted.'
  };
}
