import { createHash } from 'node:crypto';
import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedHttp } from './http';

/**
 * Bounded encoding/filter-bypass review for the Advanced profile.
 * The model supplies paths already discovered (directory listings, file
 * references). This module retries them with a fixed set of encoding
 * variants and compares success signatures. Nothing is written or decoded.
 */

const MAX_PATHS = 8;
const FIXTURE_MARKER = /(?:error|invalid|not found|blocked|forbidden|unexpected token)/i;

const ENCODING_VARIANTS: ReadonlyArray<{ id: string; rewrite: (path: string) => string; note: string }> = [
  { id: 'double-encoded-null', rewrite: (path) => `${path}%2500.md`, note: 'Appends a double-encoded NUL followed by a benign extension.' },
  { id: 'raw-encoded-null', rewrite: (path) => `${path}%00.md`, note: 'Appends an encoded NUL followed by a benign extension.' },
  { id: 'double-dot-segment', rewrite: (path) => { const index = path.lastIndexOf('/'); return `${path.slice(0, index)}/..%252f/${path.slice(index + 1)}`; }, note: 'Double-encoded parent-directory segment inserted before the filename.' },
  { id: 'semicolon-suffix', rewrite: (path) => `${path};.md`, note: 'Path parameter suffix that can defeat extension filters.' }
];

async function attempt(scope: ScopeGuard, hostname: string, port: number, tls: boolean, path: string) {
  try {
    const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path });
    const body = response.raw;
    return {
      reachable: response.status === 200 && body.length > 40 && !FIXTURE_MARKER.test(body.slice(0, 400)),
      status: response.status, bytes: Buffer.byteLength(body),
      digest: createHash('sha256').update(body).digest('hex').slice(0, 12),
      error: ''
    };
  } catch (error) {
    return { reachable: false, status: 0, bytes: 0, digest: '', error: error instanceof Error ? error.message.slice(0, 100) : 'failed' };
  }
}

export async function probeEncodingFilterBypass(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; paths?: string[] }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const paths = (input.paths || []).slice(0, MAX_PATHS).map((path) => {
    const normalized = scope.assertPath(path);
    if (/[?#]/.test(normalized)) throw new Error('Probe paths must not contain a query or fragment.');
    if (/%u|[\x00-\x1f]/i.test(normalized)) throw new Error('Probe paths must not contain control characters.');
    return normalized;
  });
  if (!paths.length) throw new Error('Provide at least one previously discovered file path.');

  const suggestedFindings: AgentFinding[] = [];
  const results: Array<{ path: string; baselineStatus: number; variants: Array<{ variant: string; status: number; reachable: boolean }> }> = [];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  for (const path of paths) {
    const baseline = await attempt(scope, hostname, port, tls, path);
    const variants = [];
    for (const variant of ENCODING_VARIANTS) {
      let variantPath: string;
      try { variantPath = variant.rewrite(path); } catch { continue; }
      const outcome = await attempt(scope, hostname, port, tls, variantPath);
      variants.push({ variant: variant.id, status: outcome.status, reachable: outcome.reachable });
      if (outcome.reachable && outcome.digest !== baseline.digest) {
        suggestedFindings.push({
          title: 'File access filter is bypassed by a fixed encoding variant',
          summary: `The path ${path} returned distinct successful content only under the "${variant.id}" encoding (${variant.note}). A server-side filter decides access on the decoded or raw form inconsistently, indicating a validation-ordering weakness.`,
          severity: 'medium', confidence: 90, asset,
          evidence: [
            `Baseline GET ${path}: HTTP ${baseline.status} (digest ${baseline.digest || 'n/a'}).`,
            `Variant ${variant.id}: HTTP ${outcome.status} with a different content signature.`,
            'Only GET requests with fixed encoding rewrites were used; file contents were not retained.'
          ],
          remediation: 'Normalize and validate path input exactly once, reject NUL bytes outright, and enforce extension policy after full decoding at a single trust boundary.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-22', 'CWE-436'],
          frameworkRefs: frameworkReferences('WSTG-INPV-05'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
    }
    results.push({ path, baselineStatus: baseline.status, variants });
  }

  return {
    examined: paths.length, results, suggestedFindings,
    policy: `GET-only, fixed encoding rewrites (${ENCODING_VARIANTS.length} variants per path), at most ${MAX_PATHS} previously discovered paths, no traversal beyond the authorized origin, contents hashed not retained.`
  };
}
