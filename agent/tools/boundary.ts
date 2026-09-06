import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedJsonPost } from './http';

/**
 * Boundary-value validation probe for the Unbounded profile.
 * The model supplies the *shape* of a previously discovered JSON endpoint
 * (field names and types). This module constructs only fixed boundary
 * values: numeric zero/negative/overflow, empty and 512-byte strings,
 * flipped booleans. Arbitrary payload content is impossible.
 */

const MAX_FIELDS = 8;
const BOUNDARY_NUMBERS = [0, -1, 9_999_999] as const;
const BOUNDARY_STRINGS = ['', 'A'.repeat(512)] as const;

interface FieldSpec { name: string; kind: 'number' | 'string' | 'boolean' }

function normalizeFields(value: unknown): FieldSpec[] {
  const fields = Array.isArray(value) ? value : [];
  return fields.flatMap((entry) => {
    const name = String((entry as Record<string, unknown>)?.['name'] || '').trim();
    const kind = String((entry as Record<string, unknown>)?.['kind'] || '').toLowerCase();
    if (!/^[A-Za-z][A-Za-z0-9_.-]{0,48}$/.test(name)) return [];
    if (!['number', 'string', 'boolean'].includes(kind)) return [];
    return [{ name, kind: kind as FieldSpec['kind'] }];
  }).slice(0, MAX_FIELDS);
}

export async function probeBoundaryValidation(scope: ScopeGuard, token: string, input: { hostname?: string; port?: number; tls?: boolean; path?: string; fields?: unknown }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const path = scope.assertPath(input.path || '/');
  if (/[?#]/.test(path)) throw new Error('Boundary probing requires a clean JSON POST endpoint path.');
  const fields = normalizeFields(input.fields);
  if (!fields.length) throw new Error('Provide the endpoint field names and kinds discovered from API evidence.');

  const normalBody: Record<string, unknown> = {};
  for (const field of fields) normalBody[field.name] = field.kind === 'number' ? 1 : field.kind === 'string' ? 'wellguard-review' : true;

  const controls = token ? { bearerToken: token } : {};
  const attempts: Array<{ case: string; status: number; note: string }> = [];
  const suggestedFindings: AgentFinding[] = [];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  let normal: { status: number; raw: string };
  try {
    normal = await requestAuthorizedJsonPost(scope, { hostname, port, tls, path }, normalBody as Record<string, string>);
  } catch (error) {
    return { endpoint: path, attempts, suggestedFindings, note: `Normal-value baseline request failed: ${error instanceof Error ? error.message.slice(0, 120) : 'unknown'}` };
  }
  attempts.push({ case: 'normal-values', status: normal.status, note: 'baseline' });

  const cases: Array<{ id: string; mutate: (body: Record<string, unknown>) => Record<string, unknown>; reason: string }> = [];
  for (const field of fields) {
    if (field.kind === 'number') {
      for (const value of BOUNDARY_NUMBERS) cases.push({ id: `${field.name}=${value}`, mutate: (body) => ({ ...body, [field.name]: value }), reason: value === 0 ? 'zero boundary' : value < 0 ? 'negative boundary' : 'overflow-scale value' });
    } else if (field.kind === 'string') {
      for (const value of BOUNDARY_STRINGS) cases.push({ id: `${field.name}=len${value.length}`, mutate: (body) => ({ ...body, [field.name]: value }), reason: value ? '512-byte string' : 'empty string' });
    } else {
      cases.push({ id: `${field.name}=flipped`, mutate: (body) => ({ ...body, [field.name]: !normalBody[field.name] }), reason: 'boolean inversion' });
    }
  }

  const accepted: string[] = [];
  for (const testCase of cases.slice(0, MAX_FIELDS * 4)) {
    try {
      const response = await requestAuthorizedJsonPost(scope, { hostname, port, tls, path }, testCase.mutate(normalBody) as Record<string, string>);
      const ok = response.status >= 200 && response.status < 300;
      attempts.push({ case: testCase.id, status: response.status, note: ok ? `accepted (${testCase.reason})` : 'rejected' });
      if (ok && (normal.status >= 400 || true)) accepted.push(testCase.id);
    } catch (error) {
      attempts.push({ case: testCase.id, status: 0, note: error instanceof Error ? error.message.slice(0, 100) : 'failed' });
    }
  }

  const boundaryAccepted = accepted.filter((id) => /=(0|-1|len0|len512|9999999|flipped)/.test(id));
  if (boundaryAccepted.length && normal.status >= 200 && normal.status < 300) {
    suggestedFindings.push({
      title: 'API endpoint accepts boundary values that a UI would not emit',
      summary: `POST ${path} accepted ${boundaryAccepted.length} boundary mutations (${boundaryAccepted.slice(0, 8).join(', ')}) with success status. Server-side validation is inconsistent with the obvious client-side constraints, which is the class behind zero-value, negative-quantity and oversized-field abuse.`,
      severity: 'medium', confidence: 90, asset,
      evidence: [
        `Baseline with normal values: HTTP ${normal.status}.`,
        ...boundaryAccepted.slice(0, 8).map((id) => `Boundary case ${id}: HTTP success.`),
        'Only fixed boundary shapes were sent; values were derived from the declared field types, not arbitrary payloads.'
      ],
      remediation: 'Re-validate every field server-side (ranges, length, type), independent of the client UI, and return uniform 4xx rejections for out-of-domain values.',
      sourceUrls: [], cveIds: [], weaknessIds: ['CWE-20'],
      frameworkRefs: frameworkReferences('WSTG-INPV-05'),
      assetKey, relatedAssetKeys: [], relationKey: ''
    });
  }

  return {
    endpoint: path, baselineStatus: normal.status, attemptsUsed: attempts.length, attempts,
    acceptedBoundaryCases: boundaryAccepted, suggestedFindings,
    policy: `Fixed boundary shapes only, derived from ${fields.length} declared field(s); at most ${MAX_FIELDS * 4} requests; session token reused only if acquired earlier in this investigation.`
  };
}
