import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { ScopeGuard } from './security/scope-guard';
import type { ScanMode } from './types';
import { requestAuthorizedHttp, requestAuthorizedJsonPost, requestAuthorizedMethod, type AuthorizedHttpResponse } from './tools/http';

export const GENERATED_TOOL_SCHEMA_VERSION = 'http-probe-v1';

const profileOrder: ScanMode[] = ['light', 'standard', 'extended', 'advanced', 'unbounded'];
const scalarBody = z.string().max(400);

function fileShapedPath(path: string): boolean {
  const pathname = path.split(/[?#]/, 1)[0]!.toLowerCase();
  const basename = pathname.split('/').at(-1) || '';
  return basename === 'dockerfile' || basename.startsWith('.') || /\.[a-z0-9]{1,12}$/.test(basename);
}

export const generatedAssertionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('status-in'), values: z.array(z.number().int().min(100).max(599)).min(1).max(8) }),
  z.object({ type: z.literal('header-present'), name: z.string().regex(/^[A-Za-z0-9-]{1,80}$/) }),
  z.object({ type: z.literal('header-contains'), name: z.string().regex(/^[A-Za-z0-9-]{1,80}$/), value: z.string().min(1).max(160) }),
  z.object({ type: z.literal('body-contains'), value: z.string().min(2).max(200) }),
  z.object({ type: z.literal('json-key-exists'), path: z.string().regex(/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){0,7}$/) })
]);

export const generatedProbeStepSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{1,39}$/),
  purpose: z.string().min(8).max(240),
  method: z.enum(['GET', 'HEAD', 'OPTIONS', 'POST_JSON']),
  path: z.string().min(1).max(300).refine((path) => path.startsWith('/') && !path.startsWith('//') && !path.includes('\\') && !/(^|\/)\.\.?($|\/)/.test(path), 'Use one bounded same-origin relative path.'),
  body: z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/), scalarBody).optional(),
  assertions: z.array(generatedAssertionSchema).min(1).max(6)
}).superRefine((step, context) => {
  const bodyEntries = Object.entries(step.body || {});
  if (bodyEntries.length > 8) context.addIssue({ code: 'custom', message: 'Generated request bodies may contain at most eight fields.' });
  if (step.method !== 'POST_JSON' && bodyEntries.length) context.addIssue({ code: 'custom', message: 'Only POST_JSON steps may include a body.' });
  if (step.method === 'POST_JSON' && JSON.stringify(step.body || {}).length > 2_048) context.addIssue({ code: 'custom', message: 'Generated JSON bodies are bounded to 2048 bytes.' });
  if (fileShapedPath(step.path) && step.method === 'HEAD') context.addIssue({ code: 'custom', message: 'File-shaped probes must read a bounded body; HEAD cannot establish that the requested document was returned.' });
  if (fileShapedPath(step.path) && step.method === 'GET' && !step.assertions.some((assertion) => assertion.type === 'body-contains' || assertion.type === 'json-key-exists')) {
    context.addIssue({ code: 'custom', message: 'File-shaped GET probes require a body marker or JSON-key assertion; HTTP status alone is insufficient.' });
  }
});

export const generatedProbeSpecSchema = z.object({
  version: z.literal(GENERATED_TOOL_SCHEMA_VERSION).default(GENERATED_TOOL_SCHEMA_VERSION),
  steps: z.array(generatedProbeStepSchema).min(1).max(12)
});

export const generatedToolProposalSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]{2,63}$/),
  title: z.string().min(8).max(160),
  summary: z.string().min(20).max(500),
  rationale: z.string().min(20).max(1_000),
  category: z.enum(['discovery', 'configuration', 'authentication', 'authorization', 'session', 'input-validation', 'client-side', 'api']),
  evidence: z.array(z.string().min(8).max(300)).min(1).max(10),
  spec: generatedProbeSpecSchema
});

export type GeneratedProbeSpec = z.infer<typeof generatedProbeSpecSchema>;
export type GeneratedToolProposal = z.infer<typeof generatedToolProposalSchema>;
export type GeneratedToolStatus = 'proposed' | 'approved' | 'rejected' | 'disabled';

export interface GeneratedToolDefinition extends GeneratedToolProposal {
  id: string;
  workspace: string;
  checksum: string;
  status: GeneratedToolStatus;
  minProfile: ScanMode;
  unboundedAutoUse: boolean;
  compatibleProfiles: ScanMode[];
  requestCeiling: number;
  riskLevel: 'passive' | 'low' | 'interactive';
  generatedByModel: string;
  sourceScan: string;
  sourceTarget: string;
  reviewedBy: string;
  reviewedAt: string;
  reviewNote: string;
  created: string;
  updated: string;
}

export interface GeneratedToolValidation {
  valid: boolean;
  errors: string[];
  checksum: string;
  compatibleProfiles: ScanMode[];
  requestCeiling: number;
  riskLevel: 'passive' | 'low' | 'interactive';
}

const constraints: Record<ScanMode, { maxSteps: number; methods: GeneratedProbeSpec['steps'][number]['method'][] }> = {
  light: { maxSteps: 2, methods: ['GET'] },
  standard: { maxSteps: 4, methods: ['GET', 'HEAD'] },
  extended: { maxSteps: 6, methods: ['GET', 'HEAD', 'OPTIONS'] },
  advanced: { maxSteps: 8, methods: ['GET', 'HEAD', 'OPTIONS', 'POST_JSON'] },
  unbounded: { maxSteps: 12, methods: ['GET', 'HEAD', 'OPTIONS', 'POST_JSON'] }
};

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(',')}}`;
  return JSON.stringify(value);
}

export function generatedToolChecksum(proposal: GeneratedToolProposal): string {
  return createHash('sha256').update(stable(proposal)).digest('hex');
}

export function validateGeneratedTool(input: unknown): { proposal?: GeneratedToolProposal; validation: GeneratedToolValidation } {
  const parsed = generatedToolProposalSchema.safeParse(input);
  if (!parsed.success) return {
    validation: { valid: false, errors: parsed.error.issues.map((issue) => `${issue.path.join('.') || 'proposal'}: ${issue.message}`).slice(0, 20), checksum: '', compatibleProfiles: [], requestCeiling: 0, riskLevel: 'interactive' }
  };
  const proposal = parsed.data;
  const methods = proposal.spec.steps.map((step) => step.method);
  const compatibleProfiles = profileOrder.filter((profile) => proposal.spec.steps.length <= constraints[profile].maxSteps && methods.every((method) => constraints[profile].methods.includes(method)));
  const riskLevel: GeneratedToolValidation['riskLevel'] = methods.includes('POST_JSON') ? 'interactive' : methods.some((method) => method !== 'GET') ? 'low' : 'passive';
  return {
    proposal,
    validation: { valid: compatibleProfiles.length > 0, errors: compatibleProfiles.length ? [] : ['No scan profile can execute this request plan.'], checksum: generatedToolChecksum(proposal), compatibleProfiles, requestCeiling: proposal.spec.steps.length, riskLevel }
  };
}

export function generatedToolEligible(tool: GeneratedToolDefinition, profile: ScanMode): boolean {
  if (!tool.compatibleProfiles.includes(profile)) return false;
  if (tool.status === 'approved') return profileOrder.indexOf(profile) >= profileOrder.indexOf(tool.minProfile);
  return profile === 'unbounded' && tool.status === 'proposed' && tool.unboundedAutoUse;
}

function jsonPathExists(raw: string, path: string): boolean {
  try {
    let value: unknown = JSON.parse(raw);
    for (const segment of path.split('.')) {
      if (!value || typeof value !== 'object' || !(segment in value)) return false;
      value = (value as Record<string, unknown>)[segment];
    }
    return true;
  } catch { return false; }
}

function redactPreview(raw: string): string {
  return raw.replace(/(["']?(?:password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?)[^\s,"'<>}]{1,300}/gi, '$1[redacted]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/\s+/g, ' ').trim().slice(0, 600);
}

function assertionResult(assertion: z.infer<typeof generatedAssertionSchema>, response: AuthorizedHttpResponse): { assertion: string; matched: boolean } {
  if (assertion.type === 'status-in') return { assertion: `status in ${assertion.values.join(', ')}`, matched: assertion.values.includes(response.status) };
  if (assertion.type === 'header-present') return { assertion: `header ${assertion.name} present`, matched: assertion.name.toLowerCase() in response.headers };
  if (assertion.type === 'header-contains') return { assertion: `header ${assertion.name} contains a proposed marker`, matched: (response.headers[assertion.name.toLowerCase()] || '').toLowerCase().includes(assertion.value.toLowerCase()) };
  if (assertion.type === 'body-contains') return { assertion: 'body contains a proposed marker', matched: response.raw.toLowerCase().includes(assertion.value.toLowerCase()) };
  return { assertion: `JSON key ${assertion.path} exists`, matched: jsonPathExists(response.raw, assertion.path) };
}

export async function executeGeneratedTool(scope: ScopeGuard, definition: GeneratedToolDefinition, profile: ScanMode, input: { hostname?: string; port?: number; tls?: boolean }, signal?: AbortSignal) {
  const checked = validateGeneratedTool(definition);
  if (!checked.proposal || !checked.validation.valid || checked.validation.checksum !== definition.checksum) throw new Error('Generated tool failed immutable schema or checksum validation.');
  if (!generatedToolEligible(definition, profile)) throw new Error(`Generated tool is not enabled for the ${profile} profile.`);
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const results: Array<Record<string, unknown>> = [];
  let matchedAssertions = 0;

  for (const step of checked.proposal.spec.steps) {
    signal?.throwIfAborted();
    let response: AuthorizedHttpResponse;
    if (step.method === 'GET') response = await requestAuthorizedHttp(scope, { hostname, port, tls, path: step.path, maxBodyBytes: 64 * 1024 });
    else if (step.method === 'POST_JSON') response = await requestAuthorizedJsonPost(scope, { hostname, port, tls, path: step.path, maxBodyBytes: 64 * 1024 }, step.body || {});
    else response = await requestAuthorizedMethod(scope, { hostname, port, tls, path: step.path }, step.method);
    const assertions = step.assertions.map((assertion) => assertionResult(assertion, response));
    matchedAssertions += assertions.filter((assertion) => assertion.matched).length;
    let jsonShape: unknown = null;
    try {
      const value = JSON.parse(response.raw);
      jsonShape = Array.isArray(value) ? { type: 'array', items: value.length } : value && typeof value === 'object' ? { type: 'object', keys: Object.keys(value).slice(0, 40) } : { type: typeof value };
    } catch { /* Non-JSON evidence is represented by a bounded preview. */ }
    results.push({
      id: step.id, purpose: step.purpose, method: step.method, path: step.path, status: response.status,
      headers: response.headers, bytes: Buffer.byteLength(response.raw), truncated: response.truncated,
      bodySha256: createHash('sha256').update(response.raw).digest('hex'), jsonShape,
      bodyPreview: redactPreview(response.raw), assertions
    });
  }

  const assertionCount = checked.proposal.spec.steps.reduce((sum, step) => sum + step.assertions.length, 0);
  return {
    toolId: definition.id, name: definition.name, title: definition.title, status: definition.status,
    profile, requestCount: results.length, matchedAssertions, assertionCount,
    allAssertionsMatched: assertionCount > 0 && matchedAssertions === assertionCount, results,
    boundary: 'The runtime compiled a declarative same-origin request plan. No generated code, shell, filesystem, arbitrary headers, credential material, redirects, or out-of-scope network access was available.'
  };
}
