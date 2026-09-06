import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp } from './http';

const OPERATIONS = ['get', 'head', 'options', 'post', 'put', 'patch', 'delete', 'trace'] as const;

function example(parameter: Record<string, unknown>): string {
  const schema = parameter['schema'] && typeof parameter['schema'] === 'object' ? parameter['schema'] as Record<string, unknown> : {};
  const candidate = parameter['example'] ?? schema['example'] ?? schema['default'] ?? (Array.isArray(schema['enum']) ? schema['enum'][0] : undefined);
  if (candidate != null && ['string', 'number', 'boolean'].includes(typeof candidate)) return String(candidate).slice(0, 120);
  if (schema['type'] === 'boolean') return 'true';
  if (schema['type'] === 'integer' || schema['type'] === 'number') return '1';
  return 'wellguard-sample';
}

function jsonShape(raw: string): unknown {
  try {
    const value = JSON.parse(raw);
    if (Array.isArray(value)) return { type: 'array', items: value.length, firstItemKeys: value[0] && typeof value[0] === 'object' ? Object.keys(value[0]).slice(0, 30) : [] };
    if (value && typeof value === 'object') return { type: 'object', keys: Object.keys(value).slice(0, 40) };
    return { type: typeof value };
  } catch { return null; }
}

export async function inspectApiSchema(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; schemaPath: string; sampleReadOnly?: boolean; maxOperations?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const schemaPath = scope.assertPath(input.schemaPath);
  const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path: schemaPath, maxBodyBytes: 1200 * 1024 });
  let document: Record<string, unknown>;
  try { document = JSON.parse(response.raw) as Record<string, unknown>; }
  catch { throw new Error('The observed schema document is not JSON.'); }
  const paths = document['paths'] && typeof document['paths'] === 'object' ? document['paths'] as Record<string, Record<string, unknown>> : {};
  if (!Object.keys(paths).length || !(document['openapi'] || document['swagger'])) throw new Error('The document does not expose an OpenAPI or Swagger paths object.');
  const operations: Array<Record<string, unknown>> = [];

  for (const [template, pathItem] of Object.entries(paths).slice(0, 300)) {
    const sharedParameters = Array.isArray(pathItem['parameters']) ? pathItem['parameters'] as Array<Record<string, unknown>> : [];
    for (const method of OPERATIONS) {
      const operation = pathItem[method];
      if (!operation || typeof operation !== 'object') continue;
      const value = operation as Record<string, unknown>;
      const parameters = [...sharedParameters, ...(Array.isArray(value['parameters']) ? value['parameters'] as Array<Record<string, unknown>> : [])].filter((parameter) => !parameter['$ref']);
      operations.push({
        method: method.toUpperCase(), path: template, operationId: String(value['operationId'] || ''),
        summary: String(value['summary'] || value['description'] || '').slice(0, 300),
        securityDeclared: value['security'] !== undefined ? Boolean((value['security'] as unknown[])?.length) : Boolean((document['security'] as unknown[])?.length),
        parameters: parameters.map((parameter) => ({ name: String(parameter['name'] || ''), in: String(parameter['in'] || ''), required: Boolean(parameter['required']), sampleAvailable: parameter['example'] != null || Boolean((parameter['schema'] as Record<string, unknown> | undefined)?.['example']) })).slice(0, 30),
        requestContentTypes: Object.keys(((value['requestBody'] as Record<string, unknown> | undefined)?.['content'] as Record<string, unknown> | undefined) || {})
      });
    }
  }

  const samples: Array<Record<string, unknown>> = [];
  if (input.sampleReadOnly) {
    const maxOperations = Math.max(1, Math.min(30, Math.floor(input.maxOperations || 16)));
    for (const operation of operations.filter((item) => item['method'] === 'GET').slice(0, maxOperations)) {
      let path = String(operation['path']);
      const pathItem = paths[path] || {};
      const value = pathItem['get'] && typeof pathItem['get'] === 'object' ? pathItem['get'] as Record<string, unknown> : {};
      const parameters = [...(Array.isArray(pathItem['parameters']) ? pathItem['parameters'] as Array<Record<string, unknown>> : []), ...(Array.isArray(value['parameters']) ? value['parameters'] as Array<Record<string, unknown>> : [])].filter((parameter) => !parameter['$ref']);
      for (const parameter of parameters.filter((item) => item['in'] === 'path')) path = path.replace(`{${String(parameter['name'])}}`, encodeURIComponent(example(parameter)));
      if (/[{}]/.test(path)) continue;
      const query = new URLSearchParams();
      for (const parameter of parameters.filter((item) => item['in'] === 'query' && item['required'])) query.set(String(parameter['name']), example(parameter));
      const requestPath = scope.assertPath(`${path}${query.size ? `?${query}` : ''}`);
      try {
        const sample = await requestAuthorizedHttp(scope, { hostname, port, tls, path: requestPath, maxBodyBytes: 48 * 1024 });
        samples.push({ method: 'GET', path: requestPath, status: sample.status, contentType: sample.headers['content-type'] || '', bytes: Buffer.byteLength(sample.raw), jsonShape: jsonShape(sample.raw), securityDeclared: operation['securityDeclared'], authenticationReviewNeeded: Boolean(operation['securityDeclared']) && sample.status >= 200 && sample.status < 300 });
      } catch (error) { samples.push({ method: 'GET', path: requestPath, error: error instanceof Error ? error.message.slice(0, 240) : 'Request failed' }); }
    }
  }

  return {
    schemaPath, schemaStatus: response.status, specification: String(document['openapi'] || document['swagger']),
    title: String((document['info'] as Record<string, unknown> | undefined)?.['title'] || ''), operationCount: operations.length,
    methods: Object.fromEntries(OPERATIONS.map((method) => [method.toUpperCase(), operations.filter((item) => item['method'] === method.toUpperCase()).length])),
    operations: operations.slice(0, 300), anonymousReadSamples: samples,
    boundary: 'The schema itself and optional GET operations were read anonymously. State-changing operations were inventoried but never invoked; a 2xx response is review evidence, not proof of broken authorization.'
  };
}
