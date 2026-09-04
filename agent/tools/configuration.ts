import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp } from './http';

export interface ConfigurationCheck {
  control: string;
  state: 'present' | 'review' | 'exposed';
  observed: string;
  cweIds: string[];
  explanation: string;
}

export function assessHttpConfiguration(headers: Record<string, string>, tls: boolean): ConfigurationCheck[] {
  const value = (name: string) => headers[name.toLowerCase()]?.trim() || '';
  const csp = value('content-security-policy');
  const frame = value('x-frame-options');
  const hsts = value('strict-transport-security');
  const cors = value('access-control-allow-origin');
  const credentials = value('access-control-allow-credentials');
  const serverIdentity = [value('server'), value('x-powered-by')].filter(Boolean).join(' · ');
  return [
    {
      control: 'Transport downgrade protection', state: !tls || hsts ? 'present' : 'review',
      observed: tls ? (hsts || 'Strict-Transport-Security was not returned') : 'Not applicable to this plain HTTP response',
      cweIds: !tls || hsts ? [] : ['CWE-319'],
      explanation: hsts ? 'The response asks supporting browsers to keep using HTTPS.' : 'Confirm that the HTTPS site intentionally omits HSTS and that HTTP always redirects safely.'
    },
    {
      control: 'Framing protection', state: frame || /(?:^|;)\s*frame-ancestors\b/i.test(csp) ? 'present' : 'review',
      observed: frame || (/(?:^|;)\s*frame-ancestors[^;]*/i.exec(csp)?.[0]?.trim()) || 'No X-Frame-Options or CSP frame-ancestors directive was returned',
      cweIds: frame || /(?:^|;)\s*frame-ancestors\b/i.test(csp) ? [] : ['CWE-1021'],
      explanation: 'Missing framing controls can permit UI redress on pages that contain sensitive actions; applicability depends on page behavior.'
    },
    {
      control: 'Content Security Policy', state: csp ? 'present' : 'review', observed: csp || 'Content-Security-Policy was not returned',
      cweIds: csp ? [] : ['CWE-693'], explanation: csp ? 'A browser content policy is present; its directives still require review.' : 'A CSP can limit the impact of injected or unexpectedly loaded content.'
    },
    {
      control: 'MIME sniffing protection', state: /^nosniff$/i.test(value('x-content-type-options')) ? 'present' : 'review',
      observed: value('x-content-type-options') || 'X-Content-Type-Options was not returned',
      cweIds: /^nosniff$/i.test(value('x-content-type-options')) ? [] : ['CWE-693'], explanation: 'The nosniff directive reduces browser content-type ambiguity.'
    },
    {
      control: 'Referrer disclosure policy', state: value('referrer-policy') ? 'present' : 'review',
      observed: value('referrer-policy') || 'Referrer-Policy was not returned', cweIds: value('referrer-policy') ? [] : ['CWE-200'],
      explanation: 'An explicit policy limits accidental disclosure of path and query information to other origins.'
    },
    {
      control: 'Cross-origin read policy', state: cors === '*' || (cors && /^true$/i.test(credentials)) ? 'exposed' : cors ? 'present' : 'review',
      observed: cors ? `${cors}${credentials ? ` · credentials=${credentials}` : ''}` : 'No Access-Control-Allow-Origin policy was returned',
      cweIds: cors === '*' || (cors && /^true$/i.test(credentials)) ? ['CWE-942'] : [],
      explanation: cors ? 'The returned CORS policy must match the intended public API audience.' : 'No permissive cross-origin policy was observed on this response.'
    },
    {
      control: 'Server identity disclosure', state: /\d+\.\d+/.test(serverIdentity) ? 'exposed' : serverIdentity ? 'present' : 'present',
      observed: serverIdentity || 'No server or runtime identity header was returned', cweIds: /\d+\.\d+/.test(serverIdentity) ? ['CWE-200'] : [],
      explanation: /\d+\.\d+/.test(serverIdentity) ? 'A precise public server/runtime version can make vulnerability targeting easier.' : 'No precise server/runtime version was observed in identity headers.'
    }
  ];
}

export async function inspectHttpConfiguration(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path?: string }) {
  const response = await requestAuthorizedHttp(scope, input);
  const tls = input.tls ?? true;
  return {
    requestedUrl: response.requestedUrl,
    status: response.status,
    checks: assessHttpConfiguration(response.headers, tls),
    headers: response.headers,
    note: 'A missing response header is a configuration review signal, not by itself proof of an exploitable vulnerability.'
  };
}
