import type { AgentFinding, FindingSeverity } from '../types';
import type { ScopeGuard } from '../security/scope-guard';
import { requestAuthorizedHttp, type AuthorizedHttpResponse } from './http';
import { frameworkReferences } from '../compliance';

interface SafeTemplate {
  id: string;
  path: string;
  title: string;
  severity: FindingSeverity;
  weaknessIds: string[];
  remediation: string;
  matches: (response: AuthorizedHttpResponse) => boolean;
  evidence: (response: AuthorizedHttpResponse) => string;
}

const json = (response: AuthorizedHttpResponse): Record<string, unknown> | null => {
  try { return JSON.parse(response.raw) as Record<string, unknown>; } catch { return null; }
};

export const SAFE_WEB_TEMPLATES: SafeTemplate[] = [
  {
    id: 'exposed-dotenv', path: '/.env', title: 'Environment configuration file is publicly readable', severity: 'high', weaknessIds: ['CWE-200'],
    matches: (response) => response.status === 200 && !/text\/html/i.test(response.headers['content-type'] || '') && /^(?:APP_KEY|DATABASE_URL|DB_(?:HOST|PASSWORD|USERNAME)|SECRET_KEY|AWS_ACCESS_KEY_ID)=/m.test(response.raw),
    evidence: (response) => `GET ${response.requestedUrl} returned a non-HTML response containing environment-variable assignment names. Values were not retained.`,
    remediation: 'Block dotfiles at the public proxy, remove environment files from the web root, rotate every value that may have been exposed, and verify access logs for prior retrieval.'
  },
  {
    id: 'exposed-git-head', path: '/.git/HEAD', title: 'Git repository metadata is publicly readable', severity: 'high', weaknessIds: ['CWE-538'],
    matches: (response) => response.status === 200 && /^ref:\s+refs\/heads\/[A-Za-z0-9._/-]+\s*$/m.test(response.raw),
    evidence: (response) => `GET ${response.requestedUrl} returned a valid Git HEAD reference.`,
    remediation: 'Deny public access to .git paths, deploy build artifacts without repository metadata, and assess whether repository contents or secrets could have been retrieved.'
  },
  {
    id: 'apache-server-status', path: '/server-status', title: 'Apache server-status information is publicly accessible', severity: 'medium', weaknessIds: ['CWE-200'],
    matches: (response) => response.status === 200 && /<title>Apache Status|Apache Server Status for|Server Version:\s*Apache/i.test(response.raw),
    evidence: (response) => `GET ${response.requestedUrl} returned Apache server-status markers. Request rows and values were not retained.`,
    remediation: 'Restrict mod_status to an authenticated administrative network or disable it on the public virtual host.'
  },
  {
    id: 'phpinfo', path: '/phpinfo.php', title: 'PHP runtime diagnostic page is publicly accessible', severity: 'medium', weaknessIds: ['CWE-200'],
    matches: (response) => response.status === 200 && /<title>phpinfo\(\)<\/title>|PHP Version [0-9]+\.[0-9]+/i.test(response.raw),
    evidence: (response) => `GET ${response.requestedUrl} returned phpinfo runtime markers. Configuration values were not retained.`,
    remediation: 'Remove the diagnostic page from production and rotate any credential or token that its environment output may have exposed.'
  },
  {
    id: 'spring-actuator-env', path: '/actuator/env', title: 'Spring Actuator environment endpoint is publicly accessible', severity: 'high', weaknessIds: ['CWE-200'],
    matches: (response) => {
      const body = json(response);
      return response.status === 200 && Boolean(body && (Array.isArray(body['propertySources']) || typeof body['activeProfiles'] !== 'undefined'));
    },
    evidence: (response) => `GET ${response.requestedUrl} returned the Spring Actuator environment document shape. Property names and values were not retained.`,
    remediation: 'Require authentication and network restrictions for Actuator management endpoints, expose only required health detail, and review whether configuration values were disclosed.'
  }
];

export function evaluateSafeTemplate(template: SafeTemplate, response: AuthorizedHttpResponse): boolean {
  return template.matches(response);
}

export async function inspectSafeWebAudit(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const checks: Array<{ templateId: string; path: string; status: number; matched: boolean; observation: string }> = [];
  const suggestedFindings: AgentFinding[] = [];

  for (const template of SAFE_WEB_TEMPLATES) {
    try {
      const response = await requestAuthorizedHttp(scope, { hostname, port, tls, path: template.path });
      const matched = evaluateSafeTemplate(template, response);
      checks.push({ templateId: template.id, path: template.path, status: response.status, matched, observation: matched ? template.evidence(response) : 'Strict exposure markers did not match.' });
      if (matched) suggestedFindings.push({
        title: template.title,
        summary: `${template.evidence(response)} This is a confirmed public information-exposure condition; the check did not retrieve linked files, invoke an operation, or attempt exploitation.`,
        severity: template.severity, confidence: 100, asset: hostname,
        evidence: [template.evidence(response)], remediation: template.remediation,
        sourceUrls: template.weaknessIds.map((id) => `https://cwe.mitre.org/data/definitions/${id.slice(4)}.html`),
        cveIds: [], weaknessIds: template.weaknessIds, frameworkRefs: frameworkReferences('CRA-I-1', 'CRA-I-2b', 'CRA-I-2j', 'CRA-II-3'), assetKey: '', relatedAssetKeys: [], relationKey: ''
      });
    } catch (error) {
      checks.push({ templateId: template.id, path: template.path, status: 0, matched: false, observation: error instanceof Error ? error.message : String(error) });
    }
  }

  return {
    hostname, checks, suggestedFindings,
    policy: {
      profile: 'safe-recon-v1', requests: SAFE_WEB_TEMPLATES.length, concurrency: 1, method: 'GET',
      excluded: ['authentication attempts', 'payload injection', 'fuzzing', 'headless browser actions', 'out-of-band callbacks', 'CVE exploit templates', 'state-changing requests']
    },
    note: 'This is a small audited allowlist comparable to the safe subset of a template scanner, not an unrestricted Nuclei run. Strict response markers reduce SPA and custom-404 false positives, and sensitive response values are never returned.'
  };
}
