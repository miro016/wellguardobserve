import { existsSync } from 'node:fs';
import { isIP } from 'node:net';
import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding, FindingSeverity } from '../types';
import { frameworkReferences } from '../compliance';

const TEMPLATE_DIRECTORY = process.env['WELLGUARD_NUCLEI_TEMPLATES'] || '/app/nuclei/templates';
const NUCLEI_BINARY = process.env['NUCLEI_BINARY'] || 'nuclei';
const MAX_OUTPUT_BYTES = 160 * 1024;

type NucleiMatch = { templateId: string; name: string; severity: FindingSeverity; url: string; matcher: string; observedIp: string; timestamp: string };

const policies: Record<string, { title: string; summary: string; severity: FindingSeverity; remediation: string; weaknesses: string[] }> = {
  'wellguard-go-expvar': { title: 'Go expvar diagnostics are publicly reachable', summary: 'A strict response match indicates that runtime variables and process diagnostics are available without authentication.', severity: 'medium', remediation: 'Disable the public expvar handler or place it behind authenticated administrative access and a network allowlist.', weaknesses: ['CWE-200'] },
  'wellguard-prometheus-metrics': { title: 'Prometheus-format metrics are publicly reachable', summary: 'The service returned unauthenticated Prometheus exposition data, which can reveal operational names, topology, and workload behavior.', severity: 'low', remediation: 'Confirm public metrics are intentional; otherwise require authentication or restrict the metrics listener to a monitoring network.', weaknesses: ['CWE-200'] },
  'wellguard-openapi-exposure': { title: 'Public API schema is discoverable', summary: 'A public JSON OpenAPI or Swagger document was observed. This is useful inventory evidence and should be reviewed against the intended API exposure.', severity: 'info', remediation: 'Keep the schema public only when intentional; otherwise restrict documentation endpoints while preserving required API access.', weaknesses: [] },
  'wellguard-spring-actuator': { title: 'Spring Actuator metadata is publicly reachable', summary: 'A strict JSON marker indicates that Actuator discovery, mappings, or bean metadata is exposed without authentication.', severity: 'medium', remediation: 'Expose only required health endpoints publicly and protect detailed Actuator endpoints with authentication and network controls.', weaknesses: ['CWE-200'] },
  'wellguard-debug-diagnostics': { title: 'Application diagnostics index is publicly reachable', summary: 'A product-specific marker indicates that a diagnostics or error-log index can be accessed without authentication.', severity: 'medium', remediation: 'Disable public diagnostics in deployed environments or require authenticated administrative access behind an allowlist.', weaknesses: ['CWE-200'] }
};

function canonicalUrl(raw: string, hostname: string, port: number, tls: boolean): string {
  try {
    const parsed = new URL(raw);
    const defaultPort = port === (tls ? 443 : 80) ? '' : `:${port}`;
    return `${tls ? 'https' : 'http'}://${hostname}${defaultPort}${parsed.pathname}`;
  } catch { return `${tls ? 'https' : 'http'}://${hostname}${port === (tls ? 443 : 80) ? '' : `:${port}`}/`; }
}

export function parseNucleiJsonl(output: string, hostname: string, port: number, tls: boolean): NucleiMatch[] {
  const matches: NucleiMatch[] = [];
  for (const line of output.slice(0, MAX_OUTPUT_BYTES).split(/\r?\n/).filter(Boolean).slice(0, 50)) {
    try {
      const value = JSON.parse(line) as Record<string, unknown>;
      const templateId = String(value['template-id'] || '');
      if (!policies[templateId]) continue;
      const info = value['info'] as Record<string, unknown> | undefined;
      matches.push({
        templateId, name: String(info?.['name'] || policies[templateId]!.title), severity: policies[templateId]!.severity,
        url: canonicalUrl(String(value['matched-at'] || value['url'] || ''), hostname, port, tls), matcher: String(value['matcher-name'] || 'strict-response-match'),
        observedIp: String(value['ip'] || ''), timestamp: String(value['timestamp'] || '')
      });
    } catch { /* Ignore non-JSON diagnostics; stderr is handled separately. */ }
  }
  return matches;
}

export async function runNucleiAudit(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean }, signal?: AbortSignal) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  if (port < 1 || port > 65535) throw new Error('Nuclei audit port is outside the allowed range.');
  if (!existsSync(TEMPLATE_DIRECTORY)) throw new Error('The reviewed Wellguard Nuclei template pack is not installed.');
  const [{ address }] = await scope.resolve(hostname);
  const hostAddress = isIP(address) === 6 ? `[${address}]` : address;
  const target = `${tls ? 'https' : 'http'}://${hostAddress}:${port}`;
  const args = [NUCLEI_BINARY, '-u', target, '-t', TEMPLATE_DIRECTORY, '-pt', 'http', '-j', '-silent', '-nc', '-or', '-ot', '-dr', '-lna', '-ni', '-duc', '-no-stdin', '-rl', '2', '-bs', '1', '-c', '1', '-timeout', '6', '-retries', '0', '-rsr', '65536', '-H', `Host: ${hostname}`, '-sni', hostname, '-etags', 'dos,fuzz,bruteforce,headless,code,dast'];
  signal?.throwIfAborted();
  const process = Bun.spawn(args, { stdout: 'pipe', stderr: 'pipe' });
  const abort = () => process.kill();
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => process.kill(), 90_000);
  try {
    const [stdout, stderr, exitCode] = await Promise.all([new Response(process.stdout).text(), new Response(process.stderr).text(), process.exited]);
    signal?.throwIfAborted();
    if (exitCode !== 0) throw new Error(`Reviewed Nuclei audit exited safely with code ${exitCode}: ${stderr.slice(0, 600).replace(/\s+/g, ' ')}`);
    const matches = parseNucleiJsonl(stdout, hostname, port, tls);
    const suggestedFindings: AgentFinding[] = matches.map((match) => {
      const policy = policies[match.templateId]!;
      return {
        title: policy.title, summary: policy.summary, severity: policy.severity, confidence: 99,
        asset: `${hostname}:${port}`, evidence: [`Reviewed Nuclei template ${match.templateId} strictly matched ${match.url}.`, match.observedIp ? `The connection used the pre-authorized public address ${match.observedIp}.` : 'The authorized public host returned the matching response.'],
        remediation: policy.remediation, sourceUrls: ['https://docs.projectdiscovery.io/templates/structure'], cveIds: [], weaknessIds: policy.weaknesses, frameworkRefs: frameworkReferences('CRA-I-1', 'CRA-I-2j', 'CRA-II-3'),
        assetKey: `service:${hostname}:${port}:web`, relatedAssetKeys: [`hostname:${hostname}`, `port:${hostname}:${port}`]
      };
    });
    return { hostname, port, transport: tls ? 'https' : 'http', policy: 'reviewed-get-v1', templates: Object.keys(policies), requestRateLimit: 2, concurrency: 1, rawResponsesRetained: false, matches, suggestedFindings, note: 'Only repository-reviewed GET templates ran. Redirects, private-network access, OOB callbacks, code, headless, fuzzing, DAST, and downloaded templates were disabled.' };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}
