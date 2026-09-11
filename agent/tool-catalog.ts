import type { ScanMode } from './types';

export type AgentToolRisk = 'passive' | 'low' | 'interactive';
export type AgentToolSource = 'wellguard' | 'vanguard';

export interface AgentToolCatalogEntry {
  name: string;
  title: string;
  summary: string;
  category: string;
  source: AgentToolSource;
  version: string;
  riskLevel: AgentToolRisk;
  defaultProfiles: ScanMode[];
  essential?: boolean;
}

export interface AgentToolPolicy {
  name: string;
  enabled: boolean;
  profiles: ScanMode[];
}

const all: ScanMode[] = ['light', 'standard', 'extended', 'advanced', 'unbounded'];
const standard: ScanMode[] = ['standard', 'extended', 'advanced', 'unbounded'];
const active: ScanMode[] = ['extended', 'advanced', 'unbounded'];
const interactive: ScanMode[] = ['advanced', 'unbounded'];
const unbounded: ScanMode[] = ['unbounded'];

const tool = (name: string, title: string, summary: string, category: string, riskLevel: AgentToolRisk, defaultProfiles: ScanMode[], source: AgentToolSource = 'wellguard', essential = false): AgentToolCatalogEntry =>
  ({ name, title, summary, category, riskLevel, defaultProfiles, source, version: source === 'vanguard' ? 'd9e2b785b973' : 'scan-policy-v5', essential });

export const AGENT_TOOL_CATALOG: readonly AgentToolCatalogEntry[] = [
  tool('inspect_dns', 'DNS resolution', 'Resolve authorized hosts and retain public address evidence.', 'discovery', 'passive', all),
  tool('inspect_certificate_transparency', 'Certificate transparency', 'Discover certificate names from public CT records.', 'discovery', 'passive', all),
  tool('inspect_domain_registration', 'Domain registration', 'Read delegated RDAP registration and public contact evidence.', 'intelligence', 'passive', all),
  tool('inspect_dns_posture', 'DNS and mail posture', 'Inspect NS, MX, DNSSEC, SPF, DMARC, MTA-STS and TLS reporting.', 'configuration', 'passive', all),
  tool('inspect_network_registration', 'Network registration', 'Attribute public addresses using delegated IP RDAP.', 'intelligence', 'passive', all),
  tool('inspect_tls', 'TLS handshake', 'Inspect certificate identity, validity, protocol and cipher.', 'configuration', 'low', all),
  tool('discover_tcp_ports', 'Bounded TCP discovery', 'Check a profile-bounded list of TCP ports.', 'discovery', 'low', all),
  tool('inspect_service_banner', 'Passive service banner', 'Read only data emitted by a reachable TCP service.', 'discovery', 'low', all),
  tool('inspect_http', 'Single HTTP observation', 'Read one bounded public HTTP response and identity signals.', 'discovery', 'low', all),
  tool('inspect_http_configuration', 'HTTP configuration', 'Assess browser, framing, CORS, transport and server headers.', 'configuration', 'low', all),
  tool('inspect_frontend_api', 'Frontend API evidence', 'Mine public same-origin bundles for backend and route evidence.', 'api', 'low', all),
  tool('inspect_public_metadata', 'Public metadata', 'Read fixed standards-based metadata locations.', 'intelligence', 'low', all),
  tool('inspect_wordpress', 'WordPress public metadata', 'Use strict fingerprints before reading bounded public REST metadata.', 'service', 'low', all),
  tool('inspect_public_directory_index', 'Directory index review', 'Validate an already observed directory listing without opening entries.', 'configuration', 'low', all),
  tool('inspect_service_adapter', 'Product adapter', 'Run a reviewed product-specific read-only adapter after fingerprinting.', 'service', 'low', all),
  tool('discover_service_hosts', 'Service-host discovery', 'Combine passive names, supplied hints and bounded HTTPS verification.', 'discovery', 'low', all),
  tool('list_service_adapters', 'Adapter catalogue', 'Expose installed product adapters and fingerprint packs to the agent.', 'control', 'passive', all),
  tool('list_generated_probes', 'Generated probe catalogue', 'List eligible administrator-reviewed declarative probes.', 'control', 'passive', all),
  tool('execute_generated_probe', 'Generated probe runner', 'Execute an eligible checksum-bound declarative request plan.', 'control', 'low', all),
  tool('list_security_framework_references', 'Security framework catalogue', 'Provide curated OWASP and EU CRA reference semantics.', 'intelligence', 'passive', all),
  tool('read_public_source', 'Public source reader', 'Read a bounded public HTTPS documentation page.', 'intelligence', 'passive', all),
  tool('query_github_advisory', 'GitHub advisory lookup', 'Retrieve a concrete GHSA or CVE advisory.', 'intelligence', 'passive', all),
  tool('query_cisa_kev', 'CISA KEV lookup', 'Check a confirmed CVE against the authoritative exploited catalogue.', 'intelligence', 'passive', all),
  tool('query_epss', 'EPSS lookup', 'Retrieve exploitation probability for confirmed CVEs.', 'intelligence', 'passive', all),
  tool('query_osv', 'OSV lookup', 'Query vulnerabilities for an exact package and observed version.', 'intelligence', 'passive', all),
  tool('query_github_releases', 'GitHub release lookup', 'Compare an observed version with an official repository.', 'intelligence', 'passive', all),
  tool('query_nvd_cves', 'NVD candidate lookup', 'Search NVD after exact product and version evidence exists.', 'intelligence', 'passive', all),
  tool('query_cwe', 'MITRE CWE lookup', 'Retrieve the authoritative definition of a concrete weakness.', 'intelligence', 'passive', all),
  tool('query_product_lifecycle', 'Product lifecycle lookup', 'Compare an observed release with endoflife.date.', 'intelligence', 'passive', all),
  tool('query_cve_record', 'CVE record lookup', 'Retrieve the canonical CVE Program record and affected ranges.', 'intelligence', 'passive', all),
  tool('query_openssf_scorecard', 'OpenSSF Scorecard', 'Read supply-chain context for a confirmed official repository.', 'intelligence', 'passive', all),
  tool('record_finding', 'Finding recorder', 'Persist evidence-backed conclusions and their asset attribution.', 'control', 'passive', all, 'wellguard', true),
  tool('inspect_safe_web_audit', 'Safe web audit', 'Run fixed GET-only exposure checks with strict signatures.', 'configuration', 'low', standard),
  tool('inspect_browser_session_controls', 'Browser session controls', 'Compare anonymous cookie and CORS behavior without retaining values.', 'session', 'low', standard),
  tool('run_vanguard_observation', 'Vanguard evidence collector', 'Run pinned evidence-first domain observation and import its deterministic projection.', 'integration', 'low', active, 'vanguard'),
  tool('inspect_reviewed_nuclei', 'Reviewed Nuclei checks', 'Run only repository-reviewed GET templates with strict matches.', 'configuration', 'low', active),
  tool('inspect_unknown_web_service', 'Unknown service recognition', 'Correlate bounded response, favicon and pinned fingerprints.', 'service', 'low', active),
  tool('inspect_input_error_handling', 'Input error differential', 'Compare fixed inert quoted input without injection payloads.', 'input-validation', 'low', active),
  tool('inspect_rate_limit_controls', 'Rate-control observation', 'Run a capped sequential comparison on a known read-only path.', 'configuration', 'low', active),
  tool('propose_generated_probe', 'Probe proposal', 'Create a schema-validated declarative probe for administrator review.', 'control', 'passive', active),
  tool('inspect_authentication_controls', 'Authentication controls', 'Use a fixed bounded credential and tautology test set.', 'authentication', 'interactive', interactive),
  tool('probe_encoding_filter_bypass', 'Encoding boundary comparison', 'Compare fixed path encodings on previously observed files.', 'input-validation', 'interactive', interactive),
  tool('inspect_emulated_page', 'Emulated DOM review', 'Exercise a fixed inert marker in a bounded emulated page.', 'client-side', 'interactive', interactive),
  tool('crawl_web_application', 'Application crawl', 'Inventory same-origin pages, forms and parameters without submission.', 'discovery', 'low', unbounded),
  tool('inspect_api_schema', 'API schema inspection', 'Parse a discovered OpenAPI schema and sample GET operations only.', 'api', 'low', unbounded),
  tool('sweep_full_port_range', 'Full TCP range', 'Perform a high-concurrency connect scan across a selected range.', 'discovery', 'interactive', unbounded),
  tool('mine_frontend_bundles', 'Deep bundle mining', 'Extract API routes, client routes and secret-shaped values.', 'api', 'low', unbounded),
  tool('probe_http_method_surface', 'HTTP method surface', 'Send fixed empty OPTIONS, HEAD, TRACE and PATCH requests.', 'configuration', 'interactive', unbounded),
  tool('sweep_common_paths', 'Content-validating path sweep', 'Read fixed candidate paths and reject root or SPA fallbacks.', 'discovery', 'interactive', unbounded),
  tool('analyze_token_structure', 'Offline token analysis', 'Decode a retained JWT-shaped value without sending it.', 'session', 'passive', unbounded),
  tool('replay_with_acquired_session', 'Authenticated session replay', 'Compare known paths after a bounded successful login check.', 'authorization', 'interactive', unbounded),
  tool('probe_boundary_validation', 'API boundary validation', 'Submit fixed type-aware boundary values to a discovered endpoint.', 'input-validation', 'interactive', unbounded),
  tool('review_dynamic_dom', 'Chromium DOM review', 'Use packaged Chromium with a fixed inert marker on known routes.', 'client-side', 'interactive', unbounded)
];

export function defaultAgentToolPolicy(name: string): AgentToolPolicy | undefined {
  const entry = AGENT_TOOL_CATALOG.find((item) => item.name === name);
  return entry ? { name, enabled: true, profiles: [...entry.defaultProfiles] } : undefined;
}

export function compiledAgentToolSupports(name: string, profile: ScanMode): boolean {
  return AGENT_TOOL_CATALOG.some((item) => item.name === name && item.defaultProfiles.includes(profile));
}
