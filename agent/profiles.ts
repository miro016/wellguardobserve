import type { ScanMode, ScanPolicySnapshot } from './types';

export interface AgentScanProfile extends ScanPolicySnapshot {
  allowSafeWebAudit: boolean;
  allowNucleiAudit: boolean;
  allowUnknownWebInspection: boolean;
  allowBrowserSessionReview: boolean;
  allowActiveValidation: boolean;
  allowAuthenticationProbe: boolean;
  allowEncodingBypass: boolean;
  allowHeadlessBrowser: boolean;
  agentInstructions: string;
}

const VERSION = 'scan-policy-v2';
const CORE_TOOLS = [
  'dns', 'certificate-transparency', 'rdap', 'tls', 'bounded-tcp-connect', 'passive-banner',
  'single-http-get', 'service-discovery', 'configuration-review', 'public-metadata', 'service-adapters',
  'public-directory-index-v1', 'frontend-api-evidence', 'authoritative-advisory-sources', 'security-framework-reference-catalog'
];

export const AGENT_SCAN_PROFILES: Record<ScanMode, AgentScanProfile> = {
  light: {
    id: 'light', name: 'Baseline', version: VERSION, maxActions: 22, nucleiRequestsPerSecond: 0,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: CORE_TOOLS,
    nucleiPolicy: 'disabled', consentRequired: false, allowSafeWebAudit: false, allowNucleiAudit: false, allowUnknownWebInspection: false, allowBrowserSessionReview: false, allowActiveValidation: false, allowAuthenticationProbe: false, allowEncodingBypass: false, allowHeadlessBrowser: false,
    agentInstructions: 'Prioritize an essential perimeter inventory. Do not attempt exhaustive follow-up; retain limitations when the budget is insufficient.'
  },
  standard: {
    id: 'standard', name: 'Standard', version: VERSION, maxActions: 68, nucleiRequestsPerSecond: 0,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1'],
    nucleiPolicy: 'disabled', consentRequired: false, allowSafeWebAudit: true, allowNucleiAudit: false, allowUnknownWebInspection: false, allowBrowserSessionReview: true, allowActiveValidation: false, allowAuthenticationProbe: false, allowEncodingBypass: false, allowHeadlessBrowser: false,
    agentInstructions: 'Perform adaptive service discovery, use the reviewed safe web audit on higher-value surfaces, and inspect observable cookie and CORS controls on meaningful web applications.'
  },
  extended: {
    id: 'extended', name: 'Active validation', version: VERSION, maxActions: 104, nucleiRequestsPerSecond: 2,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1', 'quoted-input-differential-v1', 'bounded-rate-controls-v1', 'reviewed-nuclei-get-v1', 'unknown-web-recognition-v1'],
    nucleiPolicy: 'reviewed local templates only; HTTP GET only; no redirects, OOB, code, headless, unsigned downloads, fuzzing or DAST',
    consentRequired: false, allowSafeWebAudit: true, allowNucleiAudit: true, allowUnknownWebInspection: true, allowBrowserSessionReview: true, allowActiveValidation: true, allowAuthenticationProbe: false, allowEncodingBypass: false, allowHeadlessBrowser: false,
    agentInstructions: 'Use active validation selectively on previously observed anonymous read-only paths: cookie/CORS posture, a fixed three-request quoted-input differential, and a capped sequential throttling/header-trust comparison. Use the reviewed local Nuclei audit and unknown-web recognition where evidence warrants them. Credential attempts remain prohibited.'
  },
  advanced: {
    id: 'advanced', name: 'Advanced interactive', version: VERSION, maxActions: 160, nucleiRequestsPerSecond: 2,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET', 'HTTP POST (bounded form/JSON probes)', 'Emulated DOM (bounded, same-origin)'],
    enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1', 'quoted-input-differential-v1', 'bounded-rate-controls-v1', 'reviewed-nuclei-get-v1', 'unknown-web-recognition-v1', 'authentication-probe-v1', 'encoding-filter-bypass-v1', 'headless-browser-review-v1'],
    nucleiPolicy: 'reviewed local templates only; HTTP GET only; no redirects, OOB, code, headless, unsigned downloads, fuzzing or DAST',
    consentRequired: true, allowSafeWebAudit: true, allowNucleiAudit: true, allowUnknownWebInspection: true, allowBrowserSessionReview: true, allowActiveValidation: true,
    allowAuthenticationProbe: true, allowEncodingBypass: true, allowHeadlessBrowser: true,
    agentInstructions: 'This profile performs interactive validation, not just GET observation. Use inspect_authentication_controls on login endpoints the evidence already surfaced: it sends a fixed list of up to 12 bounded credential/injection attempts and nothing else. Use probe_encoding_filter_bypass on directory listings or file paths already discovered, with fixed encoding variants only. Use inspect_emulated_page for pages where dynamic DOM behavior matters; it stays on the authorized origin and executes a fixed inert marker payload. Never invent payloads beyond these fixed tools.'
  },
  unbounded: {
    id: 'unbounded', name: 'Unbounded (admin decision)', version: VERSION, maxActions: 320, nucleiRequestsPerSecond: 4,
    methods: ['DNS', 'TLS handshake', 'TCP connect (full range)', 'HTTP GET', 'HTTP POST (bounded form/JSON probes)', 'HTTP introspection methods', 'Emulated DOM (bounded, same-origin)'],
    enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1', 'quoted-input-differential-v1', 'bounded-rate-controls-v1', 'reviewed-nuclei-get-v1', 'unknown-web-recognition-v1', 'authentication-probe-v1', 'encoding-filter-bypass-v1', 'emulated-dom-review-v1', 'full-port-sweep-v1', 'frontend-bundle-mining-v1', 'http-method-surface-v1', 'common-path-sweep-v1', 'offline-token-analysis-v1'],
    nucleiPolicy: 'reviewed local templates only; HTTP GET only; no redirects, OOB, code, headless, unsigned downloads, fuzzing or DAST',
    consentRequired: true, allowSafeWebAudit: true, allowNucleiAudit: true, allowUnknownWebInspection: true, allowBrowserSessionReview: true, allowActiveValidation: true,
    allowAuthenticationProbe: true, allowEncodingBypass: true, allowHeadlessBrowser: true,
    agentInstructions: 'Reserved for non-production or challenge environments and selected explicitly by an administrator. In addition to the Advanced toolset, you may run sweep_full_port_range for a complete TCP connect sweep, mine_frontend_bundles to extract endpoints and secrets from same-origin JavaScript, probe_http_method_surface for TRACE/OPTIONS style introspection, sweep_common_paths against the fixed in-module wordlist, and analyze_token_structure for offline JWT review. There is no traffic ceiling for these tools, but payloads remain the fixed module lists.'
  }
};

export function resolveScanProfile(value: unknown): AgentScanProfile {
  return AGENT_SCAN_PROFILES[String(value) as ScanMode] || AGENT_SCAN_PROFILES.standard;
}

export function policySnapshot(profile: AgentScanProfile): ScanPolicySnapshot {
  const { allowSafeWebAudit: _safe, allowNucleiAudit: _nuclei, allowUnknownWebInspection: _unknown, allowBrowserSessionReview: _browser, allowActiveValidation: _active, allowAuthenticationProbe: _auth, allowEncodingBypass: _enc, allowHeadlessBrowser: _browser2, agentInstructions: _instructions, ...snapshot } = profile;
  return structuredClone(snapshot);
}
