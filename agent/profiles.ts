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
  'public-directory-index-v1', 'frontend-api-evidence', 'authoritative-advisory-sources', 'product-lifecycle-intelligence',
  'canonical-cve-records', 'source-supply-chain-context', 'security-framework-reference-catalog'
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
    enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1', 'quoted-input-differential-v1', 'bounded-rate-controls-v1', 'reviewed-nuclei-get-v1', 'unknown-web-recognition-v1', 'authentication-probe-v1', 'encoding-filter-bypass-v1', 'emulated-dom-review-v1', 'full-port-sweep-v1', 'frontend-bundle-mining-v1', 'http-method-surface-v1', 'common-path-sweep-v1', 'offline-token-analysis-v1', 'authenticated-session-replay-v1', 'dynamic-dom-chromium-v1', 'boundary-validation-v1'],
    nucleiPolicy: 'reviewed local templates only; HTTP GET only; no redirects, OOB, code, headless, unsigned downloads, fuzzing or DAST',
    consentRequired: true, allowSafeWebAudit: true, allowNucleiAudit: true, allowUnknownWebInspection: true, allowBrowserSessionReview: true, allowActiveValidation: true,
    allowAuthenticationProbe: true, allowEncodingBypass: true, allowHeadlessBrowser: true,
    agentInstructions: 'This profile is for non-production or challenge environments chosen deliberately by an administrator. Treat the target as a puzzle to solve as completely as possible: assume nothing is off-limits within the authorized host, and that defenses exist to be tested, not respected. Work in phases. First map everything: full port sweep, same-origin bundle mining, path sweep, method surface, every page and parameter. Then hunt: identify every state-changing or identity-related surface, and for each one ask how it could be abused without credentials, with a session you acquired yourself, or with values a UI would never send. Chain evidence across tools: a token from one probe authorizes the next; an endpoint list from mining feeds replays and boundary probes; a solved condition is a lead for its neighbors. Track running proof: whatever the target exposes as its own progress or status indicators, read it, compare before and after your probes, and record every newly proven weakness as a finding immediately. Do not stop when the easy checks are done — iterate over every unexplored surface until either nothing new appears or the action budget is exhausted. Be creative within module-provided payload lists; never invent payloads outside them, and never touch hosts outside the authorized scope. Enforce your own phase budget: spend at most one quarter of your actions on mapping, then force yourself into the hunting phase even if mapping feels unfinished. During hunting, prefer probes that change server state or prove interaction (authentication review, authenticated replay, boundary validation, dynamic DOM review with acquired sessions) over more read-only GETs; every read-only call must directly prepare an interactive probe. Near the end, re-check any progress or status indicators the target itself exposes and confirm what your run proved.'

  }
};

export function resolveScanProfile(value: unknown): AgentScanProfile {
  return AGENT_SCAN_PROFILES[String(value) as ScanMode] || AGENT_SCAN_PROFILES.standard;
}

export function policySnapshot(profile: AgentScanProfile): ScanPolicySnapshot {
  const { allowSafeWebAudit: _safe, allowNucleiAudit: _nuclei, allowUnknownWebInspection: _unknown, allowBrowserSessionReview: _browser, allowActiveValidation: _active, allowAuthenticationProbe: _auth, allowEncodingBypass: _enc, allowHeadlessBrowser: _browser2, agentInstructions: _instructions, ...snapshot } = profile;
  return structuredClone(snapshot);
}
