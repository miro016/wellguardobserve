import type { ScanMode, ScanPolicySnapshot } from './types';

export interface AgentScanProfile extends ScanPolicySnapshot {
  allowSafeWebAudit: boolean;
  allowNucleiAudit: boolean;
  allowUnknownWebInspection: boolean;
  allowBrowserSessionReview: boolean;
  allowActiveValidation: boolean;
  agentInstructions: string;
}

const VERSION = 'scan-policy-v2';
const CORE_TOOLS = [
  'dns', 'certificate-transparency', 'rdap', 'tls', 'bounded-tcp-connect', 'passive-banner',
  'single-http-get', 'service-discovery', 'configuration-review', 'public-metadata', 'service-adapters',
  'frontend-api-evidence', 'authoritative-advisory-sources', 'security-framework-reference-catalog'
];

export const AGENT_SCAN_PROFILES: Record<ScanMode, AgentScanProfile> = {
  light: {
    id: 'light', name: 'Baseline', version: VERSION, maxActions: 22, nucleiRequestsPerSecond: 0,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: CORE_TOOLS,
    nucleiPolicy: 'disabled', consentRequired: false, allowSafeWebAudit: false, allowNucleiAudit: false, allowUnknownWebInspection: false, allowBrowserSessionReview: false, allowActiveValidation: false,
    agentInstructions: 'Prioritize an essential perimeter inventory. Do not attempt exhaustive follow-up; retain limitations when the budget is insufficient.'
  },
  standard: {
    id: 'standard', name: 'Standard', version: VERSION, maxActions: 68, nucleiRequestsPerSecond: 0,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1'],
    nucleiPolicy: 'disabled', consentRequired: false, allowSafeWebAudit: true, allowNucleiAudit: false, allowUnknownWebInspection: false, allowBrowserSessionReview: true, allowActiveValidation: false,
    agentInstructions: 'Perform adaptive service discovery, use the reviewed safe web audit on higher-value surfaces, and inspect observable cookie and CORS controls on meaningful web applications.'
  },
  extended: {
    id: 'extended', name: 'Active validation', version: VERSION, maxActions: 104, nucleiRequestsPerSecond: 2,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'browser-session-controls-v1', 'quoted-input-differential-v1', 'bounded-rate-controls-v1', 'reviewed-nuclei-get-v1', 'unknown-web-recognition-v1'],
    nucleiPolicy: 'reviewed local templates only; HTTP GET only; no redirects, OOB, code, headless, unsigned downloads, fuzzing or DAST',
    consentRequired: false, allowSafeWebAudit: true, allowNucleiAudit: true, allowUnknownWebInspection: true, allowBrowserSessionReview: true, allowActiveValidation: true,
    agentInstructions: 'Use active validation selectively on previously observed anonymous read-only paths: cookie/CORS posture, a fixed three-request quoted-input differential, and a capped sequential throttling/header-trust comparison. Use the reviewed local Nuclei audit and unknown-web recognition where evidence warrants them. Credential attempts remain prohibited.'
  }
};

export function resolveScanProfile(value: unknown): AgentScanProfile {
  return AGENT_SCAN_PROFILES[String(value) as ScanMode] || AGENT_SCAN_PROFILES.standard;
}

export function policySnapshot(profile: AgentScanProfile): ScanPolicySnapshot {
  const { allowSafeWebAudit: _safe, allowNucleiAudit: _nuclei, allowUnknownWebInspection: _unknown, allowBrowserSessionReview: _browser, allowActiveValidation: _active, agentInstructions: _instructions, ...snapshot } = profile;
  return structuredClone(snapshot);
}
