import type { ScanMode, ScanPolicySnapshot } from './types';

export interface AgentScanProfile extends ScanPolicySnapshot {
  allowSafeWebAudit: boolean;
  allowNucleiAudit: boolean;
  allowUnknownWebInspection: boolean;
  agentInstructions: string;
}

const VERSION = 'scan-policy-v1';
const CORE_TOOLS = [
  'dns', 'certificate-transparency', 'rdap', 'tls', 'bounded-tcp-connect', 'passive-banner',
  'single-http-get', 'service-discovery', 'configuration-review', 'public-metadata', 'service-adapters',
  'frontend-api-evidence', 'authoritative-advisory-sources'
];

export const AGENT_SCAN_PROFILES: Record<ScanMode, AgentScanProfile> = {
  light: {
    id: 'light', name: 'Baseline', version: VERSION, maxActions: 22, nucleiRequestsPerSecond: 0,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: CORE_TOOLS,
    nucleiPolicy: 'disabled', consentRequired: false, allowSafeWebAudit: false, allowNucleiAudit: false, allowUnknownWebInspection: false,
    agentInstructions: 'Prioritize an essential perimeter inventory. Do not attempt exhaustive follow-up; retain limitations when the budget is insufficient.'
  },
  standard: {
    id: 'standard', name: 'Standard', version: VERSION, maxActions: 64, nucleiRequestsPerSecond: 0,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1'],
    nucleiPolicy: 'disabled', consentRequired: false, allowSafeWebAudit: true, allowNucleiAudit: false, allowUnknownWebInspection: false,
    agentInstructions: 'Perform adaptive service discovery and use the reviewed safe web audit on higher-value application and administration surfaces.'
  },
  extended: {
    id: 'extended', name: 'Extended lab', version: VERSION, maxActions: 96, nucleiRequestsPerSecond: 2,
    methods: ['DNS', 'TLS handshake', 'TCP connect', 'HTTP GET'], enabledTools: [...CORE_TOOLS, 'safe-web-audit-v1', 'reviewed-nuclei-get-v1', 'unknown-web-recognition-v1'],
    nucleiPolicy: 'reviewed local templates only; HTTP GET only; no redirects, OOB, code, headless, unsigned downloads, fuzzing or DAST',
    consentRequired: true, allowSafeWebAudit: true, allowNucleiAudit: true, allowUnknownWebInspection: true,
    agentInstructions: 'This explicitly approved extended profile can use the reviewed local Nuclei audit and unknown-web recognition when direct evidence leaves a meaningful application surface unidentified. It is still reconnaissance-only and GET-only.'
  }
};

export function resolveScanProfile(value: unknown): AgentScanProfile {
  return AGENT_SCAN_PROFILES[String(value) as ScanMode] || AGENT_SCAN_PROFILES.standard;
}

export function policySnapshot(profile: AgentScanProfile): ScanPolicySnapshot {
  const { allowSafeWebAudit: _safe, allowNucleiAudit: _nuclei, allowUnknownWebInspection: _unknown, agentInstructions: _instructions, ...snapshot } = profile;
  return structuredClone(snapshot);
}
