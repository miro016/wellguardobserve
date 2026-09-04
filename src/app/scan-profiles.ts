import type { ScanMode } from './models';

export interface ScanProfileDefinition {
  id: ScanMode;
  name: string;
  signal: string;
  description: string;
  maxActions: number;
  requestRate: string;
  methods: string;
  capabilities: string[];
}

export const SCAN_PROFILES: readonly ScanProfileDefinition[] = [
  {
    id: 'light', name: 'Baseline', signal: 'LOW TRAFFIC',
    description: 'Essential perimeter inventory for frequent checks and production-safe monitoring.',
    maxActions: 22, requestRate: 'Nuclei disabled', methods: 'DNS · TLS · TCP connect · GET',
    capabilities: ['DNS and certificate posture', 'Root web fingerprints', 'Bounded port sample']
  },
  {
    id: 'standard', name: 'Standard', signal: 'RECOMMENDED',
    description: 'Adaptive discovery plus observable browser, cookie, CORS, and safe exposure checks.',
    maxActions: 68, requestRate: 'Nuclei disabled', methods: 'DNS · TLS · TCP connect · GET',
    capabilities: ['Service-host discovery', 'Technology and API evidence', 'Cookie and CORS posture']
  },
  {
    id: 'extended', name: 'Active validation', signal: 'POC / BOUNDED',
    description: 'Fixed low-impact validation for input errors, browser trust, throttling, and stubborn unknown services.',
    maxActions: 104, requestRate: 'Max 13-request rate check', methods: 'DNS · TLS · TCP connect · GET only',
    capabilities: ['Quoted-input differential', 'Cookie, CORS and rate controls', 'Reviewed local Nuclei templates']
  }
] as const;

export const DEFAULT_SCAN_PROFILE: ScanMode = 'standard';

export function scanProfile(mode: ScanMode | string | null | undefined): ScanProfileDefinition {
  return SCAN_PROFILES.find((profile) => profile.id === mode) || SCAN_PROFILES[1]!;
}

export function storedScanProfile(): ScanMode {
  const stored = localStorage.getItem('wellguard-scan-depth');
  return SCAN_PROFILES.some((profile) => profile.id === stored) ? stored as ScanMode : DEFAULT_SCAN_PROFILE;
}
