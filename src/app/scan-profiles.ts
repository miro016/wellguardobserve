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
  requiresConsent: boolean;
}

export const SCAN_PROFILES: readonly ScanProfileDefinition[] = [
  {
    id: 'light', name: 'Baseline', signal: 'LOW TRAFFIC',
    description: 'Essential perimeter inventory for frequent checks and production-safe monitoring.',
    maxActions: 22, requestRate: 'Nuclei disabled', methods: 'DNS · TLS · TCP connect · GET',
    capabilities: ['DNS and certificate posture', 'Root web fingerprints', 'Bounded port sample'], requiresConsent: false
  },
  {
    id: 'standard', name: 'Standard', signal: 'RECOMMENDED',
    description: 'Adaptive service discovery with deeper application metadata and safe exposure checks.',
    maxActions: 64, requestRate: 'Nuclei disabled', methods: 'DNS · TLS · TCP connect · GET',
    capabilities: ['Service-host discovery', 'Technology and API evidence', 'Reviewed safe web audit'], requiresConsent: false
  },
  {
    id: 'extended', name: 'Extended lab', signal: 'NON-PRODUCTION',
    description: 'A wider evidence budget for explicitly approved test estates and stubborn unknown services.',
    maxActions: 96, requestRate: '2 requests / sec', methods: 'DNS · TLS · TCP connect · GET',
    capabilities: ['Reviewed local Nuclei templates', 'Favicon and header recognition', 'More adaptive follow-up'], requiresConsent: true
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
