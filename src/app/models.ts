export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Target {
  id: string;
  name: string;
  hostname: string;
  authorizationStatus: 'verified' | 'admin_override' | 'pending';
  status: 'observed' | 'scanning' | 'paused';
  lastScanAt: string;
  assetCount: number;
  findingCount: number;
  posture: number;
}

export interface Finding {
  id: string;
  title: string;
  summary: string;
  severity: Severity;
  confidence: number;
  asset: string;
  evidence: string[];
  source?: string;
  created: string;
  status: 'open' | 'accepted' | 'resolved';
}

export interface TlsObservation {
  hostname: string;
  valid: boolean;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  subjectAltNames: string[];
}
