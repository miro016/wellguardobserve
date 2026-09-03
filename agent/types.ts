export interface AuthorizedTarget {
  id: string;
  hostname: string;
  authorizationStatus: 'verified' | 'admin_override';
  allowPrivateAddresses?: boolean;
}

export interface AgentAction {
  tool: string;
  input: Record<string, unknown>;
  summary: string;
  at: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AgentFinding {
  title: string;
  summary: string;
  severity: FindingSeverity;
  confidence: number;
  asset: string;
  evidence: string[];
  remediation: string;
  sourceUrls: string[];
}

export interface TlsEvidence {
  hostname: string;
  port: number;
  valid: boolean;
  authorizationError: string | null;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  cipher: string;
  fingerprint256: string;
  subjectAltNames: string[];
}

export interface InvestigationReport {
  target: AuthorizedTarget;
  summary: string;
  findings: AgentFinding[];
  actions: AgentAction[];
  tls: TlsEvidence[];
  startedAt: string;
  completedAt: string;
}
