export interface AuthorizedTarget {
  id: string;
  hostname: string;
  hostHints?: string[];
  authorizedHosts?: string[];
  authorizationStatus: 'verified' | 'admin_override';
  allowPrivateAddresses?: boolean;
}

export type ScanMode = 'light' | 'standard' | 'extended' | 'advanced';

export interface ScanPolicySnapshot {
  id: ScanMode;
  name: string;
  version: string;
  maxActions: number;
  nucleiRequestsPerSecond: number;
  methods: string[];
  enabledTools: string[];
  nucleiPolicy: string;
  consentRequired: boolean;
}

export interface AgentAction {
  tool: string;
  input: Record<string, unknown>;
  summary: string;
  at: string;
}

export interface AgentMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  toolName: string;
  sequence: number;
  at: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FrameworkReference {
  framework: 'OWASP WSTG' | 'OWASP ASVS' | 'EU CRA';
  control: string;
  title: string;
  url: string;
  relationship: 'test-method' | 'verification-requirement' | 'regulatory-relevance';
  note: string;
}

export interface CustomerNarrative {
  observed: string;
  possibleAttack: string;
  businessImpact: string;
  boundary: string;
}

export interface AgentFinding {
  title: string;
  summary: string;
  severity: FindingSeverity;
  confidence: number;
  asset: string;
  evidence: string[];
  remediation: string;
  sourceUrls: string[];
  cveIds: string[];
  weaknessIds: string[];
  frameworkRefs?: FrameworkReference[];
  customerNarrative?: CustomerNarrative;
  assetKey?: string;
  relatedAssetKeys?: string[];
  relationKey?: string;
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
  certificateEmails: string[];
}

export type AssetKind = 'domain' | 'hostname' | 'edge' | 'network' | 'server' | 'port' | 'service';
export type EvidenceBasis = 'observed' | 'registry' | 'inferred' | 'owner_confirmed';
export type AssetState = 'risk' | 'warning' | 'healthy' | 'observed' | 'unknown';
export interface AgentAssetFact { label: string; value: string; evidence: string; confidence: number; basis: EvidenceBasis; }
export interface AgentAsset {
  key: string; kind: AssetKind; label: string; subtitle: string; state: AssetState; confidence: number; basis: EvidenceBasis; details: AgentAssetFact[];
}
export interface AgentAssetRelation {
  key: string; fromKey: string; toKey: string; type: string; label: string; state: AssetState; confidence: number; basis: EvidenceBasis; evidence: string[]; findingTitles: string[];
}
export interface AgentPublicIdentity {
  key: string; kind: 'person' | 'mailbox' | 'organization'; displayName: string; email: string; publicLinks: string[];
  sourceUrls: string[]; evidence: string[]; sourceAssetKey: string; confidence: number; employmentStatus: 'unknown' | 'current' | 'former' | 'not_applicable'; reviewNote: string;
}

export interface InvestigationReport {
  target: AuthorizedTarget;
  summary: string;
  findings: AgentFinding[];
  actions: AgentAction[];
  conversation: AgentMessage[];
  tls: TlsEvidence[];
  assets: AgentAsset[];
  relations: AgentAssetRelation[];
  identities: AgentPublicIdentity[];
  startedAt: string;
  completedAt: string;
}
