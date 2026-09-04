export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type NodeState = 'risk' | 'warning' | 'healthy' | 'observed' | 'unknown';
export type NodeKind = 'domain' | 'hostname' | 'network' | 'edge' | 'server' | 'port' | 'service';
export type ScanMode = 'light' | 'standard' | 'extended';

export interface ScanPolicySnapshot {
  id: ScanMode; name: string; version: string; maxActions: number; nucleiRequestsPerSecond: number;
  methods: string[]; enabledTools: string[]; nucleiPolicy: string; consentRequired: boolean;
}

export interface Target {
  id: string;
  name: string;
  hostname: string;
  hostHints: string[];
  authorizedHosts: string[];
  authorizationStatus: 'verified' | 'admin_override' | 'pending';
  status: 'observed' | 'scanning' | 'paused';
  lastScanAt: string;
  assetCount: number;
  findingCount: number;
  posture: number;
}

export interface CreateTargetInput {
  name: string;
  hostname: string;
  hostHints: string[];
  authorizedHosts: string[];
  authorizationReason: string;
}

export interface TargetScope {
  id: string; target: string; hostname: string; kind: 'exact_host'; reason: string; enabled: boolean; authorizedAt: string;
}

export interface Finding {
  id: string; target: string; scan: string; title: string; summary: string; severity: Severity;
  confidence: number; asset: string; evidence: string[]; remediation: string; sourceUrls: string[];
  cveIds: string[]; weaknessIds: string[];
  assetKey: string; relatedAssetKeys: string[]; relationKey: string;
  created: string; status: 'open' | 'accepted' | 'resolved';
}

export interface TlsObservation {
  id?: string; scan?: string; hostname: string; port?: number; valid: boolean; authorizationError?: string | null;
  issuer: string; subject?: string; validFrom: string; validTo: string; daysRemaining: number; protocol: string;
  cipher?: string; fingerprint256?: string; subjectAltNames: string[];
  certificateEmails?: string[];
}

export interface Scan {
  id: string; target: string; request?: string; status: 'running' | 'cancelled' | 'completed' | 'failed'; startedAt: string;
  completedAt: string; summary: string; error: string; created: string;
}

export interface ScanRequest {
  id: string; target: string; mode: ScanMode; status: 'queued' | 'processing' | 'cancelling' | 'cancelled' | 'completed' | 'failed';
  startedAt: string; completedAt: string; heartbeatAt: string; phase: string; actionCount: number; messageCount: number; error: string; created: string;
  profileSnapshot: ScanPolicySnapshot | null; extendedConsent: boolean;
}

export interface AgentActionRecord {
  id: string; target: string; scan: string; tool: string; input: Record<string, unknown>; summary: string; occurredAt: string;
}

export interface AgentMessageRecord {
  id: string; target: string; scan: string; role: 'system' | 'user' | 'assistant' | 'tool'; content: string;
  toolName: string; sequence: number; occurredAt: string;
}

export interface CertificateTransparencyRecord {
  id: string | number; commonName: string; names: string[]; issuerCaId: number | null; issuerName: string; notBefore: string; notAfter: string;
  serialNumber: string; resultCount: number;
}

export type EvidenceBasis = 'observed' | 'registry' | 'inferred' | 'owner_confirmed';
export interface EvidenceItem { label: string; value: string; evidence: string; confidence?: number; basis?: EvidenceBasis; }

export interface AssetRecord {
  id: string; target: string; scan: string; key: string; kind: NodeKind; label: string; subtitle: string;
  state: NodeState; confidence: number; basis: EvidenceBasis; details: EvidenceItem[];
}

export interface AssetRelationRecord {
  id: string; target: string; scan: string; key: string; fromKey: string; toKey: string; type: string; label: string;
  state: NodeState; confidence: number; basis: EvidenceBasis; evidence: string[]; findingTitles: string[];
}

export interface PublicIdentity {
  id: string; target: string; scan: string; key: string; kind: 'person' | 'mailbox' | 'organization'; displayName: string;
  email: string; publicLinks: string[]; sourceUrls: string[]; evidence: string[]; sourceAssetKey: string; confidence: number;
  employmentStatus: 'unknown' | 'current' | 'former' | 'not_applicable'; reviewNote: string; confirmedBy: string; confirmedAt: string; created: string;
}

export interface TopologyNode {
  id: string; kind: NodeKind; label: string; subtitle: string; state: NodeState; x: number; y: number;
  details: EvidenceItem[]; findingIds: string[];
}

export interface TopologyEdge {
  id?: string; from: string; to: string; label?: string; type?: string; state?: NodeState; confidence?: number;
  basis?: EvidenceBasis; evidence?: string[]; findingIds?: string[];
}
