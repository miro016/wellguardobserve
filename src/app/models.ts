export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type NodeState = 'risk' | 'warning' | 'healthy' | 'observed' | 'unknown';
export type NodeKind = 'domain' | 'edge' | 'server' | 'port' | 'service';

export interface Target {
  id: string;
  name: string;
  hostname: string;
  hostHints: string[];
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
  authorizationReason: string;
}

export interface Finding {
  id: string; target: string; scan: string; title: string; summary: string; severity: Severity;
  confidence: number; asset: string; evidence: string[]; remediation: string; sourceUrls: string[];
  cveIds: string[]; weaknessIds: string[];
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
  id: string; target: string; mode: 'light' | 'standard'; status: 'queued' | 'processing' | 'cancelling' | 'cancelled' | 'completed' | 'failed';
  startedAt: string; completedAt: string; error: string; created: string;
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

export interface EvidenceItem { label: string; value: string; evidence: string; }

export interface TopologyNode {
  id: string; kind: NodeKind; label: string; subtitle: string; state: NodeState; x: number; y: number;
  details: EvidenceItem[]; findingIds: string[];
}

export interface TopologyEdge { from: string; to: string; label?: string; }
