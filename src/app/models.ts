export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type NodeState = 'risk' | 'warning' | 'healthy' | 'observed' | 'unknown';
export type NodeKind = 'domain' | 'hostname' | 'url' | 'network' | 'edge' | 'server' | 'port' | 'service';
export type ScanMode = 'light' | 'standard' | 'extended' | 'advanced' | 'unbounded';
export type TargetCriticality = 'critical' | 'high' | 'standard' | 'low';
export type SurfaceChangeState = 'added' | 'changed' | 'not_observed';
export type ChangeReviewStatus = 'unreviewed' | 'expected' | 'investigate' | 'resolved';
export type ObservationCadence = 'off' | 'daily' | 'weekly' | 'monthly';
export type ScheduledScanMode = Extract<ScanMode, 'light' | 'standard'>;
export type WorkspaceRole = 'owner' | 'admin' | 'operator' | 'viewer';

export interface Workspace {
  id: string; name: string; slug: string; description: string; status: 'active' | 'archived'; createdBy: string; created: string; updated: string;
}

export interface WorkspaceMember {
  id: string; workspace: string; user: string; role: WorkspaceRole; enabled: boolean; created: string; updated: string;
  userName: string; userEmail: string;
}

export interface WorkspaceUser {
  id: string; name: string; email: string; verified: boolean; created: string;
}

export interface ScanPolicySnapshot {
  id: ScanMode; name: string; version: string; maxActions: number; nucleiRequestsPerSecond: number;
  methods: string[]; enabledTools: string[]; nucleiPolicy: string; consentRequired: boolean;
}

export interface FrameworkReference {
  framework: 'OWASP WSTG' | 'OWASP ASVS' | 'EU CRA'; control: string; title: string; url: string;
  relationship: 'test-method' | 'verification-requirement' | 'regulatory-relevance'; note: string;
}

export interface CustomerNarrative {
  observed: string; possibleAttack: string; businessImpact: string; boundary: string;
}

export interface Target {
  id: string;
  workspace: string;
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
  criticality: TargetCriticality;
  tags: string[];
}

export interface CreateTargetInput {
  workspace: string;
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
  cveIds: string[]; weaknessIds: string[]; frameworkRefs: FrameworkReference[];
  customerNarrative: CustomerNarrative | null;
  assetKey: string; relatedAssetKeys: string[]; relationKey: string;
  observations: Array<{ scan: string; observedAt: string; profile?: string }>; runCount: number;
  created: string; status: 'open' | 'accepted' | 'resolved';
  threatContext?: ThreatContext;
}

export interface ThreatContext {
  kev?: boolean; epss?: number; cvssScore?: number; cvssVersion?: string; cvssVector?: string; sourceUrls?: string[];
}

export type FindingLifecycle = 'new' | 'persistent' | 'not_observed' | 'resolved';

export interface KnowledgeObservation {
  id: string; target: string; scan: string; patternKey: string; category: string; technology: string;
  findingTitle: string; severity: Severity; assetKey: string; assetKind: NodeKind | 'unknown'; weaknessIds: string[];
  frameworkControls: string[]; configurationSignals: string[]; observedAt: string; created: string;
}

export interface ScanEvaluation {
  id: string; workspace: string; target: string; scan: string; model: string; reasoningEffort: string; profile: string;
  qualityScore: number; toolSuccessRate: number; evidenceCoverage: number; sourceCoverage: number; assetLinkage: number;
  toolErrors: number; duplicateCalls: number; unknownServices: number; cacheHits: number; cacheMisses: number; originRequests: number;
  signals: Record<string, unknown>; created: string;
}

export interface FindingFeedback {
  id: string; workspace: string; target: string; finding: string; patternKey: string;
  verdict: 'confirmed' | 'false_positive' | 'unclear'; note: string; reviewedBy: string; created: string; updated: string;
}

export interface ImprovementProposal {
  id: string; workspace: string; proposalKey: string; kind: 'confidence_guard' | 'coverage_priority' | 'tool_reliability';
  scopeKey: string; title: string; rationale: string; evidence: Record<string, unknown>;
  recommendedAction: 'cap-confidence' | 'prioritize-unknown-service' | 'review-tool'; parameter: Record<string, unknown>;
  confidence: number; occurrences: number; status: 'proposed' | 'approved' | 'rejected'; reviewedBy: string;
  reviewedAt: string; reviewNote: string; applicationCount: number; lastAppliedAt: string; created: string; updated: string;
}

export interface GeneratedProbeAssertion {
  type: 'status-in' | 'header-present' | 'header-contains' | 'body-contains' | 'json-key-exists';
  values?: number[]; name?: string; value?: string; path?: string;
}

export interface GeneratedProbeStep {
  id: string; purpose: string; method: 'GET' | 'HEAD' | 'OPTIONS' | 'POST_JSON'; path: string;
  body?: Record<string, string>; assertions: GeneratedProbeAssertion[];
}

export interface GeneratedTool {
  id: string; workspace: string; name: string; title: string; summary: string; rationale: string;
  category: 'discovery' | 'configuration' | 'authentication' | 'authorization' | 'session' | 'input-validation' | 'client-side' | 'api';
  evidence: string[]; spec: { version: 'http-probe-v1'; steps: GeneratedProbeStep[] }; schemaVersion: string; checksum: string;
  compatibleProfiles: ScanMode[]; requestCeiling: number; riskLevel: 'passive' | 'low' | 'interactive';
  status: 'proposed' | 'approved' | 'rejected' | 'disabled'; minProfile: ScanMode; unboundedAutoUse: boolean;
  generatedByModel: string; sourceScan: string; sourceTarget: string; reviewedBy: string; reviewedAt: string; reviewNote: string;
  created: string; updated: string;
}

export interface GeneratedToolExecution {
  id: string; workspace: string; tool: string; target: string; scan: string; profile: ScanMode; hostname: string;
  status: 'completed' | 'blocked' | 'failed'; requestCount: number; matchedAssertions: number; summary: string; occurredAt: string;
}

export interface KnowledgePattern {
  key: string; title: string; category: string; technology: string; severity: Severity; weaknessIds: string[];
  occurrences: number; affectedTargetIds: string[]; currentCount: number; newCount: number; persistentCount: number;
  firstSeenAt: string; lastSeenAt: string; findingIds: string[];
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

export interface ChangeReview {
  id: string; target: string; scan: string; changeKey: string; status: ChangeReviewStatus; note: string;
  reviewedBy: string; reviewedAt: string; created: string; updated: string;
}

export interface ObservationSchedule {
  id: string; target: string; enabled: boolean; cadence: Exclude<ObservationCadence, 'off'>; mode: ScheduledScanMode;
  nextRunAt: string; lastQueuedAt: string; lastRequest: string; created: string; updated: string;
}

export interface PublicIdentity {
  id: string; target: string; scan: string; key: string; kind: 'person' | 'mailbox' | 'organization'; displayName: string;
  email: string; publicLinks: string[]; sourceUrls: string[]; evidence: string[]; sourceAssetKey: string; confidence: number;
  employmentStatus: 'unknown' | 'current' | 'former' | 'not_applicable'; reviewNote: string; confirmedBy: string; confirmedAt: string; created: string;
}

export interface TopologyNode {
  id: string; kind: NodeKind; label: string; subtitle: string; state: NodeState; x: number; y: number;
  details: EvidenceItem[]; findingIds: string[]; changeState?: SurfaceChangeState;
}

export interface TopologyEdge {
  id?: string; from: string; to: string; label?: string; type?: string; state?: NodeState; confidence?: number;
  basis?: EvidenceBasis; evidence?: string[]; findingIds?: string[]; changeState?: SurfaceChangeState;
}
