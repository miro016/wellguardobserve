import type { ScopeGuard } from '../security/scope-guard';
import type { FrameworkReference } from '../types';

export interface AdapterManifest {
  id: string;
  name: string;
  version: string;
  products: string[];
  capabilities: string[];
  methods: Array<'GET' | 'TLS' | 'BANNER'>;
  maxRequests: number;
  sourceUrl: string;
}

export interface AdapterInput { hostname?: string; port?: number; tls?: boolean; basePath?: string; }

export interface AdapterFindingSuggestion {
  title: string; summary: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: number;
  asset: string; assetKey: string; relatedAssetKeys: string[]; relationKey: string;
  evidence: string[]; remediation: string; sourceUrls: string[]; cveIds: string[]; weaknessIds: string[];
  frameworkRefs?: FrameworkReference[];
}

export interface AdapterResult {
  adapter: { id: string; version: string; name: string };
  hostname: string;
  identified: boolean;
  product: string;
  observations: unknown;
  relations: Array<{ key: string; fromKey: string; toKey: string; type: string; label: string; confidence: number; basis: 'observed' | 'registry' | 'inferred' | 'owner_confirmed'; evidence: string[]; state: 'risk' | 'warning' | 'healthy' | 'observed' | 'unknown' }>;
  suggestedFindings: AdapterFindingSuggestion[];
  note: string;
}

export interface ServiceAdapter {
  manifest: AdapterManifest;
  inspect(scope: ScopeGuard, input: AdapterInput): Promise<AdapterResult>;
}
