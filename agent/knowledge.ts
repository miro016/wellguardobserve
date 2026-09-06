import type { AgentAsset, AgentFinding, AssetKind } from './types';

export interface KnowledgeObservationInput {
  patternKey: string;
  category: string;
  technology: string;
  findingTitle: string;
  severity: AgentFinding['severity'];
  assetKey: string;
  assetKind: AssetKind | 'unknown';
  weaknessIds: string[];
  frameworkControls: string[];
  configurationSignals: string[];
}

const clean = (value: unknown) => String(value ?? '').trim();
const token = (value: string) => value.toLowerCase().replace(/https?:\/\/[^\s/]+/g, ' endpoint ').replace(/\b\d+(?:\.\d+){1,3}\b/g, ' version ').replace(/\b\d{2,5}\b/g, ' number ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 180) || 'uncategorized';

export function knowledgeCategory(finding: Pick<AgentFinding, 'title' | 'summary' | 'weaknessIds'>): string {
  const corpus = `${finding.title} ${finding.summary} ${(finding.weaknessIds || []).join(' ')}`.toLowerCase();
  if (/default (?:password|credential)|credential|password|authentication|authorization|identity|login|session|account/.test(corpus)) return 'Identity & access';
  if (/certificate|\btls\b|https|cipher|transport/.test(corpus)) return 'Transport security';
  if (/dnssec|\bdns\b|dmarc|\bspf\b|nameserver|domain/.test(corpus)) return 'Domain & email';
  if (/cors|content.security.policy|\bcsp\b|cookie|security header|clickjack|browser/.test(corpus)) return 'Browser boundary';
  if (/sql|injection|input validation|deserialization|template injection/.test(corpus)) return 'Input handling';
  if (/api|openapi|swagger|graphql|rest endpoint/.test(corpus)) return 'API surface';
  if (/cve-|outdated|unsupported|end.of.life|version/.test(corpus)) return 'Patch & lifecycle';
  if (/public|exposed|open port|directory index|debug|metadata|admin/.test(corpus)) return 'Exposure & configuration';
  return 'Configuration hygiene';
}

export function knowledgeTechnology(finding: Pick<AgentFinding, 'assetKey' | 'asset' | 'title'>, assets: AgentAsset[]): string {
  const asset = assets.find((item) => item.key === finding.assetKey);
  if (asset?.kind === 'service' && asset.label) return asset.label;
  const serviceKey = clean(finding.assetKey).match(/^service:.+?:\d+:(.+)$/)?.[1];
  if (serviceKey) return serviceKey.replace(/-/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
  const known = ['WordPress', 'Keycloak', 'Grafana', 'Jenkins', 'GitLab', 'Kubernetes', 'Nginx', 'Apache', 'Traefik', 'PocketBase', 'PostgreSQL', 'MySQL', 'Redis', 'MongoDB', 'Elasticsearch', 'RabbitMQ', 'Docker'];
  return known.find((name) => `${finding.title} ${finding.asset}`.toLowerCase().includes(name.toLowerCase())) || 'Technology not identified';
}

export function buildKnowledgeObservation(finding: AgentFinding, assets: AgentAsset[]): KnowledgeObservationInput {
  const technology = knowledgeTechnology(finding, assets);
  const category = knowledgeCategory(finding);
  const weakness = [...(finding.weaknessIds || [])].sort()[0] || '';
  const normalizedTitle = token(finding.title);
  const patternKey = token([category, technology, weakness || normalizedTitle].join(':'));
  const asset = assets.find((item) => item.key === finding.assetKey);
  return {
    patternKey, category, technology, findingTitle: finding.title, severity: finding.severity,
    assetKey: clean(finding.assetKey), assetKind: asset?.kind || 'unknown', weaknessIds: finding.weaknessIds || [],
    frameworkControls: (finding.frameworkRefs || []).map((reference) => `${reference.framework}:${reference.control}`),
    configurationSignals: [...new Set([
      ...(finding.weaknessIds || []),
      ...(finding.frameworkRefs || []).map((reference) => reference.control),
      finding.remediation ? token(finding.remediation).split('-').slice(0, 10).join('-') : ''
    ].filter(Boolean))].slice(0, 20)
  };
}
