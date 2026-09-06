import { AssetRecord, Finding, FindingLifecycle, Severity, SurfaceChangeState, TargetCriticality, TopologyEdge, TopologyNode } from '../models';
import type { Topology } from './topology.service';

export interface SurfaceChange {
  key: string;
  state: SurfaceChangeState;
  assetKey: string;
  kind: AssetRecord['kind'];
  label: string;
  before?: AssetRecord;
  after?: AssetRecord;
  changedFields: string[];
}

export interface PriorityFactor { label: string; value: string; points: number | null; available: boolean; evidence: string; }
export interface PriorityAssessment {
  score: number; band: 'urgent' | 'high' | 'planned' | 'watch'; label: string;
  factors: PriorityFactor[]; kev: boolean | null; epss: number | null; cvss: number | null;
}

const severityPoints: Record<Severity, number> = { critical: 38, high: 30, medium: 21, low: 11, info: 3 };
const criticalityPoints: Record<TargetCriticality, number> = { critical: 18, high: 13, standard: 7, low: 3 };
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
  return JSON.stringify(value);
};

function material(asset: AssetRecord): Record<string, unknown> {
  return {
    kind: asset.kind, label: asset.label, subtitle: asset.subtitle, state: asset.state, basis: asset.basis,
    details: [...asset.details].map((item) => ({ label: item.label, value: item.value })).sort((a, b) => a.label.localeCompare(b.label))
  };
}

export function diffAssets(current: AssetRecord[], previous: AssetRecord[]): SurfaceChange[] {
  const now = new Map(current.map((asset) => [asset.key, asset]));
  const before = new Map(previous.map((asset) => [asset.key, asset]));
  const changes: SurfaceChange[] = [];
  for (const asset of current) {
    const prior = before.get(asset.key);
    if (!prior) {
      changes.push({ key: `added:${asset.key}`, state: 'added', assetKey: asset.key, kind: asset.kind, label: asset.label, after: asset, changedFields: ['asset'] });
      continue;
    }
    const fields = ['kind', 'label', 'subtitle', 'state', 'basis', 'details'].filter((field) => canonical(material(asset)[field]) !== canonical(material(prior)[field]));
    if (fields.length) changes.push({ key: `changed:${asset.key}`, state: 'changed', assetKey: asset.key, kind: asset.kind, label: asset.label, before: prior, after: asset, changedFields: fields });
  }
  for (const asset of previous) if (!now.has(asset.key)) {
    changes.push({ key: `not_observed:${asset.key}`, state: 'not_observed', assetKey: asset.key, kind: asset.kind, label: asset.label, before: asset, changedFields: ['visibility'] });
  }
  const rank: Record<SurfaceChangeState, number> = { added: 3, changed: 2, not_observed: 1 };
  return changes.sort((a, b) => rank[b.state] - rank[a.state] || a.kind.localeCompare(b.kind) || a.label.localeCompare(b.label));
}

function numberNear(text: string, expression: RegExp): number | null {
  const match = text.match(expression);
  if (!match?.[1]) return null;
  const value = Number(match[1]);
  return Number.isFinite(value) ? value : null;
}

export function assessFindingPriority(finding: Finding, criticality: TargetCriticality = 'standard', lifecycle: FindingLifecycle = 'new'): PriorityAssessment {
  const corpus = [finding.title, finding.summary, ...finding.evidence, ...finding.sourceUrls].join(' ');
  const structured = finding.threatContext || {};
  const kev = typeof structured.kev === 'boolean' ? structured.kev : (/CISA.{0,30}(?:KEV|known exploited)|known exploited vulnerabilit/i.test(corpus) ? true : null);
  let epss = typeof structured.epss === 'number' ? structured.epss : numberNear(corpus, /EPSS(?:\s+(?:score|probability))?\s*[:=]?\s*(\d+(?:\.\d+)?)\s*%?/i);
  if (epss !== null && epss > 1) epss /= 100;
  if (epss !== null && (epss < 0 || epss > 1)) epss = null;
  const cvss = typeof structured.cvssScore === 'number' ? structured.cvssScore
    : numberNear(corpus, /\bCVSS(?:\s*v?[234](?:\.\d)?)?\s+(?:base\s+)?score\s*[:=]?\s*(\d+(?:\.\d+)?)/i)
      ?? numberNear(corpus, /\bCVSS\s*v?[234](?:\.\d)?\s*[:=]\s*(\d+(?:\.\d+)?)(?:\s|$|[.,;)])/i);
  const confidence = Math.round(Math.max(0, Math.min(100, finding.confidence)) / 10);
  const lifecycleAdjustment = ({ new: 5, persistent: 3, not_observed: -12, resolved: -25 } as Record<FindingLifecycle, number>)[lifecycle];
  const factors: PriorityFactor[] = [
    { label: 'Technical severity', value: finding.severity, points: severityPoints[finding.severity], available: true, evidence: 'Severity recorded with the finding.' },
    { label: 'Public reachability', value: 'External observation', points: 12, available: true, evidence: 'Wellguard findings originate from the authorized public perimeter.' },
    { label: 'Asset importance', value: criticality, points: criticalityPoints[criticality], available: true, evidence: 'Owner-managed business criticality; this is environmental context, not a CVSS metric.' },
    { label: 'Evidence confidence', value: `${finding.confidence}%`, points: confidence, available: true, evidence: 'Confidence influences queue position independently of severity.' },
    { label: 'CISA KEV', value: kev === null ? 'Not checked / retained' : kev ? 'Known exploited' : 'Checked — no match', points: kev ? 20 : 0, available: kev !== null, evidence: kev ? 'Retained evidence identifies a CISA KEV match.' : 'No affirmative KEV evidence is retained.' },
    { label: 'EPSS (30-day probability)', value: epss === null ? 'Not available' : `${(epss * 100).toFixed(1)}%`, points: epss === null ? null : Math.round(epss * 15), available: epss !== null, evidence: epss === null ? 'No EPSS value is retained for the matched CVE.' : 'EPSS probability retained by the vulnerability-source tool.' },
    { label: 'CVSS base', value: cvss === null ? 'Not available' : `${cvss.toFixed(1)} / 10`, points: cvss === null ? null : Math.round(Math.max(0, Math.min(10, cvss)) * 1.2), available: cvss !== null, evidence: cvss === null ? 'No validated CVSS metric is retained.' : `Vendor/NVD metric${structured.cvssVersion ? ` version ${structured.cvssVersion}` : ''}; Wellguard does not alter its vector.` },
    { label: 'Observation state', value: lifecycle.replace('_', ' '), points: lifecycleAdjustment, available: true, evidence: 'New and persistent current evidence ranks above assets not observed in the latest run.' }
  ];
  const score = Math.max(0, Math.min(100, factors.reduce((sum, factor) => sum + (factor.points || 0), 0)));
  const band = score >= 80 ? 'urgent' : score >= 60 ? 'high' : score >= 35 ? 'planned' : 'watch';
  return { score, band, label: ({ urgent: 'Act now', high: 'Prioritize', planned: 'Plan', watch: 'Watch' } as const)[band], factors, kev, epss, cvss };
}

function nodeSignature(node: TopologyNode): string {
  return canonical({ kind: node.kind, label: node.label, subtitle: node.subtitle, state: node.state, details: node.details.map((item) => [item.label, item.value]) });
}
function edgeKey(edge: TopologyEdge): string { return edge.id || `${edge.from}|${edge.to}|${edge.type || ''}`; }
function edgeSignature(edge: TopologyEdge): string { return canonical({ from: edge.from, to: edge.to, label: edge.label, type: edge.type, state: edge.state }); }

export function mergeTopologySnapshots(current: Topology, previous: Topology): Topology {
  const priorNodes = new Map(previous.nodes.map((node) => [node.id, node]));
  const currentNodeIds = new Set(current.nodes.map((node) => node.id));
  const nodes = current.nodes.map((node) => {
    const prior = priorNodes.get(node.id);
    return { ...node, changeState: !prior ? 'added' : nodeSignature(node) !== nodeSignature(prior) ? 'changed' : undefined } as TopologyNode;
  });
  nodes.push(...previous.nodes.filter((node) => !currentNodeIds.has(node.id)).map((node) => ({ ...node, state: 'unknown' as const, findingIds: [], changeState: 'not_observed' as const })));
  const priorEdges = new Map(previous.edges.map((edge) => [edgeKey(edge), edge]));
  const currentEdgeIds = new Set(current.edges.map(edgeKey));
  const edges = current.edges.map((edge) => {
    const prior = priorEdges.get(edgeKey(edge));
    return { ...edge, changeState: !prior ? 'added' : edgeSignature(edge) !== edgeSignature(prior) ? 'changed' : undefined } as TopologyEdge;
  });
  edges.push(...previous.edges.filter((edge) => !currentEdgeIds.has(edgeKey(edge))).map((edge) => ({ ...edge, state: 'unknown' as const, findingIds: [], changeState: 'not_observed' as const })));
  return { nodes, edges };
}
