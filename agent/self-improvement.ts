import type { AgentAction, InvestigationReport } from './types';
import type { CacheTelemetry } from './external-cache';

export interface ScanEvaluationInput {
  qualityScore: number;
  toolSuccessRate: number;
  evidenceCoverage: number;
  sourceCoverage: number;
  assetLinkage: number;
  toolErrors: number;
  duplicateCalls: number;
  unknownServices: number;
  cacheHits: number;
  cacheMisses: number;
  originRequests: number;
  signals: { failingTools: string[]; unknownAssetKeys: string[]; cacheBySource: CacheTelemetry['bySource'] };
}

export interface ImprovementProposalCandidate {
  proposalKey: string;
  kind: 'confidence_guard' | 'coverage_priority' | 'tool_reliability';
  scopeKey: string;
  title: string;
  rationale: string;
  evidence: Record<string, unknown>;
  recommendedAction: 'cap-confidence' | 'prioritize-unknown-service' | 'review-tool';
  parameter: Record<string, unknown>;
  confidence: number;
  occurrences: number;
}

export interface LearningDirectives {
  confidenceCaps: Record<string, number>;
  prioritizeUnknownServices: boolean;
  proposalIds: string[];
}

const ratio = (numerator: number, denominator: number) => denominator ? numerator / denominator : 1;
const rounded = (value: number) => Math.round(value * 1_000) / 1_000;

export function evaluateScan(report: InvestigationReport, cache: CacheTelemetry): ScanEvaluationInput {
  const networkActions = report.actions.filter((action) => action.tool !== 'record_finding');
  const failed = networkActions.filter((action) => action.summary.startsWith('{"_wellguardError"'));
  const duplicates = networkActions.filter((action) => action.summary.startsWith('Duplicate network or source call skipped'));
  const findings = report.findings;
  const evidenceCoverage = ratio(findings.filter((finding) => finding.evidence.length > 0).length, findings.length);
  const sourceCoverage = ratio(findings.filter((finding) => finding.sourceUrls.length > 0 || finding.evidence.some((line) => /https?:\/\//i.test(line))).length, findings.length);
  const assetLinkage = ratio(findings.filter((finding) => Boolean(finding.assetKey)).length, findings.length);
  const unknownAssets = report.assets.filter((asset) => asset.kind === 'service' && /unknown|unidentified|generic web/i.test(`${asset.label} ${asset.subtitle}`));
  const toolSuccessRate = ratio(networkActions.length - failed.length, networkActions.length);
  const qualityScore = Math.round(100 * (toolSuccessRate * .32 + evidenceCoverage * .28 + sourceCoverage * .16 + assetLinkage * .24));
  return {
    qualityScore, toolSuccessRate: rounded(toolSuccessRate), evidenceCoverage: rounded(evidenceCoverage), sourceCoverage: rounded(sourceCoverage), assetLinkage: rounded(assetLinkage),
    toolErrors: failed.length, duplicateCalls: duplicates.length, unknownServices: unknownAssets.length,
    cacheHits: cache.hits, cacheMisses: cache.misses, originRequests: cache.originRequests,
    signals: { failingTools: [...new Set(failed.map((action) => action.tool))], unknownAssetKeys: unknownAssets.map((asset) => asset.key), cacheBySource: cache.bySource }
  };
}

export function improvementCandidates(input: {
  falsePositivePatterns: Array<{ patternKey: string; count: number }>;
  evaluations: Array<Pick<ScanEvaluationInput, 'unknownServices' | 'toolErrors' | 'signals'>>;
}): ImprovementProposalCandidate[] {
  const candidates: ImprovementProposalCandidate[] = [];
  for (const pattern of input.falsePositivePatterns.filter((item) => item.count >= 2)) {
    candidates.push({
      proposalKey: `confidence-guard:${pattern.patternKey}`, kind: 'confidence_guard', scopeKey: pattern.patternKey,
      title: 'Cap confidence for a repeatedly disputed pattern',
      rationale: `${pattern.count} administrator reviews marked findings in this pattern as false positives. Future matching conclusions should remain visible but carry lower confidence until their evidence rule is improved.`,
      evidence: { falsePositiveReviews: pattern.count, patternKey: pattern.patternKey }, recommendedAction: 'cap-confidence',
      parameter: { maximumConfidence: 60 }, confidence: Math.min(95, 55 + pattern.count * 10), occurrences: pattern.count
    });
  }
  const unknownRuns = input.evaluations.filter((evaluation) => evaluation.unknownServices > 0).length;
  const unknownTotal = input.evaluations.reduce((sum, evaluation) => sum + evaluation.unknownServices, 0);
  if (unknownRuns >= 2) candidates.push({
    proposalKey: 'coverage-priority:unknown-web-services', kind: 'coverage_priority', scopeKey: 'unknown-web-services',
    title: 'Prioritize unresolved web-service identification',
    rationale: `${unknownTotal} unidentified service observations occurred across ${unknownRuns} evaluated scans. The approved unknown-service inspector can be prioritized when direct HTTP evidence remains unresolved.`,
    evidence: { runsWithUnknownServices: unknownRuns, unknownServices: unknownTotal }, recommendedAction: 'prioritize-unknown-service',
    parameter: { enabled: true }, confidence: Math.min(90, 55 + unknownRuns * 8), occurrences: unknownRuns
  });
  const toolCounts = new Map<string, number>();
  for (const evaluation of input.evaluations) for (const tool of evaluation.signals.failingTools || []) toolCounts.set(tool, (toolCounts.get(tool) || 0) + 1);
  for (const [tool, count] of toolCounts) if (count >= 3) candidates.push({
    proposalKey: `tool-reliability:${tool}`, kind: 'tool_reliability', scopeKey: tool,
    title: `Review recurring ${tool} failures`,
    rationale: `The tool was recorded as unsuccessful in ${count} evaluated scans. Review timeouts, source availability, and parsing before changing its availability.`,
    evidence: { scansWithFailure: count, tool }, recommendedAction: 'review-tool', parameter: {}, confidence: Math.min(95, 60 + count * 6), occurrences: count
  });
  return candidates;
}

export function approvedPrompt(directives?: LearningDirectives): string {
  if (!directives?.prioritizeUnknownServices) return '';
  return '\nAPPROVED LEARNING DIRECTIVE: When a meaningful web surface remains unidentified after ordinary fingerprinting, prioritize the existing profile-gated unknown-service inspector. This changes ordering only; it does not expand scope, methods, request budgets, or tool permissions.';
}

export function applyConfidenceGuard<T extends { confidence: number }>(finding: T, patternKey: string, directives?: LearningDirectives): T {
  const cap = directives?.confidenceCaps[patternKey];
  return cap == null ? finding : { ...finding, confidence: Math.min(finding.confidence, cap) };
}
