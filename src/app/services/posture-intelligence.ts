import { Finding, FindingLifecycle, KnowledgePattern, Scan, Severity } from '../models';

const severityRank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const clean = (value: unknown) => String(value ?? '').trim();
const normalized = (value: string) => value.toLowerCase().replace(/https?:\/\/[^\s/]+/g, ' endpoint ').replace(/\b\d+(?:\.\d+){1,3}\b/g, ' version ').replace(/\b\d{2,5}\b/g, ' number ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 180) || 'uncategorized';

export function latestCompletedScans(scans: Scan[]): Map<string, Scan> {
  const result = new Map<string, Scan>();
  for (const scan of scans.filter((item) => item.status === 'completed').sort((a, b) => Date.parse(b.completedAt || b.created) - Date.parse(a.completedAt || a.created))) {
    if (!result.has(scan.target)) result.set(scan.target, scan);
  }
  return result;
}

export function findingLifecycle(finding: Finding, latestScanId?: string): FindingLifecycle {
  if (finding.status === 'resolved') return 'resolved';
  if (latestScanId && finding.scan !== latestScanId) return 'not_observed';
  return finding.runCount > 1 || finding.observations.length > 1 ? 'persistent' : 'new';
}

export function findingCategory(finding: Pick<Finding, 'title' | 'summary' | 'weaknessIds'>): string {
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

export function findingTechnology(finding: Pick<Finding, 'assetKey' | 'asset' | 'title'>): string {
  const serviceKey = clean(finding.assetKey).match(/^service:.+?:\d+:(.+)$/)?.[1];
  if (serviceKey) return serviceKey.replace(/-/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
  const known = ['WordPress', 'Keycloak', 'Grafana', 'Jenkins', 'GitLab', 'Kubernetes', 'Nginx', 'Apache', 'Traefik', 'PocketBase', 'PostgreSQL', 'MySQL', 'Redis', 'MongoDB', 'Elasticsearch', 'RabbitMQ', 'Docker'];
  return known.find((name) => `${finding.title} ${finding.asset}`.toLowerCase().includes(name.toLowerCase())) || 'Technology not identified';
}

export function buildKnowledgePatterns(findings: Finding[], scans: Scan[]): KnowledgePattern[] {
  const latest = latestCompletedScans(scans);
  const patterns = new Map<string, KnowledgePattern>();
  for (const finding of findings) {
    const category = findingCategory(finding);
    const technology = findingTechnology(finding);
    const weakness = [...finding.weaknessIds].sort()[0] || '';
    const key = normalized([category, technology, weakness || normalized(finding.title)].join(':'));
    const lifecycle = findingLifecycle(finding, latest.get(finding.target)?.id);
    const observationDates = finding.observations.map((item) => item.observedAt).filter(Boolean);
    const firstSeenAt = observationDates[0] || finding.created;
    const lastSeenAt = observationDates.at(-1) || finding.created;
    const existing = patterns.get(key);
    if (!existing) {
      patterns.set(key, {
        key, title: finding.title, category, technology, severity: finding.severity, weaknessIds: [...finding.weaknessIds],
        occurrences: Math.max(finding.runCount, finding.observations.length, 1), affectedTargetIds: [finding.target],
        currentCount: lifecycle === 'new' || lifecycle === 'persistent' ? 1 : 0, newCount: lifecycle === 'new' ? 1 : 0,
        persistentCount: lifecycle === 'persistent' ? 1 : 0, firstSeenAt, lastSeenAt, findingIds: [finding.id]
      });
      continue;
    }
    existing.occurrences += Math.max(finding.runCount, finding.observations.length, 1);
    if (!existing.affectedTargetIds.includes(finding.target)) existing.affectedTargetIds.push(finding.target);
    if (lifecycle === 'new' || lifecycle === 'persistent') existing.currentCount++;
    if (lifecycle === 'new') existing.newCount++;
    if (lifecycle === 'persistent') existing.persistentCount++;
    existing.weaknessIds = [...new Set([...existing.weaknessIds, ...finding.weaknessIds])];
    existing.findingIds.push(finding.id);
    if (severityRank[finding.severity] > severityRank[existing.severity]) { existing.severity = finding.severity; existing.title = finding.title; }
    if (Date.parse(firstSeenAt) < Date.parse(existing.firstSeenAt)) existing.firstSeenAt = firstSeenAt;
    if (Date.parse(lastSeenAt) > Date.parse(existing.lastSeenAt)) existing.lastSeenAt = lastSeenAt;
  }
  return [...patterns.values()].sort((a, b) => b.occurrences - a.occurrences || severityRank[b.severity] - severityRank[a.severity] || a.title.localeCompare(b.title));
}
