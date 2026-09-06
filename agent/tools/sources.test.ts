import { afterEach, describe, expect, test } from 'bun:test';
import { queryCveRecord, queryOpenSsfScorecard, queryProductLifecycle } from './sources';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function respond(body: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch;
}

describe('bounded intelligence sources', () => {
  test('matches lifecycle evidence to the observed release cycle', async () => {
    globalThis.fetch = respond({
      last_modified: '2026-08-28T00:00:00Z',
      result: { label: 'Node.js', links: { html: 'https://endoflife.date/nodejs' }, releases: [{ name: '22', label: '22 LTS', isMaintained: true, isEol: false, eolFrom: '2027-04-30', latest: { name: '22.19.0', date: '2026-08-20', link: 'https://nodejs.org/' } }] }
    });
    const result = await queryProductLifecycle({ product: 'nodejs', version: '22.14.0' });
    expect(result.releases).toHaveLength(1);
    expect(result.releases[0]?.cycle).toBe('22');
    expect(result.releases[0]?.isMaintained).toBeTrue();
  });

  test('normalizes canonical CNA and ADP evidence without retaining an unbounded record', async () => {
    globalThis.fetch = respond({
      cveMetadata: { cveId: 'CVE-2024-3094', state: 'PUBLISHED', datePublished: '2024-03-29' },
      containers: {
        cna: { title: 'Example issue', descriptions: [{ lang: 'en', value: 'Canonical description' }], affected: [{ packageName: 'xz', versions: [{ version: '5.6.0', status: 'affected' }] }], metrics: [{ cvssV3_1: { baseScore: 10, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/example' } }], references: [{ url: 'https://example.test/advisory' }] },
        adp: [{ providerMetadata: { shortName: 'CISA-ADP' }, title: 'SSVC', metrics: [{ other: { type: 'ssvc', content: { exploitation: 'active' } } }] }]
      }
    });
    const result = await queryCveRecord('CVE-2024-3094');
    expect(result.id).toBe('CVE-2024-3094');
    expect(result.affected[0]?.packageName).toBe('xz');
    expect(result.cnaMetrics[0]?.['score']).toBe(10);
    expect(result.adpMetrics[0]?.provider).toBe('CISA-ADP');
  });

  test('labels Scorecard as repository context rather than target vulnerability proof', async () => {
    globalThis.fetch = respond({ date: '2026-09-05', repo: { name: 'github.com/ossf/scorecard', commit: 'abc' }, score: 9, checks: [{ name: 'Code-Review', score: 10, reason: 'all changes reviewed', documentation: { url: 'https://github.com/ossf/scorecard/docs/checks.md' } }] });
    const result = await queryOpenSsfScorecard({ owner: 'ossf', repository: 'scorecard' });
    expect(result.score).toBe(9);
    expect(result.checks[0]?.name).toBe('Code-Review');
    expect(result.interpretation).toContain('not evidence');
  });

  test('rejects arbitrary lifecycle paths before issuing a request', async () => {
    let requested = false;
    globalThis.fetch = (async () => { requested = true; return new Response(); }) as unknown as typeof fetch;
    expect(queryProductLifecycle({ product: '../private', version: '1.0' })).rejects.toThrow('concrete');
    expect(requested).toBeFalse();
  });
});
