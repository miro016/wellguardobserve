import { describe, expect, test } from 'bun:test';
import { AGENT_TOOL_CATALOG, compiledAgentToolSupports } from './tool-catalog';

describe('administrator tool catalogue', () => {
  test('covers every callable investigator tool exactly once', async () => {
    const source = await Bun.file(new URL('./investigator.ts', import.meta.url)).text();
    const callable = [...source.matchAll(/name:\s*'([a-z0-9_]+)'/g)].map((match) => match[1]!).sort();
    const catalogued = AGENT_TOOL_CATALOG.map((tool) => tool.name).sort();
    expect(new Set(catalogued).size).toBe(catalogued.length);
    expect(catalogued).toEqual(callable);
  });

  test('defines a non-empty compiled profile boundary for each tool', () => {
    for (const tool of AGENT_TOOL_CATALOG) {
      expect(tool.defaultProfiles.length).toBeGreaterThan(0);
      expect(new Set(tool.defaultProfiles).size).toBe(tool.defaultProfiles.length);
    }
    expect(AGENT_TOOL_CATALOG.find((tool) => tool.name === 'record_finding')?.essential).toBeTrue();
    expect(compiledAgentToolSupports('run_vanguard_observation', 'standard')).toBeFalse();
    expect(compiledAgentToolSupports('run_vanguard_observation', 'extended')).toBeTrue();
    expect(compiledAgentToolSupports('crawl_web_application', 'light')).toBeFalse();
  });
});
