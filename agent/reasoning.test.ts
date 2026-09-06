import { describe, expect, test } from 'bun:test';
import { resolveReasoningEffort } from './investigator';

describe('model reasoning configuration', () => {
  test('defaults invalid or absent values to high', () => {
    expect(resolveReasoningEffort(undefined)).toBe('high');
    expect(resolveReasoningEffort('medium')).toBe('high');
  });

  test('accepts the supported named Ollama levels', () => {
    expect(resolveReasoningEffort('low')).toBe('low');
    expect(resolveReasoningEffort('high')).toBe('high');
    expect(resolveReasoningEffort('max')).toBe('max');
  });
});
