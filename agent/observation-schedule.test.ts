import { describe, expect, it } from 'bun:test';
import { nextScheduledAt } from '../src/app/services/observation-schedule';

describe('observation scheduling', () => {
  it('computes daily and weekly runs without local timezone drift', () => {
    const now = new Date('2026-09-06T10:15:00.000Z');
    expect(nextScheduledAt('daily', now)).toBe('2026-09-07T10:15:00.000Z');
    expect(nextScheduledAt('weekly', now)).toBe('2026-09-13T10:15:00.000Z');
  });

  it('clamps monthly runs to the final day of a shorter month', () => {
    expect(nextScheduledAt('monthly', new Date('2026-01-31T10:15:00.000Z'))).toBe('2026-02-28T10:15:00.000Z');
  });
});
