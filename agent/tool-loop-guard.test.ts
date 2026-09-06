import { describe, expect, test } from 'bun:test';
import { ExactToolCallGuard, exactToolCallKey } from './tool-loop-guard';

describe('exact tool-call repetition guard', () => {
  test('canonicalizes object key order', () => {
    expect(exactToolCallKey({ name: 'inspect_http', args: { path: '/', port: 443 } }))
      .toBe(exactToolCallKey({ name: 'inspect_http', args: { port: 443, path: '/' } }));
  });

  test('allows three identical requests and blocks the fourth', () => {
    const guard = new ExactToolCallGuard();
    const results = [1, 2, 3, 4].map((id) => guard.register({ id: String(id), name: 'inspect_http', args: { hostname: 'example.test', path: '/' } }));
    expect(results.map((result) => result.allowed)).toEqual([true, true, true, false]);
    expect(results.at(-1)?.count).toBe(4);
  });

  test('does not count a repeated middleware observation of the same call id twice', () => {
    const guard = new ExactToolCallGuard();
    guard.register({ id: 'same-id', name: 'inspect_dns', args: {} });
    expect(guard.register({ id: 'same-id', name: 'inspect_dns', args: {} }).count).toBe(1);
  });
});
