import { createConnection } from 'node:net';
import type { ScopeGuard } from '../security/scope-guard';

// Internal helper: full-range TCP connect sweep for the Unbounded profile.
async function probe(address: string, family: 4 | 6, port: number, timeoutMs: number): Promise<boolean> {
  return await new Promise((resolve) => {
    const socket = createConnection({ host: address, family, port });
    const finish = (open: boolean) => { socket.destroy(); resolve(open); };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

export async function sweepFullPortRange(scope: ScopeGuard, input: { hostname?: string; from?: number; to?: number; concurrency?: number; timeoutMs?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const from = Math.max(1, Math.min(65535, Math.floor(input.from || 1)));
  const to = Math.max(from, Math.min(65535, Math.floor(input.to || 65535)));
  const concurrency = Math.max(8, Math.min(256, Math.floor(input.concurrency || 128)));
  const timeoutMs = Math.max(250, Math.min(2000, Math.floor(input.timeoutMs || 800)));
  const [{ address, family }] = await scope.resolve(hostname);

  const open: number[] = [];
  let tested = 0;
  const pending: Promise<void>[] = [];
  let next = from;
  const worker = async () => {
    while (next <= to) {
      const port = next++;
      tested++;
      if (await probe(address, family, port, timeoutMs)) open.push(port);
    }
  };
  for (let i = 0; i < concurrency; i++) pending.push(worker());
  await Promise.all(pending);

  return {
    hostname, testedAddress: address, range: `${from}-${to}`, portsTested: tested,
    openPorts: open.sort((a, b) => a - b),
    note: 'Full-range TCP connect sweep. Ports on shared edge/CDN infrastructure describe the edge, not necessarily the origin.'
  };
}
