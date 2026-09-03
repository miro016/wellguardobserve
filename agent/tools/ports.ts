import { createConnection } from 'node:net';
import type { ScopeGuard } from '../security/scope-guard';

export const STANDARD_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 2375, 3000, 3306, 5432, 5601, 5672, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9443, 27017];

async function checkPort(address: string, family: 4 | 6, port: number, timeoutMs: number): Promise<boolean> {
  return await new Promise((resolve) => {
    const socket = createConnection({ host: address, family, port });
    const finish = (open: boolean) => { socket.destroy(); resolve(open); };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

export async function discoverPorts(scope: ScopeGuard, input: { hostname?: string; ports?: number[] }) {
  const hostname = scope.assertHostname(input.hostname);
  const requested = [...new Set(input.ports?.length ? input.ports : STANDARD_PORTS)]
    .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535).slice(0, 40);
  if (!requested.length) throw new Error('At least one valid port must be supplied.');
  const [{ address, family }] = await scope.resolve(hostname);
  const results: Array<{ port: number; open: boolean }> = [];
  for (let index = 0; index < requested.length; index += 8) {
    const batch = requested.slice(index, index + 8);
    const states = await Promise.all(batch.map(async (port) => ({ port, open: await checkPort(address, family, port, 1_200) })));
    results.push(...states);
  }
  return {
    hostname, testedAddress: address, portsTested: requested.length,
    openPorts: results.filter((item) => item.open).map((item) => item.port),
    note: 'When the hostname uses a CDN or reverse proxy, these ports describe that public edge and not necessarily the origin server.'
  };
}
