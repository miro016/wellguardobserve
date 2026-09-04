import { createConnection } from 'node:net';
import type { ScopeGuard } from '../security/scope-guard';
import { fingerprintBanner } from '../fingerprints/recog';

const protocols: Record<number, string> = { 21: 'ftp', 22: 'ssh', 25: 'smtp', 465: 'smtp', 587: 'smtp' };

export async function inspectServiceBanner(scope: ScopeGuard, input: { hostname?: string; port: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const port = input.port;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Banner port is outside the allowed range.');
  const [{ address, family }] = await scope.resolve(hostname);
  const protocolHint = protocols[port] || 'unknown';
  const banner = await new Promise<string>((resolve, reject) => {
    const socket = createConnection({ host: address, family, port });
    const chunks: Buffer[] = []; let total = 0; let settled = false;
    const finish = () => { if (settled) return; settled = true; socket.destroy(); resolve(Buffer.concat(chunks).toString('utf8').slice(0, 8_192)); };
    socket.setTimeout(3_000);
    socket.once('connect', () => setTimeout(finish, 1_200));
    socket.on('data', (chunk: Buffer) => { if (total < 8_192) { const part = chunk.subarray(0, 8_192 - total); chunks.push(part); total += part.length; } if (total >= 8_192) finish(); });
    socket.once('timeout', finish);
    socket.once('error', (error) => { if (settled) return; settled = true; reject(error); });
    socket.once('end', finish);
  });
  const fingerprinting = protocolHint === 'unknown' ? { protocol: protocolHint, matches: [], source: '', status: 'No protocol-specific fingerprint pack selected.' } : await fingerprintBanner(protocolHint, banner);
  const plain = banner.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').trim().slice(0, 1_000);
  return {
    hostname, address, port, protocolHint, banner: plain, fingerprinting,
    note: plain ? 'Only the service-initiated passive banner was retained; no command or authentication was sent.' : 'The TCP service accepted a connection but did not send a passive banner within the bounded wait.'
  };
}
