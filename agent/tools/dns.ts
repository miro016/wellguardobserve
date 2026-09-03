import { resolveAny } from 'node:dns/promises';
import type { ScopeGuard } from '../security/scope-guard';

export async function inspectDns(scope: ScopeGuard, hostname?: string) {
  const host = scope.assertHostname(hostname);
  const addresses = await scope.resolve(host);
  const records = await resolveAny(host).catch(() => []);
  return {
    hostname: host,
    addresses,
    records: records.slice(0, 40),
    note: 'Addresses describe the public DNS edge and may belong to a CDN rather than the origin.'
  };
}

export async function inspectCertificateTransparency(scope: ScopeGuard) {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${scope.rootHostname}`)}&output=json`;
  const response = await fetch(url, { signal: AbortSignal.timeout(12_000), headers: { 'user-agent': 'WellguardObserve/0.1' } });
  if (!response.ok) throw new Error(`Certificate transparency source returned ${response.status}.`);
  const rows = await response.json() as Array<{ name_value?: string; issuer_name?: string; not_after?: string }>;
  const names = [...new Set(rows.flatMap((row) => (row.name_value || '').split(/\r?\n/)))]
    .map((name) => name.toLowerCase().replace(/^\*\./, ''))
    .filter((name) => name === scope.rootHostname || name.endsWith(`.${scope.rootHostname}`))
    .slice(0, 100);
  return { source: 'crt.sh', root: scope.rootHostname, names, certificateCount: rows.length };
}
