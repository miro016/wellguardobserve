import { resolveAny } from 'node:dns/promises';
import type { ScopeGuard } from '../security/scope-guard';
import { cachedExternalFetch } from '../external-cache';

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
  const response = await cachedExternalFetch(url, { signal: AbortSignal.timeout(12_000), headers: { 'user-agent': 'WellguardObserve/0.1' } }, { source: 'crt.sh certificate transparency', ttlMs: 6 * 3_600_000, staleIfErrorMs: 86_400_000 });
  if (!response.ok) throw new Error(`Certificate transparency source returned ${response.status}.`);
  const rows = await response.json() as Array<{ id?: number; common_name?: string; name_value?: string; issuer_ca_id?: number; issuer_name?: string; not_before?: string; not_after?: string; serial_number?: string; result_count?: number }>;
  const names = [...new Set(rows.flatMap((row) => (row.name_value || '').split(/\r?\n/)))]
    .map((name) => name.toLowerCase().replace(/^\*\./, ''))
    .filter((name) => name === scope.rootHostname || name.endsWith(`.${scope.rootHostname}`))
    .slice(0, 100);
  const certificates = rows.slice(0, 100).map((row, index) => ({
    id: row.id ?? index,
    commonName: String(row.common_name || '').toLowerCase(),
    names: [...new Set(String(row.name_value || '').split(/\r?\n/).map((name) => name.trim().toLowerCase()).filter(Boolean))],
    issuerCaId: row.issuer_ca_id ?? null,
    issuerName: String(row.issuer_name || ''),
    notBefore: String(row.not_before || ''),
    notAfter: String(row.not_after || ''),
    serialNumber: String(row.serial_number || ''),
    resultCount: row.result_count ?? 1
  }));
  return { source: 'crt.sh', root: scope.rootHostname, names, certificateCount: rows.length, certificatesRetained: certificates.length, certificates };
}
