import { connect, type PeerCertificate } from 'node:tls';
import type { ScopeGuard } from '../security/scope-guard';
import type { TlsEvidence } from '../types';

function flattenName(value?: Record<string, string | string[] | undefined>): string {
  return value ? Object.entries(value).filter((entry) => entry[1] !== undefined).map(([key, item]) => `${key}=${Array.isArray(item) ? item.join('/') : item}`).join(', ') : '';
}

function certificateNames(cert: PeerCertificate): string[] {
  return (cert.subjectaltname || '').split(',').map((value) => value.trim().replace(/^DNS:/, '')).filter(Boolean);
}

export async function inspectTls(scope: ScopeGuard, input: { hostname?: string; port?: number }): Promise<TlsEvidence> {
  const hostname = scope.assertHostname(input.hostname);
  const port = input.port ?? 443;
  if (port < 1 || port > 65535) throw new Error('TLS port is outside the allowed range.');
  const [{ address }] = await scope.resolve(hostname);

  return await new Promise<TlsEvidence>((resolve, reject) => {
    const socket = connect(port, address, { servername: hostname, rejectUnauthorized: false });
    socket.setTimeout(5_000, () => socket.destroy(new Error('TLS inspection timed out.')));
    const timer = setTimeout(() => socket.destroy(new Error('TLS inspection timed out.')), 6_000);
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const cert = socket.getPeerCertificate();
      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const authorizationError = socket.authorizationError ? String(socket.authorizationError) : null;
      const result: TlsEvidence = {
        hostname, port, valid: !authorizationError && validFrom <= new Date() && validTo >= new Date(), authorizationError,
        issuer: flattenName(cert.issuer), subject: flattenName(cert.subject),
        validFrom: validFrom.toISOString(), validTo: validTo.toISOString(),
        daysRemaining: Math.floor((validTo.getTime() - Date.now()) / 86_400_000),
        protocol: socket.getProtocol() || 'unknown', cipher: socket.getCipher()?.name || 'unknown',
        fingerprint256: cert.fingerprint256 || '', subjectAltNames: certificateNames(cert)
      };
      socket.end(); resolve(result);
    });
    socket.once('error', (error) => { clearTimeout(timer); reject(error); });
  });
}
