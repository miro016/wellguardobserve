import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createServer, type Server } from 'node:http';
import { ScopeGuard } from '../security/scope-guard';
import { inspectHttp } from './http';
import { discoverPorts } from './ports';
import { classifyServiceObservation } from './service-hosts';

let server: Server;
let port: number;
const scope = new ScopeGuard({ id: 'local-test', hostname: '127.0.0.1', authorizationStatus: 'admin_override', allowPrivateAddresses: true });

beforeAll(async () => {
  server = createServer((_request, response) => {
    response.setHeader('server', 'Example-Control/2.0');
    response.setHeader('x-powered-by', 'Bun');
    response.end('<html><head><title>Easypanel</title></head><body>Control at https://panel.example.test and origin 203.0.113.42.</body></html>');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Test server did not bind.');
  port = address.port;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

describe('bounded network tools', () => {
  test('extracts generic identity and disclosure signals from HTTP', async () => {
    const result = await inspectHttp(scope, { hostname: '127.0.0.1', port, tls: false, path: '/' });
    expect(result['status']).toBe(200);
    const signals = result['signals'] as { title: string; serviceWords: string[]; ipv4: string[]; urls: string[] };
    expect(signals.title).toBe('Easypanel');
    expect(signals.serviceWords).toContain('easypanel');
    expect(signals.ipv4).toContain('203.0.113.42');
    expect(signals.urls).toContain('https://panel.example.test');
  });

  test('finds only the explicitly requested local port', async () => {
    const result = await discoverPorts(scope, { ports: [port] });
    expect(result.openPorts).toEqual([port]);
    expect(result.portsTested).toBe(1);
  });

  test('separates a real redirected service from wildcard missing routes', () => {
    const root = { hostname: 'example.com', status: 200, title: 'Easypanel', location: '', server: 'cloudflare', contentType: 'text/html', textSample: 'Easypanel', serviceWords: ['easypanel'] };
    const missing = { ...root, hostname: 'keycloak.example.com', status: 404, title: 'Not Found', textSample: 'The application keycloak was not found on Easypanel.' };
    const service = { ...root, hostname: 'keycloak1.example.com', status: 302, title: '', location: 'https://project-keycloak.provider.test/admin/', textSample: '', serviceWords: [] };
    expect(classifyServiceObservation(missing, root)).toBeNull();
    expect(classifyServiceObservation(service, root)?.productHints).toContain('keycloak');
  });
});
