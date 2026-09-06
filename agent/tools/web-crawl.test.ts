import { describe, expect, test } from 'bun:test';
import { extractCrawlSurface } from './web-crawl';

describe('generic web crawl surface extraction', () => {
  test('keeps same-origin links and inventories forms without submitting them', () => {
    const result = extractCrawlSurface(`<a href="/catalog?q=one">Catalog</a><a href="https://outside.test/admin">Outside</a><a href="/logout">Exit</a><a href="#/search">Search</a><form action="/api/session" method="post"><input name="email" type="email"><input name="password" type="password"></form>`, new URL('https://app.example.test/'));
    expect(result.links).toEqual(['/catalog?q=one', '/']);
    expect(result.hashRoutes).toEqual(['/search']);
    expect(result.forms).toEqual([{ action: '/api/session', method: 'POST', fields: [{ name: 'email', type: 'email' }, { name: 'password', type: 'password' }] }]);
  });
});
