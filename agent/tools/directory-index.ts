import type { ScopeGuard } from '../security/scope-guard';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedHttp, type AuthorizedHttpResponse } from './http';

const SENSITIVE_NAME = /(?:^|[._-])(?:backup|dump|secret|credential|password|passwd|token|private|wallet|vault|incident|history)(?:[._-]|$)|\.(?:bak|old|orig|save|sql|sqlite|kdbx|pem|key|pfx|p12|env)(?:$|[?#])/i;

export async function inspectPublicDirectoryIndex(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; path: string }) {
  const hostname = scope.assertHostname(input.hostname);
  const path = directoryPath(scope, input.path);
  let response = await requestAuthorizedHttp(scope, { hostname, port: input.port, tls: input.tls, path });
  let requestCount = 1;
  if (isSlashRedirect(response, path)) {
    response = await requestAuthorizedHttp(scope, { hostname, port: input.port, tls: input.tls, path: `${path}/` });
    requestCount += 1;
  }
  const title = response.raw.match(/<title[^>]*>([^<]{0,240})<\/title>/i)?.[1]?.trim() || '';
  const names = listingNames(response.raw, response.requestedUrl);
  const signature = /^(?:index of|listing directory)\s+\//i.test(title)
    || /<h1[^>]*>\s*(?:index of|directory listing for)\s+\//i.test(response.raw);
  const identified = response.status === 200 && signature && names.length >= 2;
  const sensitiveNames = identified ? names.filter((name) => SENSITIVE_NAME.test(name)).slice(0, 12) : [];
  const severity = sensitiveNames.length ? 'medium' as const : 'low' as const;
  const serviceKey = `service:${hostname}:${input.port || (input.tls === false ? 80 : 443)}:public-directory-index`;
  const suggestedFindings = identified ? [{
    title: sensitiveNames.length ? 'Public directory index exposes backup or credential-store-like filenames' : 'Public directory index exposes file inventory',
    summary: `An anonymous request reached a generated directory listing on ${hostname} with ${names.length} visible entr${names.length === 1 ? 'y' : 'ies'}. ${sensitiveNames.length ? `Names such as ${sensitiveNames.slice(0, 4).join(', ')} suggest backups or security-sensitive material may be present.` : 'The listing reveals file and directory names that were not linked as normal application content.'} No listed file was downloaded.`,
    severity, confidence: 100, asset: hostname, assetKey: serviceKey, relatedAssetKeys: [], relationKey: '',
    evidence: [`GET ${response.requestedUrl} returned HTTP 200 with title “${title}”.`, `The generated index exposed ${names.length} entry names.`, ...(sensitiveNames.length ? [`Security-sensitive-looking names: ${sensitiveNames.join(', ')}.`] : [])],
    remediation: 'Disable automatic directory indexes, remove public backup and credential-store files, and explicitly allow only intended downloadable assets. Rotate any credential whose material may have been exposed.',
    sourceUrls: [], cveIds: [], weaknessIds: ['CWE-548'], frameworkRefs: frameworkReferences('CRA-I-1', 'CRA-I-2j')
  }] : [];
  return {
    hostname, requestedUrl: response.requestedUrl, status: response.status, title, identified,
    listedNames: identified ? names : [], sensitiveNames, requestCount, suggestedFindings,
    note: 'At most two anonymous GETs were made: the observed directory path and, only for its same-path slash redirect, the slash form. Listed files were not requested and response bodies are not returned.'
  };
}

function directoryPath(scope: ScopeGuard, value: string): string {
  const path = scope.assertPath(value);
  if (path.includes('?') || path.includes('#') || /(?:^|\/)\.\.?\//.test(path)) throw new Error('Directory inspection accepts only a clean observed path without query, fragment, or traversal.');
  if (/\.[A-Za-z0-9]{1,10}\/?$/.test(path)) throw new Error('Directory inspection cannot request a file-like path.');
  return path.length > 1 ? path.replace(/\/$/, '') : path;
}

function isSlashRedirect(response: AuthorizedHttpResponse, path: string): boolean {
  return path !== '/' && response.status >= 300 && response.status < 400 && response.headers['location'] === `${path}/`;
}

function listingNames(raw: string, requestedUrl: string): string[] {
  let directory = '/';
  try { directory = new URL(requestedUrl).pathname.replace(/\/$/, '') + '/'; } catch { /* Keep the conservative root fallback. */ }
  const relativeDirectory = directory.replace(/^\//, '');
  const values = [...raw.matchAll(/<a\s+[^>]*href=["']([^"']{1,500})["']/gi)].flatMap((match) => {
    const href = match[1]!;
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|[?#]|\.\.\/?$)/i.test(href)) return [];
    try {
      let value = decodeURIComponent(href).split(/[?#]/)[0]!.trim();
      if (value.startsWith('/')) {
        if (!value.startsWith(directory)) return [];
        value = value.slice(directory.length);
      }
      else if (relativeDirectory && value.startsWith(relativeDirectory)) value = value.slice(relativeDirectory.length);
      value = value.replace(/^\.\//, '').replace(/\/$/, '');
      return value && !value.includes('/') ? [value.slice(0, 180)] : [];
    } catch { return []; }
  });
  return [...new Set(values)].slice(0, 40);
}
