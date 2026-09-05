import { createHash } from 'node:crypto';
import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';
import { requestAuthorizedHttp, requestAuthorizedFormPost, type AuthorizedHttpResponse } from './http';

/**
 * Bounded emulated-browser review for the Advanced profile.
 * Uses a pure-JS DOM runtime (happy-dom) instead of a full browser: pages
 * are fetched through the same authorized, bounded HTTP layer, rendered
 * into a DOM, their forms are replayed with one fixed inert marker payload,
 * and execution feasibility is detected from the resulting DOM.
 */

const MAX_PAGES = 6;
const MARKER_ATTR = 'onerror="window.__wellguardMarker=1"';
const PAYLOAD = `<img src=x ${MARKER_ATTR}>`;
const DESTRUCTIVE_HINT = /(?:logout|delete|destroy|remove|purchase|checkout|upload|register|signup|reset|password)/i;

interface FormSpec {
  path: string;
  method: 'GET' | 'POST';
  fields: Array<{ name: string; value: string; fillable: boolean }>;
}

interface PageReport {
  path: string;
  status: number;
  formsExamined: number;
  replays: number;
  markerExecutable: boolean;
  detail: string;
}

function extractForms(raw: string, basePath: string): FormSpec[] {
  const forms: FormSpec[] = [];
  const formBlocks = raw.match(/<form[\s\S]*?<\/form>/gi) || [];
  for (const block of formBlocks.slice(0, 6)) {
    const tag = block.match(/<form\b[^>]*>/i)?.[0] || '';
    const action = tag.match(/action=["']([^"']{0,300})["']/i)?.[1] || basePath;
    const method = (tag.match(/method=["'](post|get)["']/i)?.[1] || 'GET').toUpperCase() as 'GET' | 'POST';
    if (DESTRUCTIVE_HINT.test(action)) continue;
    const fields = [...block.matchAll(/<(input|textarea)\b[^>]*>/gi)].flatMap((match) => {
      const tag = match[0];
      const name = tag.match(/name=["']([^"']{1,64})["']/i)?.[1];
      if (!name) return [];
      const type = (tag.match(/type=["']([^"']{1,32})["']/i)?.[1] || 'text').toLowerCase();
      const fillable = ['text', 'search', 'email', 'url', 'tel', 'password'].includes(type) || match[1]!.toLowerCase() === 'textarea';
      const value = tag.match(/value=["']([^"']{0,300})["']/i)?.[1] || '';
      return [{ name: name.slice(0, 64), value, fillable }];
    });
    if (fields.length) forms.push({ path: action.startsWith('/') ? action : basePath, method, fields });
  }
  return forms;
}

function discoverLinks(raw: string): string[] {
  return [...new Set([...raw.matchAll(/href=["'](\/[^"'?#]{1,300})["']/gi)].map((match) => match[1]!))]
    .filter((path) => !DESTRUCTIVE_HINT.test(path))
    .slice(0, 30);
}

async function emulateExecution(raw: string): Promise<{ executable: boolean; rendered: boolean; detail: string }> {
  const renderedInDom = raw.includes(MARKER_ATTR);
  if (!renderedInDom) return { executable: false, rendered: false, detail: 'marker not present in returned markup' };
  const { Window } = await import('happy-dom');
  const window = new Window({ settings: { disableJavaScriptFileLoading: true, disableCSSFileLoading: true } });
  try {
    window.document.write(raw.slice(0, 400_000));
    await window.happyDOM.waitUntilComplete();
    const host = window.document.querySelector('img[on*="__wellguardMarker"], img[onerror*="__wellguardMarker"]');
    if (!host) return { executable: false, rendered: true, detail: 'marker rendered only in inert/escaped form' };
    // An onerror-bearing <img src=x> always fails to load; dispatch the event the real browser would fire.
    host.setAttribute('src', 'x');
    host.dispatchEvent(new window.ErrorEvent('error'));
    const executed = (window as unknown as Record<string, unknown>)['__wellguardMarker'] === 1;
    return { executable: executed, rendered: true, detail: executed ? 'marker handler executed in DOM context' : 'handler present but inert in emulation' };
  } catch (error) {
    return { executable: false, rendered: true, detail: `emulation error: ${error instanceof Error ? error.message.slice(0, 100) : 'unknown'}` };
  } finally {
    await Promise.resolve(window.close()).catch(() => {});
  }
}

export async function runHeadlessBrowserReview(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; startPath?: string; maxPages?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const startPath = scope.assertPath(input.startPath || '/');
  const pageBudget = Math.max(1, Math.min(MAX_PAGES, Math.floor(input.maxPages || 3)));

  const suggestedFindings: AgentFinding[] = [];
  const pages: PageReport[] = [];
  const visited = new Set<string>();
  const queue = [startPath];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  while (queue.length && pages.length < pageBudget) {
    const path = queue.shift()!;
    if (visited.has(path)) continue;
    visited.add(path);
    let response: AuthorizedHttpResponse;
    try {
      response = await requestAuthorizedHttp(scope, { hostname, port, tls, path });
    } catch (error) {
      pages.push({ path, status: 0, formsExamined: 0, replays: 0, markerExecutable: false, detail: error instanceof Error ? error.message.slice(0, 120) : 'fetch failed' });
      continue;
    }
    const report: PageReport = { path, status: response.status, formsExamined: 0, replays: 0, markerExecutable: false, detail: '' };
    pages.push(report);

    for (const link of discoverLinks(response.raw)) {
      if (!visited.has(link) && queue.length < pageBudget * 2) queue.push(link);
    }

    const forms = extractForms(response.raw, path);
    report.formsExamined = forms.length;
    for (const form of forms) {
      const targets = form.fields.filter((field) => field.fillable).slice(0, 4);
      if (!targets.length) continue;
      const replayPath = form.path.startsWith('/') ? form.path : path;
      let replay: AuthorizedHttpResponse;
      try {
        if (form.method === 'GET') {
          const query = new URLSearchParams(form.fields.map((field) => [field.name, field.fillable ? PAYLOAD : field.value])).toString();
          replay = await requestAuthorizedHttp(scope, { hostname, port, tls, path: `${replayPath}?${query}` });
        } else {
          const fields = Object.fromEntries(form.fields.map((field) => [field.name, field.fillable ? PAYLOAD : field.value]));
          replay = await requestAuthorizedFormPost(scope, { hostname, port, tls, path: replayPath }, fields);
        }
      } catch { continue; }
      report.replays++;
      const verdict = await emulateExecution(replay.raw);
      report.detail = `${report.detail} ${form.method} ${replayPath}: ${verdict.detail}`.trim();
      if (verdict.executable) {
        report.markerExecutable = true;
        suggestedFindings.push({
          title: 'Fixed inert marker executes in the page DOM after form replay',
          summary: `Replaying a form on ${path} with the fixed marker payload returned markup where the marker's event handler survives unencoded, and a DOM emulation of the resulting page executed it. This demonstrates client-side code injection feasibility for this flow; no payload beyond the fixed marker was used.`,
          severity: 'high', confidence: 92, asset,
          evidence: [
            `Source page: GET ${path} (HTTP ${response.status}).`,
            `Replay: ${form.method} ${replayPath} returned HTTP ${replay.status}; digest ${createHash('sha256').update(replay.raw).digest('hex').slice(0, 12)}.`,
            `DOM emulation: ${verdict.detail}.`
          ],
          remediation: 'Encode untrusted data on output, avoid rendering user input via innerHTML-style sinks, and add a restrictive Content-Security-Policy. Confirm impact through an authorized manual review.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-79'],
          frameworkRefs: frameworkReferences('WSTG-CLNT-07'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
    }
  }

  return {
    pagesExamined: pages.length, pages, suggestedFindings,
    policy: `Same-origin GET/form replays through the authorized transport, at most ${MAX_PAGES} pages, one fixed inert marker payload, no credentials, destructive-looking forms skipped. DOM emulation only (happy-dom); no native browser is installed.`
  };
}
