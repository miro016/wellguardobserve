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

/**
 * Dynamic DOM review for the Unbounded profile.
 * Executes the page's own same-origin JavaScript in the happy-dom runtime
 * (no native browser), optionally with an investigation-acquired session
 * token in localStorage, then exercises text inputs with the fixed marker.
 */
export async function runDynamicDomReview(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; startPath?: string; sessionToken?: string; testMarker?: boolean }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const startPath = scope.assertPath(input.startPath || '/');
  if (/[?#]/.test(startPath)) throw new Error('The start path must not contain a query or fragment.');

  let happyDom: typeof import('happy-dom');
  try { happyDom = await import('happy-dom'); } catch {
    return { available: false, reason: 'happy-dom runtime not installed.', pages: [] as unknown[] };
  }

  const origin = `${tls ? 'https' : 'http'}://${hostname}${port === (tls ? 443 : 80) ? '' : `:${port}`}`;
  const pages: Array<{ url: string; forms: number; markerExecuted: boolean; detail: string }> = [];
  const suggestedFindings: AgentFinding[] = [];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  const candidates = [`${origin}${startPath}`];
  if (input.testMarker !== false) {
    // Common single-page-app hash route shapes used to exercise client-side rendering of a query value.
    for (const route of ['search', 'find', 'contact', 'about']) {
      candidates.push(`${origin}/#/${route}?q=${encodeURIComponent(PAYLOAD)}`);
    }
  }

  for (const url of candidates) {
    const browser = new happyDom.Browser({
      settings: {
        disableJavaScriptFileLoading: false,
        disableCSSFileLoading: true,
        disableIframePageLoading: true,
        fetch: { disableSameOriginPolicy: false },
        navigation: { disableFallbackToSetURL: false, disableChildFrameNavigation: true, disableChildPageNavigation: true }
      }
    });
    try {
      const page = browser.newPage();
      if (input.sessionToken) page.mainFrame.window.localStorage.setItem('token', input.sessionToken);
      await page.goto(url, { timeout: 15_000 });
      await page.mainFrame.waitUntilComplete();
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      const marker = Number((page.mainFrame.window as unknown as Record<string, unknown>)['__wellguardMarker'] || 0);
      const doc = page.mainFrame.document;
      const forms = doc.querySelectorAll('form').length;
      let executed = marker === 1;
      let detail = `scripts executed via emulated DOM; forms rendered: ${forms}; marker flag: ${marker}`;
      if (!executed) {
        // Try submitting text inputs with the fixed marker.
        const inputs = [...doc.querySelectorAll('input[type=text], input[type=search], input:not([type]), textarea')] as unknown as Array<{ value: string; form: unknown | null }>;
        for (const field of inputs.slice(0, 6)) {
          field.value = PAYLOAD;
          const form = field.form as { requestSubmit?: () => void; submit?: () => void } | null;
          page.mainFrame.window.eval('window.__wellguardMarker=0');
          if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
          else if (form && typeof form.submit === 'function') form.submit();
          await new Promise((resolve) => setTimeout(resolve, 1_500));
          if (Number((page.mainFrame.window as unknown as Record<string, unknown>)['__wellguardMarker'] || 0) === 1) { executed = true; detail += '; marker executed after form submit'; break; }
        }
      }
      if (executed) {
        suggestedFindings.push({
          title: 'Client-side marker executed inside the emulated application runtime',
          summary: `The page at ${url} executed the fixed inert marker while its own JavaScript ran in the emulated DOM, indicating a functional client-side injection path under real browsers as well.`,
          severity: 'high', confidence: 90, asset,
          evidence: [`URL exercised: ${url}.`, detail],
          remediation: 'Trace the sink where untrusted values reach script execution, encode output, and apply a restrictive CSP.',
          sourceUrls: [], cveIds: [], weaknessIds: ['CWE-79'],
          frameworkRefs: frameworkReferences('WSTG-CLNT-07'),
          assetKey, relatedAssetKeys: [], relationKey: ''
        });
      }
      pages.push({ url: url.replace('//' + hostname, '//…'), forms, markerExecuted: executed, detail: detail.slice(0, 240) });
    } catch (error) {
      pages.push({ url, forms: 0, markerExecuted: false, detail: `emulation failed: ${error instanceof Error ? error.message.slice(0, 120) : 'unknown'}` });
    } finally {
      await browser.close().catch(() => {});
    }
  }

  return {
    available: true, origin, pagesExamined: pages.length, pages, suggestedFindings,
    policy: 'Same-origin URL and same-origin bundle execution inside a JS-only DOM runtime; localStorage token reuse only when an earlier investigation probe acquired one; fixed marker payload only.'
  };
}

/**
 * System-Chromium review for the Unbounded profile.
 * Drives the Debian-packaged headless Chromium over CDP for flows that need
 * a real browser engine (single-page-app rendering, client-side script
 * execution). Same-origin only; fixed marker payload only.
 */
export async function runChromiumDomReview(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; startPath?: string; sessionToken?: string; hashRoutes?: string[] }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const startPath = scope.assertPath(input.startPath || '/');
  if (/[?#]/.test(startPath)) throw new Error('The start path must not contain a query or fragment.');

  const executablePath = process.env['OBSERVER_CHROMIUM_PATH'] || '/usr/bin/chromium';
  let puppeteer: typeof import('puppeteer-core');
  try { puppeteer = await import('puppeteer-core'); } catch {
    return { available: false, reason: 'puppeteer-core not installed.', pages: [] as unknown[] };
  }

  const origin = `${tls ? 'https' : 'http'}://${hostname}${port === (tls ? 443 : 80) ? '' : `:${port}`}`;
  const hashRoutes = (input.hashRoutes || ['search', 'contact', 'about']).slice(0, 8).map((route) => String(route).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40)).filter(Boolean);
  const candidates = [`${origin}${startPath}`, ...hashRoutes.map((route) => `${origin}/#/${route}?q=${encodeURIComponent(PAYLOAD)}`)];

  const pages: Array<{ url: string; title: string; dialogs: number; markerExecuted: boolean; detail: string }> = [];
  const suggestedFindings: AgentFinding[] = [];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath, headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--no-first-run', '--disable-extensions', `--host-resolver-rules=MAP ${hostname} ${(await scope.resolve(hostname))[0]!.address}`]
    });
  } catch (error) {
    return { available: false, reason: `Chromium launch failed: ${error instanceof Error ? error.message.slice(0, 160) : 'unknown'}.`, pages: [] };
  }

  try {
    for (const url of candidates) {
      const page = await browser.newPage();
      let dialogs = 0;
      page.on('dialog', (dialog) => { dialogs++; void dialog.dismiss().catch(() => {}); });
      const report = { url, title: '', dialogs: 0, markerExecuted: false, detail: '' };
      try {
        // Restrict the page to the authorized origin.
        await page.setRequestInterception(true);
        page.on('request', (request) => {
          try {
            const target = new URL(request.url());
            if (target.hostname.toLowerCase() === hostname.toLowerCase()) void request.continue();
            else void request.abort();
          } catch { void request.abort(); }
        });
        if (input.sessionToken) {
          await page.goto(origin, { timeout: 15_000 }).catch(() => null);
          await page.evaluate((token) => { try { window.localStorage.setItem('token', token); } catch { /* storage may be unavailable */ } }, input.sessionToken);
        }
        await page.goto(url, { timeout: 20_000, waitUntil: 'networkidle2' }).catch(() => page.goto(url, { timeout: 15_000, waitUntil: 'domcontentloaded' }));
        report.title = (await page.title()).slice(0, 160);
        for (let attempt = 0; attempt < 6; attempt++) {
          const marker = await page.evaluate(() => Number((window as unknown as Record<string, unknown>)['__wellguardMarker'] || 0)).catch(() => 0);
          if (marker === 1 || dialogs > 0) { report.markerExecuted = true; break; }
          await new Promise((resolve) => setTimeout(resolve, 1_500));
        }
        if (!report.markerExecuted) {
          // Exercise rendered text inputs and search-like fields with the fixed marker.
          const handles = await page.$$('input[type=text], input[type=search], input:not([type]), textarea');
          for (const handle of handles.slice(0, 6)) {
            await page.evaluate(() => { (window as unknown as Record<string, unknown>)['__wellguardMarker'] = 0; });
            await handle.click().catch(() => {});
            await handle.type(PAYLOAD, { delay: 5 }).catch(() => {});
            await page.keyboard.press('Enter').catch(() => {});
            await new Promise((resolve) => setTimeout(resolve, 2_500));
            const marker = await page.evaluate(() => Number((window as unknown as Record<string, unknown>)['__wellguardMarker'] || 0)).catch(() => 0);
            if (marker === 1 || dialogs > 0) { report.markerExecuted = true; report.detail = 'marker executed after text-input submission'; break; }
          }
        }
        report.dialogs = dialogs;
        if (report.markerExecuted) {
          suggestedFindings.push({
            title: 'Client-side marker executed in a real browser engine',
            summary: `Headless Chromium rendered ${url}, exercised the fixed inert marker, and observed actual script execution (marker flag or a native dialog). This confirms exploitable client-side code injection (DOM XSS class) for this view.`,
            severity: 'high', confidence: 97, asset,
            evidence: [`URL: ${url}.`, `Dialogs observed: ${dialogs}.`, report.detail || 'marker flag set during page load'],
            remediation: 'Encode untrusted data at injection sinks, remove innerHTML-style rendering of user input, and deploy a restrictive Content-Security-Policy.',
            sourceUrls: [], cveIds: [], weaknessIds: ['CWE-79'],
            frameworkRefs: frameworkReferences('WSTG-CLNT-07'),
            assetKey, relatedAssetKeys: [], relationKey: ''
          });
        }
      } catch (error) {
        report.detail = `review failed: ${error instanceof Error ? error.message.slice(0, 140) : 'unknown'}`;
      } finally {
        await page.close().catch(() => {});
      }
      pages.push(report);
    }
  } finally {
    await browser.close().catch(() => {});
  }

  return {
    available: true, origin, pagesExamined: pages.length, pages, suggestedFindings,
    policy: 'System Chromium only, requests intercepted and limited to the authorized origin, fixed inert marker payload, optional session reuse only when an earlier probe acquired a token, no other payload or credential entry.'
  };
}
