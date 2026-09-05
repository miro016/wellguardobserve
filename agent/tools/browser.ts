import type { ScopeGuard } from '../security/scope-guard';
import type { AgentFinding } from '../types';
import { frameworkReferences } from '../compliance';

/**
 * Bounded headless-browser review for the Advanced profile.
 * Stays on the authorized origin, visits a small number of in-scope pages,
 * and submits one fixed inert DOM marker payload into text-like inputs.
 * Execution of the marker inside the page (not reflection) is the signal.
 */

const MAX_PAGES = 6;
const NAV_TIMEOUT_MS = 12_000;
const TOTAL_BUDGET_MS = 90_000;
const MARKER = 'window.__wellguardMarker=1';
const PAYLOAD = `<img src=x onerror="${MARKER}">`;

interface PageReport {
  url: string;
  title: string;
  formsExamined: number;
  inputsFilled: number;
  markerExecuted: boolean;
  dialogsObserved: number;
  error?: string;
}

export async function runHeadlessBrowserReview(scope: ScopeGuard, input: { hostname?: string; port?: number; tls?: boolean; startPath?: string; maxPages?: number }) {
  const hostname = scope.assertHostname(input.hostname);
  const tls = input.tls ?? true;
  const port = input.port ?? (tls ? 443 : 80);
  const startPath = scope.assertPath(input.startPath || '/');
  if (/[?#]/.test(startPath)) throw new Error('The start path must not contain a query or fragment.');
  const pageBudget = Math.max(1, Math.min(MAX_PAGES, Math.floor(input.maxPages || 3)));

  const playwright = await import('playwright').catch(() => null);
  if (!playwright) {
    return { available: false, reason: 'The headless browser runtime is not installed in this observer build.', pages: [] };
  }

  const origin = `${tls ? 'https' : 'http'}://${hostname}${port === (tls ? 443 : 80) ? '' : `:${port}`}`;
  const startedAt = Date.now();
  const pages: PageReport[] = [];
  const suggestedFindings: AgentFinding[] = [];
  const asset = `${hostname}:${port}`;
  const assetKey = `service:${hostname}:${port}:web`;

  const browser = await playwright.chromium.launch({ headless: true }).catch((error: unknown) => {
    return Promise.reject(new Error(`Headless browser launch failed: ${error instanceof Error ? error.message.slice(0, 160) : 'unknown'}.`));
  });

  const visited = new Set<string>();
  const queue: string[] = [`${origin}${startPath}`];

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: false, userAgent: 'WellguardObserve/0.1 (+authorized reconnaissance)' });
    while (queue.length && pages.length < pageBudget && Date.now() - startedAt < TOTAL_BUDGET_MS) {
      const url = queue.shift()!;
      if (visited.has(url)) continue;
      visited.add(url);
      let targetHost: string;
      try { targetHost = new URL(url).hostname.toLowerCase(); } catch { continue; }
      try { scope.assertHostname(targetHost); } catch { continue; }

      const page = await context.newPage();
      let dialogs = 0;
      page.on('dialog', (dialog) => { dialogs++; void dialog.dismiss().catch(() => {}); });
      const report: PageReport = { url, title: '', formsExamined: 0, inputsFilled: 0, markerExecuted: false, dialogsObserved: 0 };
      try {
        await page.goto(url, { timeout: NAV_TIMEOUT_MS, waitUntil: 'domcontentloaded' });
        report.title = (await page.title()).slice(0, 160);

        // Discover same-origin, non-state-changing links for later pages.
        const links = await page.$$eval('a[href]', (anchors) => anchors.map((anchor) => (anchor as HTMLAnchorElement).href));
        for (const link of links.slice(0, 60)) {
          try {
            const parsed = new URL(link);
            if (parsed.origin !== origin) continue;
            if (/(?:logout|delete|create|purchase|checkout|admin)/i.test(parsed.pathname)) continue;
            if (queue.length >= pageBudget * 2) break;
            const clean = `${parsed.origin}${parsed.pathname}`;
            if (!visited.has(clean)) queue.push(clean);
          } catch { /* ignore malformed href */ }
        }

        // Submit the fixed marker into text-like inputs of non-destructive forms.
        const forms = await page.$$('form');
        for (const form of forms.slice(0, 6)) {
          report.formsExamined++;
          const action = (await form.getAttribute('action') || '');
          if (/(?:logout|delete|destroy|purchase|checkout|upload|register|signup)/i.test(action)) continue;
          const inputs = await form.$$('input:not([type]), input[type=text], input[type=search], input[type=email]');
          if (!inputs.length) continue;
          await page.evaluate(() => { (window as unknown as Record<string, unknown>)['__wellguardMarker'] = 0; });
          for (const field of inputs.slice(0, 4)) { await field.fill(PAYLOAD); report.inputsFilled++; }
          const submit = await form.$('button[type=submit], input[type=submit], button:not([type])');
          if (submit) await submit.click().catch(() => {});
          else await inputs[0]!.press('Enter').catch(() => {});
          await page.waitForTimeout(1500);
          const marker = await page.evaluate(() => Number((window as unknown as Record<string, unknown>)['__wellguardMarker'] || 0));
          if (marker === 1 || dialogs > 0) report.markerExecuted = true;
        }
        report.dialogsObserved = dialogs;
        if (report.markerExecuted) {
          suggestedFindings.push({
            title: 'Fixed inert marker executes in the page context after form submission',
            summary: `A headless browser submitted the fixed marker payload into text inputs on ${url} and observed script execution in the page context (marker flag or a native dialog). This demonstrates client-side code injection feasibility for this view; no payload beyond the fixed marker was used.`,
            severity: 'high', confidence: 95, asset,
            evidence: [
              `URL: ${url}.`,
              `Inputs filled: ${report.inputsFilled}; marker executed: ${report.markerExecuted}; dialogs observed: ${report.dialogsObserved}.`
            ],
            remediation: 'Encode untrusted data on output, avoid innerHTML-style rendering of user input, and deploy a restrictive Content-Security-Policy. Verify impact with an authorized code review.',
            sourceUrls: [], cveIds: [], weaknessIds: ['CWE-79'],
            frameworkRefs: frameworkReferences('WSTG-CLNT-07'),
            assetKey, relatedAssetKeys: [], relationKey: ''
          });
        }
      } catch (error) {
        report.error = error instanceof Error ? error.message.slice(0, 160) : 'navigation failed';
      } finally {
        await page.close().catch(() => {});
      }
      pages.push(report);
    }
    await context.close().catch(() => {});
  } finally {
    await browser.close().catch(() => {});
  }

  return {
    available: true, origin, pagesExamined: pages.length, pages, suggestedFindings,
    policy: `Same-origin navigation only, at most ${MAX_PAGES} pages, one fixed inert marker payload, no credential submission, no state-changing form actions, ~${Math.round(TOTAL_BUDGET_MS / 1000)}s budget.`
  };
}
