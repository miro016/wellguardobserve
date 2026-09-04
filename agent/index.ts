import type { RecordModel } from 'pocketbase';
import { investigate } from './investigator';
import { InvestigationStore } from './store';

const store = new InvestigationStore();
await store.connect();
console.log('Wellguard observer connected to PocketBase.');

const pollMs = Number(process.env['SCAN_POLL_MS'] || 4_000);
while (true) {
  const request = await store.nextRequest();
  if (!request) { await Bun.sleep(pollMs); continue; }
  let scan: RecordModel | null = null;
  let cancellationTimer: ReturnType<typeof setInterval> | undefined;
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  try {
    if (!await store.claim(request)) continue;
    const target = await store.loadTarget(request['target']);
    scan = await store.createScan(target.id, request.id);
    console.log(`Investigating ${target.hostname} for request ${request.id}.`);
    const controller = new AbortController();
    let currentPhase = 'Preparing investigation';
    let actionCount = 0;
    let messageCount = 0;
    const publishPhase = async (phase: string) => { currentPhase = phase; await store.heartbeat(request.id, phase, actionCount, messageCount); };
    heartbeatTimer = setInterval(() => { void store.heartbeat(request.id, currentPhase, actionCount, messageCount).catch(() => {}); }, 5_000);
    let checkingCancellation = false;
    cancellationTimer = setInterval(() => {
      if (checkingCancellation || controller.signal.aborted) return;
      checkingCancellation = true;
      void store.isCancellationRequested(request.id).then((cancelled) => { if (cancelled) controller.abort(new Error('Investigation stopped by the user.')); }).catch(() => {}).finally(() => { checkingCancellation = false; });
    }, 1_000);
    const maxActions = request['mode'] === 'light' ? 22 : 64;
    const report = await investigate(target, {
      maxActions,
      signal: controller.signal,
      onAction: async (action) => { await store.saveAction(target.id, scan!.id, action); actionCount += 1; await store.heartbeat(request.id, currentPhase, actionCount, messageCount); },
      onMessage: async (message) => { await store.saveMessage(target.id, scan!.id, message); messageCount += 1; await store.heartbeat(request.id, currentPhase, actionCount, messageCount); },
      onProgress: publishPhase
    });
    if (await store.isCancellationRequested(request.id)) { await store.cancel(request, scan); continue; }
    await store.complete(request, scan, report);
    console.log(`Completed ${target.hostname}: ${report.findings.length} findings.`);
  } catch (error) {
    if (await store.isCancellationRequested(request.id).catch(() => false)) {
      console.log(`Stopped request ${request.id} at the user's request.`);
      await store.cancel(request, scan);
    } else {
      console.error('Investigation failed:', error);
      await store.fail(request, scan, error);
    }
  } finally {
    if (cancellationTimer) clearInterval(cancellationTimer);
    if (heartbeatTimer) clearInterval(heartbeatTimer);
  }
}
