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
  try {
    await store.claim(request);
    const target = await store.loadTarget(request['target']);
    scan = await store.createScan(target.id, request.id);
    console.log(`Investigating ${target.hostname} for request ${request.id}.`);
    const maxActions = request['mode'] === 'light' ? 18 : 44;
    const report = await investigate(target, { maxActions, onAction: (action) => store.saveAction(target.id, scan!.id, action) });
    await store.complete(request, scan, report);
    console.log(`Completed ${target.hostname}: ${report.findings.length} findings.`);
  } catch (error) {
    console.error('Investigation failed:', error);
    await store.fail(request, scan, error);
  }
}
