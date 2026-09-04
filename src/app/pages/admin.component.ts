import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-admin', imports: [AppSidebarComponent, FormsModule, RouterLink, DatePipe],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main admin-page">
      <header class="app-header"><div><span class="app-breadcrumb">WORKSPACE / ADMINISTRATION</span><h1>Target operations</h1><p>Approve owned infrastructure, give the observer useful host clues, and start a bounded investigation.</p></div><span class="scope-lock">⌾ Administrator approval required</span></header>
      @if (!db.isAdmin()) { <div class="error-banner"><strong>Administrator access required</strong><span>Your account cannot approve new reconnaissance targets.</span></div> }
      @if (error()) { <div class="error-banner"><strong>Operation failed</strong><span>{{ error() }}</span></div> }
      @if (notice()) { <div class="success-banner"><strong>{{ notice() }}</strong><span>The observer queue will pick up requested scans automatically.</span></div> }

      <section class="admin-grid">
        <form class="panel target-form" (ngSubmit)="create(true)">
          <div class="panel-heading"><div><span class="section-index">AUTHORIZE A ROOT</span><h2>Add target</h2></div><span class="evidence-count">Recon only</span></div>
          <div class="form-body">
            <label><span>Display name</span><input name="name" [(ngModel)]="name" maxlength="160" placeholder="Production perimeter" required></label>
            <label><span>Root domain</span><input name="hostname" [(ngModel)]="hostname" maxlength="253" inputmode="url" autocomplete="off" placeholder="example.com" required><small>Enter a root domain without a protocol, path, or port.</small></label>
            <label><span>Known service hosts <em>optional</em></span><textarea name="hostHints" [(ngModel)]="hostHints" rows="4" placeholder="sso.example.com&#10;staging.example.com"></textarea><small>One hostname per line or comma separated. Hints must stay beneath the approved root; passive discovery still runs.</small></label>
            <label><span>Approval record</span><textarea name="reason" [(ngModel)]="reason" rows="3" maxlength="500" placeholder="I own and administer this domain." required></textarea></label>
            <label class="authorization-check"><input name="confirmed" type="checkbox" [(ngModel)]="confirmed"><span><strong>I own this infrastructure or have explicit permission to assess it.</strong><small>Wellguard will make bounded DNS, TLS, TCP, and safe HTTP requests to this root and its discovered subdomains.</small></span></label>
            <div class="form-actions"><button class="button primary" type="submit" [disabled]="busy() || !db.isAdmin()">{{ busy() ? 'Creating…' : 'Add target & run scan' }} <span>→</span></button><button class="button secondary" type="button" (click)="create(false)" [disabled]="busy() || !db.isAdmin()">Add without scan</button></div>
          </div>
        </form>

        <section class="panel operations-list"><div class="panel-heading"><div><span class="section-index">AUTHORIZED SCOPE</span><h2>{{ targets().length }} targets</h2></div><span class="evidence-count">Private preview</span></div>
          <div class="target-operations">@for (target of targets(); track target.id) {
            <article><a [routerLink]="['/app/targets', target.id]"><span class="target-monogram">{{ target.hostname[0].toUpperCase() }}</span><span><strong>{{ target.hostname }}</strong><small>{{ target.name }} · {{ target.assetCount }} observed assets</small></span></a><div><span class="state-pill" [attr.data-state]="target.status === 'scanning' ? 'warning' : 'healthy'">{{ scanState(target) }}</span><button class="button secondary compact" type="button" (click)="run(target)" [disabled]="queued()[target.id]">{{ queued()[target.id] ? 'Queued' : 'Run scan' }}</button></div>@if (target.hostHints.length) { <p><b>Host hints</b>{{ target.hostHints.join(' · ') }}</p> }<footer><span>Last observed</span><strong>{{ target.lastScanAt ? (target.lastScanAt | date:'MMM d, y · HH:mm') : 'Never' }}</strong></footer></article>
          } @empty { <div class="empty-state"><strong>No targets approved yet.</strong><span>Add the first owned domain using the authorization form.</span></div> }</div>
        </section>
      </section>
    </main></div>`,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AdminComponent implements OnInit {
  protected readonly db = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]); protected readonly busy = signal(false); protected readonly queued = signal<Record<string, boolean>>({}); protected readonly error = signal(''); protected readonly notice = signal('');
  protected name = ''; protected hostname = ''; protected hostHints = ''; protected reason = 'I own and administer this infrastructure.'; protected confirmed = false;
  ngOnInit(): void { void this.load(); }
  private async load(): Promise<void> { try { this.targets.set(await this.db.targets()); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Targets could not be loaded.'); } }
  protected async create(runScan: boolean): Promise<void> {
    this.error.set(''); this.notice.set('');
    if (!this.confirmed) { this.error.set('Confirm that you own the target or have explicit permission to assess it.'); return; }
    if (!this.name.trim() || !this.reason.trim()) { this.error.set('Enter a display name and a clear approval record.'); return; }
    let hostname: string; let hints: string[];
    try { hostname = this.normalizeRoot(this.hostname); hints = this.normalizeHints(hostname, this.hostHints); }
    catch (error) { this.error.set(error instanceof Error ? error.message : 'Check the target hostname.'); return; }
    this.busy.set(true);
    try {
      const target = await this.db.createTarget({ name: this.name.trim(), hostname, hostHints: hints, authorizationReason: this.reason.trim() });
      if (runScan) { await this.db.requestScan(target.id, 'standard'); this.queued.update((state) => ({ ...state, [target.id]: true })); }
      this.notice.set(runScan ? `${target.hostname} was approved and queued.` : `${target.hostname} was approved.`);
      this.name = ''; this.hostname = ''; this.hostHints = ''; this.confirmed = false;
      await this.load();
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'The target could not be created.'); }
    finally { this.busy.set(false); }
  }
  protected async run(target: Target): Promise<void> {
    this.error.set(''); this.notice.set(''); this.queued.update((state) => ({ ...state, [target.id]: true }));
    try { await this.db.requestScan(target.id, 'standard'); this.notice.set(`${target.hostname} was queued for a standard investigation.`); }
    catch (error) { this.queued.update((state) => ({ ...state, [target.id]: false })); this.error.set(error instanceof Error ? error.message : 'The scan could not be queued.'); }
  }
  protected scanState(target: Target): string { return this.queued()[target.id] ? 'Queued' : target.status === 'scanning' ? 'Scanning' : 'Ready'; }
  private normalizeRoot(value: string): string {
    const raw = value.trim().toLowerCase().replace(/\.$/, '');
    if (/^https?:\/\//.test(raw) || /[\/:?#]/.test(raw) || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(raw)) throw new Error('Enter a valid root domain such as example.com, without a protocol or path.');
    return raw;
  }
  private normalizeHints(root: string, value: string): string[] {
    const hints = [...new Set(value.split(/[\s,]+/).map((item) => item.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/:].*$/, '').replace(/\.$/, '')).filter(Boolean))];
    if (hints.some((hint) => hint !== root && !hint.endsWith(`.${root}`))) throw new Error(`Every service hint must be ${root} or one of its subdomains.`);
    return hints.slice(0, 40);
  }
}
