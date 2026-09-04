import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { ScanMode, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';
import { SCAN_PROFILES, scanProfile, storedScanProfile } from '../scan-profiles';

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
            <label><span>Related exact hostnames <em>optional</em></span><textarea name="authorizedHosts" [(ngModel)]="authorizedHosts" rows="3" placeholder="project-keycloak.provider.example"></textarea><small>Explicitly authorizes only these exact external hostnames. Their parent domain and sibling tenants remain out of scope.</small></label>
            <label><span>Approval record</span><textarea name="reason" [(ngModel)]="reason" rows="3" maxlength="500" placeholder="I own and administer this domain." required></textarea></label>
            <fieldset class="form-profile"><legend>Scan contract</legend><div class="profile-tabs">@for (profile of profiles; track profile.id) { <button type="button" [class.active]="scanMode === profile.id" (click)="setScanMode(profile.id)"><span>{{ profile.signal }}</span><strong>{{ profile.name }}</strong><small>{{ profile.maxActions }} tools</small></button> }</div><p>{{ selectedProfile().description }}</p><dl><div><dt>Methods</dt><dd>{{ selectedProfile().methods }}</dd></div><div><dt>Capabilities</dt><dd>{{ selectedProfile().capabilities.join(' · ') }}</dd></div></dl></fieldset>
            <label class="authorization-check"><input name="confirmed" type="checkbox" [(ngModel)]="confirmed"><span><strong>I own this infrastructure or have explicit permission to assess it.</strong><small>Wellguard will make bounded DNS, TLS, TCP, and safe HTTP requests to this root and its discovered subdomains.</small></span></label>
            <div class="form-actions"><button class="button primary" type="submit" [disabled]="busy() || !db.isAdmin()">{{ busy() ? 'Creating…' : 'Add target & run scan' }} <span>→</span></button><button class="button secondary" type="button" (click)="create(false)" [disabled]="busy() || !db.isAdmin()">Add without scan</button></div>
          </div>
        </form>

        <section class="panel operations-list"><div class="panel-heading"><div><span class="section-index">AUTHORIZED SCOPE</span><h2>{{ targets().length }} targets</h2></div><span class="evidence-count">{{ selectedProfile().name }} contract</span></div>
          <div class="target-operations">@for (target of targets(); track target.id) {
            <article><a [routerLink]="['/app/targets', target.id]"><span class="target-monogram">{{ target.hostname[0].toUpperCase() }}</span><span><strong>{{ target.hostname }}</strong><small>{{ target.name }} · {{ target.assetCount }} observed assets</small></span></a><div><span class="state-pill" [attr.data-state]="target.status === 'scanning' ? 'warning' : 'healthy'">{{ scanState(target) }}</span><button class="button secondary compact" type="button" (click)="run(target)" [disabled]="queued()[target.id]">{{ queued()[target.id] ? 'Queued' : 'Run scan' }}</button></div>@if (target.hostHints.length) { <p><b>Host hints</b>{{ target.hostHints.join(' · ') }}</p> }@if (target.authorizedHosts.length) { <p class="exact-scope"><b>Exact external scope</b>{{ target.authorizedHosts.join(' · ') }}</p> }<footer><span>Last observed</span><strong>{{ target.lastScanAt ? (target.lastScanAt | date:'MMM d, y · HH:mm') : 'Never' }}</strong></footer></article>
          } @empty { <div class="empty-state"><strong>No targets approved yet.</strong><span>Add the first owned domain using the authorization form.</span></div> }</div>
          @if (targets().length) { <form class="related-scope-form" (ngSubmit)="addRelatedScope()"><span class="section-index">AUTHORIZE A RELATED ASSET</span><div><label><span>Target</span><select name="scopeTarget" [(ngModel)]="scopeTargetId">@for (target of targets(); track target.id) { <option [value]="target.id">{{ target.hostname }}</option> }</select></label><label><span>Exact hostname</span><input name="scopeHostname" [(ngModel)]="scopeHostname" placeholder="service.shared-provider.example" required></label></div><label><span>Approval record</span><input name="scopeReason" [(ngModel)]="scopeReason" maxlength="500" required></label><label class="scope-confirm"><input name="scopeConfirmed" type="checkbox" [(ngModel)]="scopeConfirmed"><span>I own or have permission to assess this exact hostname.</span></label><button class="button secondary compact" type="submit" [disabled]="scopeBusy()">{{ scopeBusy() ? 'Authorizing…' : 'Authorize exact hostname' }}</button></form> }
        </section>
      </section>
    </main></div>`,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AdminComponent implements OnInit {
  protected readonly db = inject(PocketBaseService);
  private readonly router = inject(Router);
  protected readonly targets = signal<Target[]>([]); protected readonly busy = signal(false); protected readonly queued = signal<Record<string, boolean>>({}); protected readonly error = signal(''); protected readonly notice = signal('');
  protected name = ''; protected hostname = ''; protected hostHints = ''; protected authorizedHosts = ''; protected reason = 'I own and administer this infrastructure.'; protected confirmed = false;
  protected readonly profiles = SCAN_PROFILES; protected scanMode: ScanMode = storedScanProfile();
  protected selectedProfile() { return scanProfile(this.scanMode); }
  protected setScanMode(mode: ScanMode): void { this.scanMode = mode; }
  protected scopeTargetId = ''; protected scopeHostname = ''; protected scopeReason = 'I own or administer this related service hostname.'; protected scopeConfirmed = false; protected readonly scopeBusy = signal(false);
  ngOnInit(): void { void this.load(); }
  private async load(): Promise<void> { try { const targets = await this.db.targets(); this.targets.set(targets); if (!targets.some((target) => target.id === this.scopeTargetId)) this.scopeTargetId = targets[0]?.id || ''; } catch (error) { this.error.set(error instanceof Error ? error.message : 'Targets could not be loaded.'); } }
  protected async create(runScan: boolean): Promise<void> {
    this.error.set(''); this.notice.set('');
    if (!this.confirmed) { this.error.set('Confirm that you own the target or have explicit permission to assess it.'); return; }
    if (!this.name.trim() || !this.reason.trim()) { this.error.set('Enter a display name and a clear approval record.'); return; }
    let hostname: string; let hints: string[]; let authorizedHosts: string[];
    try { hostname = this.normalizeRoot(this.hostname); hints = this.normalizeHints(hostname, this.hostHints); authorizedHosts = this.normalizeExactHosts(hostname, this.authorizedHosts); }
    catch (error) { this.error.set(error instanceof Error ? error.message : 'Check the target hostname.'); return; }
    this.busy.set(true);
    try {
      const target = await this.db.createTarget({ name: this.name.trim(), hostname, hostHints: hints, authorizedHosts, authorizationReason: this.reason.trim() });
      if (runScan) {
        const requestId = await this.db.requestScan(target.id, this.scanMode);
        this.queued.update((state) => ({ ...state, [target.id]: true }));
        await this.router.navigate(['/app/investigations', requestId]);
        return;
      }
      this.notice.set(runScan ? `${target.hostname} was approved and queued.` : `${target.hostname} was approved.`);
      this.name = ''; this.hostname = ''; this.hostHints = ''; this.authorizedHosts = ''; this.confirmed = false;
      await this.load();
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'The target could not be created.'); }
    finally { this.busy.set(false); }
  }
  protected async run(target: Target): Promise<void> {
    this.error.set(''); this.notice.set(''); this.queued.update((state) => ({ ...state, [target.id]: true }));
    try { const requestId = await this.db.requestScan(target.id, this.scanMode); await this.router.navigate(['/app/investigations', requestId]); }
    catch (error) { this.queued.update((state) => ({ ...state, [target.id]: false })); this.error.set(error instanceof Error ? error.message : 'The scan could not be queued.'); }
  }
  protected scanState(target: Target): string { return this.queued()[target.id] ? 'Queued' : target.status === 'scanning' ? 'Scanning' : 'Ready'; }
  protected async addRelatedScope(): Promise<void> {
    this.error.set(''); this.notice.set('');
    if (!this.scopeConfirmed) { this.error.set('Confirm authorization for the exact related hostname.'); return; }
    let hostname: string;
    try { hostname = this.normalizeHostname(this.scopeHostname); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Check the related hostname.'); return; }
    this.scopeBusy.set(true);
    try {
      await this.db.addTargetScope(this.scopeTargetId, hostname, this.scopeReason.trim());
      this.notice.set(`${hostname} is now explicitly authorized for this target.`); this.scopeHostname = ''; this.scopeConfirmed = false; await this.load();
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'The related hostname could not be authorized.'); }
    finally { this.scopeBusy.set(false); }
  }
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
  private normalizeHostname(value: string): string {
    const hostname = value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/:?#].*$/, '').replace(/\.$/, '');
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname)) throw new Error('Enter one exact public hostname without a path or port.');
    return hostname;
  }
  private normalizeExactHosts(root: string, value: string): string[] {
    return [...new Set(value.split(/[\s,]+/).filter(Boolean).map((item) => this.normalizeHostname(item)))].filter((hostname) => hostname !== root && !hostname.endsWith(`.${root}`)).slice(0, 20);
  }
}
