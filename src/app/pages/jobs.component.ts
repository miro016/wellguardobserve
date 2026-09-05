import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Scan, ScanRequest, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';
import { scanProfile } from '../scan-profiles';

@Component({
  selector: 'wg-jobs',
  imports: [AppSidebarComponent, RouterLink, DatePipe],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main jobs-page">
      <header class="app-header"><div><span class="app-breadcrumb">TRANSPARENCY / JOB CONTROL</span><h1>Observer jobs</h1><p>Worker heartbeat, current phase, and retained evidence activity for every investigation.</p></div><span class="system-state" [class.live]="active().length > 0"><i></i>{{ active().length ? active().length + ' active' : 'Queue clear' }}</span></header>
      @if (error()) { <div class="error-banner"><strong>Jobs unavailable</strong><span>{{ error() }}</span></div> }

      @if (active().length) {
        <section class="active-job-stack" aria-live="polite">
          @for (job of active(); track job.id) {
            <article class="panel job-card" [attr.data-health]="health(job)">
              <header><div class="job-orbit"><i></i><span></span></div><div><span class="section-index">{{ profileName(job) }} contract · {{ job.id }}</span><h2>{{ targetName(job.target) }}</h2></div><span class="job-health">{{ healthLabel(job) }}</span></header>
              <div class="job-phase"><small>CURRENT PHASE</small><strong>{{ job.phase || (job.status === 'queued' ? 'Waiting for observer worker' : 'Preparing investigation') }}</strong><p>{{ activity(job) }}</p></div>
              <div class="job-vitals"><div><small>STATE</small><strong>{{ job.status }}</strong></div><div><small>ELAPSED</small><strong>{{ elapsed(job) }}</strong></div><div><small>HEARTBEAT</small><strong>{{ heartbeatAge(job) }}</strong></div><div><small>CONTRACT</small><strong>{{ job.actionCount }} / {{ actionBudget(job) }} tools</strong></div></div>
              <footer><span>{{ healthExplanation(job) }}</span><div>@if (job.status === 'queued' || job.status === 'processing') { <button class="button danger compact" type="button" (click)="stop(job)">Stop</button> }<a class="button primary compact" [routerLink]="['/app/investigations', job.id]">Open live trace →</a></div></footer>
            </article>
          }
        </section>
      } @else { <section class="panel queue-clear"><span>✓</span><div><h2>No investigation is running</h2><p>The observer queue is clear. Start a scan from a target or the administration page.</p></div><a class="button secondary compact" routerLink="/app/targets">Choose target →</a></section> }

      <section class="panel job-history"><div class="panel-heading"><div><span class="section-index">RECENT QUEUE HISTORY</span><h2>Latest jobs</h2></div><span class="evidence-count">Auto-refresh · 2 sec while active</span></div><div class="job-table"><div class="job-table-head"><span>Target</span><span>Status</span><span>Last phase</span><span>Evidence</span><span>Time</span><span></span></div>@for (job of recent(); track job.id) { <a class="job-table-row" [routerLink]="['/app/investigations', job.id]"><span><strong>{{ targetName(job.target) }}</strong><small>{{ job.id }}</small></span><span class="state-pill" [attr.data-state]="job.status === 'completed' ? 'healthy' : job.status === 'failed' ? 'risk' : job.status === 'cancelled' ? 'warning' : 'observed'">{{ job.status }}</span><span [class.job-failure-reason]="job.status === 'failed'">{{ job.status === 'failed' ? failureSummary(job) : (job.phase || 'Legacy job · phase not retained') }}</span><span>{{ retainedLabel(job) }}</span><span>{{ (job.completedAt || job.heartbeatAt || job.created) | date:'MMM d, HH:mm:ss' }}</span><b>→</b></a> } @empty { <div class="empty-state">No scan request has been created yet.</div> }</div></section>
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class JobsComponent implements OnInit, OnDestroy {
  private readonly db = inject(PocketBaseService);
  private timer?: ReturnType<typeof setTimeout>;
  private refreshing = false;
  protected readonly requests = signal<ScanRequest[]>([]);
  protected readonly scans = signal<Scan[]>([]);
  protected readonly targets = signal<Target[]>([]);
  protected readonly now = signal(Date.now());
  protected readonly error = signal('');
  protected readonly active = computed(() => this.requests().filter((job) => ['queued', 'processing', 'cancelling'].includes(job.status)));
  protected readonly recent = computed(() => this.requests().filter((job) => !this.active().some((active) => active.id === job.id)).slice(0, 30));

  ngOnInit(): void { void this.refresh(); }
  ngOnDestroy(): void { if (this.timer) clearTimeout(this.timer); }

  protected targetName(id: string): string { return this.targets().find((target) => target.id === id)?.hostname || 'Unknown target'; }
  protected profileName(job: ScanRequest): string { return job.profileSnapshot?.name || scanProfile(job.mode).name; }
  protected actionBudget(job: ScanRequest): number { return job.profileSnapshot?.maxActions || scanProfile(job.mode).maxActions; }
  protected scan(job: ScanRequest): Scan | undefined { return this.scans().find((scan) => scan.request === job.id); }
  protected actionCount(job: ScanRequest): number { return job.actionCount; }
  protected messageCount(job: ScanRequest): number { return job.messageCount; }
  protected retainedLabel(job: ScanRequest): string { return !job.heartbeatAt && !['queued', 'processing', 'cancelling'].includes(job.status) ? 'Legacy scan' : `${job.actionCount} tools · ${job.messageCount} messages`; }
  protected failureSummary(job: ScanRequest): string {
    const message = this.scan(job)?.error || job.error || job.phase || 'Investigation failed without a retained diagnostic.';
    return message.length > 140 ? `${message.slice(0, 137)}…` : message;
  }
  protected heartbeatSeconds(job: ScanRequest): number { const value = Date.parse(job.heartbeatAt || job.startedAt || job.created); return Number.isFinite(value) ? Math.max(0, Math.round((this.now() - value) / 1000)) : 0; }
  protected health(job: ScanRequest): string { if (job.status === 'queued') return 'queued'; const age = this.heartbeatSeconds(job); return age <= 15 ? 'live' : age <= 45 ? 'late' : 'stalled'; }
  protected healthLabel(job: ScanRequest): string { return ({ queued: 'Queued', live: 'Heartbeat live', late: 'Heartbeat delayed', stalled: 'Check worker' } as Record<string, string>)[this.health(job)]!; }
  protected heartbeatAge(job: ScanRequest): string { if (job.status === 'queued' && !job.heartbeatAt) return 'Not claimed'; const seconds = this.heartbeatSeconds(job); return seconds < 2 ? 'Now' : `${seconds}s ago`; }
  protected elapsed(job: ScanRequest): string {
    const start = Date.parse(job.startedAt || job.created); const end = Date.parse(job.completedAt) || this.now(); const seconds = Math.max(0, Math.round((end - start) / 1000));
    return seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
  }
  protected activity(job: ScanRequest): string {
    if (!this.scan(job)) return 'The request is waiting to create its retained scan record.';
    if (job.actionCount || job.messageCount) return `${job.actionCount} completed tool event${job.actionCount === 1 ? '' : 's'} and ${job.messageCount} transcript event${job.messageCount === 1 ? '' : 's'} retained.`;
    return 'The worker has claimed this request and is preparing its first event.';
  }
  protected healthExplanation(job: ScanRequest): string {
    const state = this.health(job);
    if (state === 'queued') return 'Queued jobs begin when the observer becomes available.';
    if (state === 'stalled') return 'No worker heartbeat for more than 45 seconds. Open the trace before deciding whether to stop it.';
    if (state === 'late') return 'The worker heartbeat is later than usual; the current bounded request may still be returning.';
    return 'The worker is alive. Tool results appear only after the bounded request completes.';
  }
  protected async stop(job: ScanRequest): Promise<void> { try { await this.db.cancelScan(job); await this.refresh(false); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not stop this job.'); } }

  private async refresh(schedule = true): Promise<void> {
    if (this.refreshing) return; this.refreshing = true;
    try {
      const [requests, scans, targets] = await Promise.all([this.db.scanRequests(), this.db.scans(), this.db.targets()]);
      this.requests.set(requests); this.scans.set(scans); this.targets.set(targets); this.now.set(Date.now()); this.error.set('');
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not refresh jobs.'); }
    finally { this.refreshing = false; if (schedule) this.timer = setTimeout(() => void this.refresh(), this.active().length ? 2_000 : 10_000); }
  }
}
