import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { AgentActionRecord, AgentMessageRecord, Scan, ScanRequest, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';
import { ReportSummaryComponent } from '../components/report-summary.component';

@Component({
  selector: 'wg-live-investigation',
  imports: [AppSidebarComponent, DatePipe, RouterLink, ReportSummaryComponent],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main live-investigation-page">
      <header class="app-header"><div><a class="app-breadcrumb" routerLink="/app/targets">OBSERVE / LIVE INVESTIGATION</a><h1>{{ target()?.hostname || 'Preparing investigation…' }}</h1><p>Model reasoning and bounded read-only requests appear here as they happen.</p></div><div class="header-actions">@if (isActive()) { <span class="system-state live"><i></i>Observer active</span><button class="button danger compact" type="button" (click)="stop()" [disabled]="stopping()">{{ stopping() ? 'Stopping safely…' : 'Stop investigation' }}</button> } @else { <span class="state-pill" [attr.data-state]="request()?.status === 'completed' ? 'healthy' : request()?.status === 'cancelled' ? 'warning' : 'risk'">{{ statusLabel() }}</span> }</div></header>

      @if (error()) { <div class="error-banner"><strong>Live view unavailable</strong><span>{{ error() }}</span></div> }
      @if (request(); as job) {
        <section class="investigation-status panel" [attr.data-status]="job.status">
          <div class="scan-progress-head"><div><span class="section-index">{{ job.mode.toUpperCase() }} / REQUEST {{ job.id }}</span><h2>{{ statusLabel() }}</h2></div><strong>{{ progress() }}%</strong></div>
          <div class="scan-progress"><span [style.width.%]="progress()"></span></div>
          <div class="live-phase"><span [attr.data-health]="heartbeatHealth()"><i></i>{{ heartbeatLabel() }}</span><div><small>CURRENT WORKER PHASE</small><strong>{{ job.phase || (job.status === 'queued' ? 'Waiting for observer worker' : 'Preparing investigation') }}</strong></div></div>
          <div class="scan-vitals"><div><small>STARTED</small><strong>{{ job.startedAt ? (job.startedAt | date:'mediumTime') : 'Waiting for worker' }}</strong></div><div><small>TOOL CALLS</small><strong>{{ actions().length }}</strong></div><div><small>MESSAGES</small><strong>{{ messages().length }}</strong></div><div><small>LAST EVENT</small><strong>{{ lastEvent() | date:'mediumTime' }}</strong></div></div>
          @if (job.status === 'cancelling') { <p class="stop-note">The agent will stop after the active bounded network request returns. No new tool call will begin.</p> }
          @if (job.status === 'cancelled') { <p class="stop-note">Investigation stopped. Evidence collected before cancellation remains available below.</p> }
        </section>

        <section class="trace-layout live-trace"><article class="panel transcript-panel"><div class="panel-heading"><div><span class="section-index">LIVE MODEL CHANNEL</span><h2>Conversation</h2></div><span class="evidence-count"><i class="live-dot"></i>{{ messages().length }} events</span></div><div class="transcript" aria-live="polite">@for (message of messages(); track message.id) { <article class="message" [attr.data-role]="message.role"><header><span>{{ message.role }}</span>@if (message.toolName) { <b>{{ message.toolName }}</b> }<time>{{ message.occurredAt | date:'HH:mm:ss' }}</time></header><pre>{{ message.content }}</pre></article> } @empty { <div class="live-wait"><i></i><strong>Waiting for the agent</strong><span>The worker will publish its instructions and first decision here.</span></div> }</div></article>
        <aside class="panel tools-panel"><div class="panel-heading"><div><span class="section-index">BOUNDED EXECUTION</span><h2>Tool calls</h2></div><span class="evidence-count">{{ actions().length }} retained</span></div><div class="tool-calls" aria-live="polite">@for (action of actions(); track action.id; let index = $index) { <details [open]="$last"><summary><span>{{ index + 1 }}</span><strong>{{ action.tool }}</strong><time>{{ action.occurredAt | date:'HH:mm:ss' }}</time></summary><div><small>INPUT</small><pre>{{ json(action.input) }}</pre><small>RESULT</small><pre>{{ pretty(action.summary) }}</pre></div></details> } @empty { <div class="live-wait compact"><i></i><strong>No request sent yet</strong><span>DNS, TLS, HTTP, and public-source activity will appear here.</span></div> }</div></aside></section>

        @if (!isActive()) { <section class="investigation-handoff panel"><div><span class="section-index">INVESTIGATION RETAINED</span><h2>{{ request()?.status === 'completed' ? 'Continue with the evidence' : 'Review the partial trace' }}</h2><wg-report-summary [text]="scan()?.summary || scan()?.error || request()?.error || 'The full transcript and completed tool results remain available.'" /></div><div><a class="button secondary" [routerLink]="['/app/surface']" [queryParams]="{ target: job.target }">Open surface map</a><a class="button primary" routerLink="/app/traces" [queryParams]="{ target: job.target }">Audit full trace →</a></div></section> }
      }
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LiveInvestigationComponent implements OnInit, OnDestroy {
  private readonly db = inject(PocketBaseService);
  private readonly route = inject(ActivatedRoute);
  private timer?: ReturnType<typeof setTimeout>;
  private polling = false;
  protected readonly request = signal<ScanRequest | null>(null);
  protected readonly scan = signal<Scan | null>(null);
  protected readonly target = signal<Target | null>(null);
  protected readonly messages = signal<AgentMessageRecord[]>([]);
  protected readonly actions = signal<AgentActionRecord[]>([]);
  protected readonly error = signal('');
  protected readonly now = signal(Date.now());
  protected readonly stopping = signal(false);
  protected readonly isActive = computed(() => ['queued', 'processing', 'cancelling'].includes(this.request()?.status || ''));
  protected readonly progress = computed(() => {
    const status = this.request()?.status;
    if (status === 'completed') return 100;
    if (status === 'cancelled' || status === 'failed') return Math.min(96, 10 + this.actions().length * 3);
    if (status === 'cancelling') return Math.min(94, 18 + this.actions().length * 3);
    if (status === 'processing') return Math.min(92, 12 + this.actions().length * 3);
    return 4;
  });
  protected readonly lastEvent = computed(() => this.actions().at(-1)?.occurredAt || this.messages().at(-1)?.occurredAt || this.request()?.startedAt || this.request()?.created || '');
  protected readonly heartbeatAge = computed(() => { const value = Date.parse(this.request()?.heartbeatAt || this.request()?.startedAt || ''); return Number.isFinite(value) ? Math.max(0, Math.round((this.now() - value) / 1000)) : 0; });
  protected readonly heartbeatHealth = computed(() => this.request()?.status === 'queued' ? 'queued' : this.heartbeatAge() <= 15 ? 'live' : this.heartbeatAge() <= 45 ? 'late' : 'stalled');

  ngOnInit(): void { void this.refresh(); }
  ngOnDestroy(): void { if (this.timer) clearTimeout(this.timer); }

  protected statusLabel(): string {
    return ({ queued: 'Waiting for observer', processing: 'Investigating public surface', cancelling: 'Stopping after active request', cancelled: 'Investigation stopped', completed: 'Investigation completed', failed: 'Investigation failed' } as Record<string, string>)[this.request()?.status || ''] || 'Loading investigation';
  }
  protected json(value: unknown): string { return JSON.stringify(value, null, 2); }
  protected pretty(value: string): string { try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; } }
  protected heartbeatLabel(): string { if (this.request()?.status === 'queued') return 'Waiting to be claimed'; const age = this.heartbeatAge(); return age < 2 ? 'Worker heartbeat now' : `Worker heartbeat ${age}s ago`; }

  protected async stop(): Promise<void> {
    const request = this.request(); if (!request || !this.isActive()) return;
    this.stopping.set(true); this.error.set('');
    try { await this.db.cancelScan(request); await this.refresh(false); }
    catch (error) { this.error.set(error instanceof Error ? error.message : 'The investigation could not be stopped.'); this.stopping.set(false); }
  }

  private async refresh(schedule = true): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      const requestId = this.route.snapshot.paramMap.get('requestId') || '';
      const request = await this.db.scanRequest(requestId);
      const [scan, targets] = await Promise.all([this.db.scanForRequest(requestId), this.target() ? Promise.resolve([]) : this.db.targets()]);
      const [messages, actions] = scan ? await Promise.all([this.db.agentMessages({ scanId: scan.id }), this.db.agentActions({ scanId: scan.id })]) : [[], []];
      this.request.set(request); this.scan.set(scan); this.messages.set(messages); this.actions.set(actions);
      this.now.set(Date.now());
      if (targets.length) this.target.set(targets.find((item) => item.id === request.target) || null);
      if (!['queued', 'processing', 'cancelling'].includes(request.status)) this.stopping.set(false);
      this.error.set('');
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not refresh the investigation.'); }
    finally {
      this.polling = false;
      if (schedule && this.isActive()) this.timer = setTimeout(() => void this.refresh(), 1_000);
    }
  }
}
