import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { InfrastructureGraphComponent } from '../components/infrastructure-graph.component';
import { AgentActionRecord, Finding, Target, TlsObservation } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-dashboard', imports: [AppSidebarComponent, InfrastructureGraphComponent, DatePipe, RouterLink],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main">
      <header class="app-header"><div><span class="app-breadcrumb">OBSERVE / OVERVIEW</span><h1>Exposure operations</h1><p>What an unauthenticated outsider can establish about your public infrastructure.</p></div><div class="header-actions"><span class="system-state"><i></i>Agent online</span><a class="button primary compact" routerLink="/app/surface">Open topology <span>→</span></a></div></header>
      @if (error()) { <div class="error-banner"><strong>Live data unavailable</strong><span>{{ error() }}</span></div> }
      @if (primaryTarget(); as target) {
        <section class="ops-metrics">
          <article class="posture-metric"><div class="posture-gauge" [style.--score]="target.posture"><span>{{ target.posture }}</span></div><div><small>EXTERNAL POSTURE</small><strong>{{ postureLabel(target.posture) }}</strong><span>Based on latest retained evidence</span></div></article>
          <article><small>ACTIONABLE FINDINGS</small><strong>{{ actionable().length }}</strong><span class="metric-delta risk"><i></i>{{ urgentCount() }} high priority</span></article>
          <article><small>OBSERVED ASSETS</small><strong>{{ target.assetCount }}</strong><span class="metric-delta"><i></i>1 authorized root</span></article>
          <article><small>LAST INVESTIGATION</small><strong class="time-value">{{ target.lastScanAt | date:'HH:mm:ss' }}</strong><span>{{ target.lastScanAt | date:'MMM d, y' }}</span></article>
        </section>

        <section class="panel topology-panel">
          <div class="panel-heading"><div><span class="section-index">LIVE SURFACE MODEL</span><h2>{{ target.hostname }}</h2></div><div class="panel-actions"><span class="evidence-count">{{ actions().length }} tool observations</span><a routerLink="/app/traces">Inspect trace →</a></div></div>
          <wg-infrastructure-graph [target]="target" [findings]="findings()" [tls]="tls()" [actions]="actions()" />
        </section>

        <section class="dashboard-lower">
          <article class="panel"><div class="panel-heading"><div><span class="section-index">PRIORITY QUEUE</span><h2>Needs review</h2></div><a routerLink="/app/findings">All findings →</a></div>
            <div class="compact-findings">@for (finding of actionable().slice(0, 4); track finding.id) { <a routerLink="/app/findings" class="compact-finding"><span class="severity-mark" [attr.data-severity]="finding.severity"></span><div><strong>{{ finding.title }}</strong><small>{{ finding.asset }} · {{ finding.confidence }}% confidence</small></div><span>→</span></a> } @empty { <div class="empty-state">No actionable findings in the latest records.</div> }</div>
          </article>
          <article class="panel"><div class="panel-heading"><div><span class="section-index">LATEST TRACE</span><h2>Agent activity</h2></div><a routerLink="/app/traces">Full transcript →</a></div>
            <div class="tool-stream">@for (action of actions().slice(-5).reverse(); track action.id) { <div><time>{{ action.occurredAt | date:'HH:mm:ss' }}</time><span>{{ action.tool }}</span><p>{{ compact(action.summary) }}</p></div> } @empty { <div class="empty-state">No retained tool activity yet.</div> }</div>
          </article>
        </section>
      } @else if (!error()) { <div class="loading-state"><i></i>Loading live workspace…</div> }
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class DashboardComponent implements OnInit {
  private readonly db = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]); protected readonly findings = signal<Finding[]>([]);
  protected readonly tls = signal<TlsObservation | null>(null); protected readonly actions = signal<AgentActionRecord[]>([]); protected readonly error = signal('');
  protected readonly primaryTarget = computed(() => this.targets()[0] || null);
  protected readonly actionable = computed(() => this.findings().filter((f) => f.severity !== 'info' && f.status === 'open'));
  protected readonly urgentCount = computed(() => this.findings().filter((f) => f.severity === 'critical' || f.severity === 'high').length);
  ngOnInit(): void { void this.load(); }
  private async load(): Promise<void> { try { const targets = await this.db.targets(); this.targets.set(targets); const target = targets[0]; if (!target) return; const [findings, tls, actions] = await Promise.all([this.db.findings(target.id), this.db.tls(target.id), this.db.agentActions({ targetId: target.id })]); this.findings.set(findings); this.tls.set(tls); this.actions.set(actions); } catch (e) { this.error.set(e instanceof Error ? e.message : 'Could not load workspace data.'); } }
  protected postureLabel(score: number): string { return score >= 90 ? 'Strong' : score >= 70 ? 'Review recommended' : 'Attention required'; }
  protected compact(value: string): string { try { const parsed = JSON.parse(value); return String(parsed.title || parsed.hostname || parsed.status || value).slice(0, 120); } catch { return value.replace(/\s+/g, ' ').slice(0, 120); } }
}
