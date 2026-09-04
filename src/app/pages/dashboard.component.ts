import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { AgentActionRecord, Finding, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-dashboard', imports: [AppSidebarComponent, DatePipe, RouterLink],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main">
      <header class="app-header"><div><span class="app-breadcrumb">OBSERVE / OVERVIEW</span><h1>Exposure operations</h1><p>Every authorized root and the distinct public services verified beneath it.</p></div><div class="header-actions"><span class="system-state"><i></i>Agent online</span><a class="button primary compact" routerLink="/app/admin">Add or scan target <span>→</span></a></div></header>
      @if (error()) { <div class="error-banner"><strong>Live data unavailable</strong><span>{{ error() }}</span></div> }
      @if (targets().length) {
        <section class="ops-metrics">
          <article class="posture-metric"><div class="posture-gauge" [style.--score]="portfolioPosture()"><span>{{ portfolioPosture() }}</span></div><div><small>PORTFOLIO POSTURE</small><strong>{{ postureLabel(portfolioPosture()) }}</strong><span>Average across authorized roots</span></div></article>
          <article><small>ACTIONABLE FINDINGS</small><strong>{{ actionable().length }}</strong><span class="metric-delta risk"><i></i>{{ urgentCount() }} high priority</span></article>
          <article><small>OBSERVED ASSETS</small><strong>{{ assetCount() }}</strong><span class="metric-delta"><i></i>{{ targets().length }} authorized root{{ targets().length === 1 ? '' : 's' }}</span></article>
          <article><small>LAST INVESTIGATION</small><strong class="time-value">{{ latestTarget().lastScanAt | date:'HH:mm:ss' }}</strong><span>{{ latestTarget().lastScanAt | date:'MMM d, y' }}</span></article>
        </section>

        <section class="panel estate-panel">
          <div class="panel-heading"><div><span class="section-index">ALL-TARGET SURFACE</span><h2>External estate</h2></div><div class="panel-actions"><span class="evidence-count">{{ actions().length }} retained observations</span><a routerLink="/app/surface">Inspect topology →</a></div></div>
          <div class="estate-map"><header><span>Authorized root</span><span>Public path</span><span>Verified service surface</span><span>Posture</span></header>
            @for (target of targets(); track target.id) { <article class="estate-row">
              <a class="estate-node domain" [routerLink]="['/app/targets', target.id]"><i>◎</i><span><strong>{{ target.hostname }}</strong><small>{{ target.name }}</small></span></a><span class="estate-link"><i></i></span>
              <div class="estate-node edge"><i>◇</i><span><strong>{{ provider(target) }}</strong><small>{{ provider(target) === 'Cloudflare' ? 'Proxy / tunnel edge' : 'Public route' }}</small></span></div><span class="estate-link"><i></i></span>
              <a class="estate-node service" routerLink="/app/surface" [queryParams]="{target: target.id}" [attr.data-state]="targetState(target)"><i>◆</i><span><strong>{{ serviceCount(target) }} distinct service{{ serviceCount(target) === 1 ? '' : 's' }}</strong><small>{{ topSignal(target) }}</small></span></a>
              <div class="estate-score" [attr.data-state]="targetState(target)"><strong>{{ target.posture }}</strong><span>/100</span><small>{{ findingsFor(target).length }} open</small></div>
            </article> }
          </div>
        </section>

        <section class="dashboard-lower">
          <article class="panel"><div class="panel-heading"><div><span class="section-index">PORTFOLIO PRIORITY QUEUE</span><h2>Needs review</h2></div><a routerLink="/app/findings">Open register →</a></div>
            <div class="compact-findings">@for (finding of actionable().slice(0, 5); track finding.id) { <a routerLink="/app/findings" class="compact-finding"><span class="severity-mark" [attr.data-severity]="finding.severity"></span><div><strong>{{ finding.title }}</strong><small>{{ targetHost(finding.target) }} · {{ finding.asset }} · {{ finding.confidence }}%</small></div><span>→</span></a> } @empty { <div class="empty-state">No actionable findings in retained records.</div> }</div>
          </article>
          <article class="panel"><div class="panel-heading"><div><span class="section-index">LATEST TRACE</span><h2>Agent activity</h2></div><a routerLink="/app/traces">Full transcript →</a></div>
            <div class="tool-stream">@for (action of latestActions(); track action.id) { <div><time>{{ action.occurredAt | date:'HH:mm:ss' }}</time><span>{{ action.tool }}</span><p>{{ compact(action.summary) }}</p></div> } @empty { <div class="empty-state">No retained tool activity yet.</div> }</div>
          </article>
        </section>
      } @else if (!error()) { <div class="empty-state panel"><strong>No authorized targets.</strong><span>Open Administration to approve a domain and start the first scan.</span><a class="button primary compact" routerLink="/app/admin">Add target →</a></div> }
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class DashboardComponent implements OnInit {
  private readonly db = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]); protected readonly findings = signal<Finding[]>([]); protected readonly actions = signal<AgentActionRecord[]>([]); protected readonly error = signal('');
  protected readonly actionable = computed(() => this.findings().filter((finding) => finding.severity !== 'info' && finding.status === 'open'));
  protected readonly urgentCount = computed(() => this.findings().filter((finding) => finding.status === 'open' && (finding.severity === 'critical' || finding.severity === 'high')).length);
  protected readonly assetCount = computed(() => this.targets().reduce((sum, target) => sum + Math.max(1, target.assetCount), 0));
  protected readonly portfolioPosture = computed(() => Math.round(this.targets().reduce((sum, target) => sum + target.posture, 0) / Math.max(1, this.targets().length)));
  protected readonly latestTarget = computed(() => [...this.targets()].sort((a, b) => Date.parse(b.lastScanAt || '0') - Date.parse(a.lastScanAt || '0'))[0] || null);
  protected readonly latestActions = computed(() => [...this.actions()].sort((a, b) => Date.parse(b.occurredAt) - Date.parse(a.occurredAt)).slice(0, 5));
  ngOnInit(): void { void this.load(); }
  private async load(): Promise<void> { try { const [targets, findings, actions] = await Promise.all([this.db.targets(), this.db.findings(), this.db.agentActions()]); this.targets.set(targets); this.findings.set(findings); this.actions.set(actions); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not load workspace data.'); } }
  protected findingsFor(target: Target): Finding[] { return this.findings().filter((finding) => finding.target === target.id && finding.status === 'open'); }
  protected targetHost(id: string): string { return this.targets().find((target) => target.id === id)?.hostname || 'Unknown target'; }
  protected provider(target: Target): string { return this.actions().some((action) => action.target === target.id && action.summary.toLowerCase().includes('cloudflare')) ? 'Cloudflare' : 'Public edge'; }
  protected serviceCount(target: Target): number {
    const action = [...this.actions()].reverse().find((item) => item.target === target.id && item.tool === 'discover_service_hosts');
    try { return JSON.parse(action?.summary || '{}')['serviceHosts']?.length ?? Math.max(0, target.assetCount - 1); } catch { return Math.max(0, target.assetCount - 1); }
  }
  protected targetState(target: Target): string { const severities = this.findingsFor(target).map((finding) => finding.severity); return severities.some((item) => item === 'critical' || item === 'high') ? 'risk' : severities.some((item) => item === 'medium' || item === 'low') ? 'warning' : 'healthy'; }
  protected topSignal(target: Target): string { const finding = this.findingsFor(target).sort((a, b) => ['info','low','medium','high','critical'].indexOf(b.severity) - ['info','low','medium','high','critical'].indexOf(a.severity))[0]; return finding?.title || (this.serviceCount(target) ? 'Public responses verified' : 'Awaiting service discovery'); }
  protected postureLabel(score: number): string { return score >= 90 ? 'Strong' : score >= 70 ? 'Review recommended' : 'Attention required'; }
  protected compact(value: string): string { try { const parsed = JSON.parse(value); return String(parsed.title || parsed.hostname || parsed.status || parsed.passiveSource || value).slice(0, 120); } catch { return value.replace(/\s+/g, ' ').slice(0, 120); } }
}
