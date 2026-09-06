import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { AgentActionRecord, Finding, FindingLifecycle, Scan, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';
import { buildKnowledgePatterns, findingLifecycle, latestCompletedScans } from '../services/posture-intelligence';

@Component({
  selector: 'wg-dashboard',
  imports: [AppSidebarComponent, DatePipe, RouterLink],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main posture-workspace">
      <header class="app-header posture-header">
        <div><span class="app-breadcrumb">POSTURE / CURRENT</span><h1>External posture</h1><p>Your latest retained view of public infrastructure, separated from investigation history.</p></div>
        <div class="header-actions"><span class="as-of-chip"><i></i>As of {{ latestAsOf() | date:'MMM d, HH:mm' }}</span><a class="button primary compact" [routerLink]="pocketbase.isAdmin() ? '/app/admin' : '/app/targets'">{{ pocketbase.isAdmin() ? 'Manage observations' : 'Open targets' }} <span>→</span></a></div>
      </header>
      @if (error()) { <div class="error-banner"><strong>Posture unavailable</strong><span>{{ error() }}</span></div> }
      @if (targets().length) {
        <section class="posture-rail" aria-label="Finding observation status">
          <div class="rail-intro"><span>Observation status</span><strong>What changed since prior evidence</strong><small>Absence is shown as “not observed,” never assumed fixed.</small></div>
          <a routerLink="/app/findings" [queryParams]="{state:'new'}" data-state="new"><span>New</span><strong>{{ newFindings().length }}</strong><small>First seen now</small></a>
          <a routerLink="/app/findings" [queryParams]="{state:'persistent'}" data-state="persistent"><span>Persistent</span><strong>{{ persistentFindings().length }}</strong><small>Seen again</small></a>
          <a routerLink="/app/findings" [queryParams]="{state:'not_observed'}" data-state="not_observed"><span>Not observed now</span><strong>{{ notObservedFindings().length }}</strong><small>Needs confirmation</small></a>
          <a routerLink="/app/findings" [queryParams]="{state:'resolved'}" data-state="resolved"><span>Resolved</span><strong>{{ resolvedFindings().length }}</strong><small>Owner confirmed</small></a>
        </section>

        <section class="posture-overview">
          <article class="panel posture-scorecard"><div class="score-ring" [style.--score]="portfolioPosture()"><strong>{{ portfolioPosture() }}</strong><span>/100</span></div><div><span class="section-index">PORTFOLIO POSTURE</span><h2>{{ postureLabel(portfolioPosture()) }}</h2><p>Calculated from findings in the latest completed observation for each authorized target.</p></div></article>
          <article class="panel posture-stat"><span>Current issues</span><strong>{{ currentFindings().length }}</strong><small>{{ urgentCount() }} high or critical</small></article>
          <article class="panel posture-stat"><span>Observed assets</span><strong>{{ assetCount() }}</strong><small>Across {{ targets().length }} authorized root{{ targets().length === 1 ? '' : 's' }}</small></article>
          <article class="panel posture-stat"><span>Recurring patterns</span><strong>{{ recurringPatterns().length }}</strong><small>Evidence seen more than once</small></article>
        </section>

        <section class="panel estate-panel corporate-estate">
          <div class="panel-heading"><div><span class="section-index">CURRENT EXTERNAL ESTATE</span><h2>Portfolio surface</h2></div><div class="panel-actions"><span class="evidence-count">Latest completed observation per target</span><a routerLink="/app/surface">Open topology →</a></div></div>
          <div class="estate-ledger">
            <div class="estate-ledger-head"><span>Authorized target</span><span>Observed route</span><span>Current posture</span><span>Change</span><span></span></div>
            @for (target of targets(); track target.id) {
              <article class="estate-ledger-row">
                <a [routerLink]="['/app/targets', target.id]" class="estate-identity"><i>{{ target.hostname.slice(0, 1).toUpperCase() }}</i><span><strong>{{ target.hostname }}</strong><small>{{ target.name }}</small></span></a>
                <span class="estate-route"><i></i><strong>{{ provider(target) }}</strong><small>{{ serviceCount(target) }} public application{{ serviceCount(target) === 1 ? '' : 's' }}</small></span>
                <span class="estate-current" [attr.data-state]="targetState(target)"><strong>{{ target.posture }}</strong><small>{{ findingsFor(target).length }} current issue{{ findingsFor(target).length === 1 ? '' : 's' }}</small></span>
                <span class="estate-change"><b>{{ newFor(target).length }} new</b><small>{{ persistentFor(target).length }} persistent</small></span>
                <a class="row-arrow" routerLink="/app/surface" [queryParams]="{target: target.id}" aria-label="Open target topology">→</a>
              </article>
            }
          </div>
        </section>

        <section class="posture-lower">
          <article class="panel priority-panel"><div class="panel-heading"><div><span class="section-index">CURRENT PRIORITY</span><h2>Issues that need a decision</h2></div><a routerLink="/app/findings">Open issue register →</a></div>
            <div class="priority-list">@for (finding of currentFindings().slice(0, 6); track finding.id) { <a routerLink="/app/findings" [queryParams]="{target:finding.target}" class="priority-row"><span class="severity-mark" [attr.data-severity]="finding.severity"></span><div><span class="lifecycle-tag" [attr.data-state]="lifecycle(finding)">{{ lifecycleLabel(finding) }}</span><strong>{{ finding.title }}</strong><small>{{ targetHost(finding.target) }} · {{ finding.asset }}</small></div><span class="confidence-value">{{ finding.confidence }}%</span><b>→</b></a> } @empty { <div class="empty-state"><strong>No current actionable findings.</strong><span>Review “not observed” items before treating them as fixed.</span></div> }</div>
          </article>
          <article class="panel knowledge-preview"><div class="panel-heading"><div><span class="section-index">EVIDENCE KNOWLEDGE</span><h2>Patterns worth preventing</h2></div><a routerLink="/app/knowledge">Explore knowledge →</a></div>
            <div class="knowledge-preview-list">@for (pattern of recurringPatterns().slice(0, 4); track pattern.key) { <a routerLink="/app/knowledge"><span>{{ pattern.category }}</span><strong>{{ pattern.title }}</strong><small>{{ pattern.technology }} · {{ pattern.occurrences }} observations · {{ pattern.affectedTargetIds.length }} target{{ pattern.affectedTargetIds.length === 1 ? '' : 's' }}</small></a> } @empty { <div class="empty-state"><strong>Knowledge starts with repeat evidence.</strong><span>Patterns will appear as observations accumulate.</span></div> }</div>
            <footer><span>Deterministic grouping</span><small>No additional AI call is required</small></footer>
          </article>
        </section>
      } @else if (!error()) { <div class="empty-state panel"><strong>No authorized targets.</strong><span>Open Administration to approve a domain when you are ready.</span><a class="button primary compact" routerLink="/app/admin">Add target →</a></div> }
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class DashboardComponent implements OnInit {
  protected readonly pocketbase = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]);
  protected readonly findings = signal<Finding[]>([]);
  protected readonly actions = signal<AgentActionRecord[]>([]);
  protected readonly scans = signal<Scan[]>([]);
  protected readonly error = signal('');
  private readonly latestScans = computed(() => latestCompletedScans(this.scans()));
  protected readonly newFindings = computed(() => this.findings().filter((finding) => this.lifecycle(finding) === 'new' && finding.severity !== 'info'));
  protected readonly persistentFindings = computed(() => this.findings().filter((finding) => this.lifecycle(finding) === 'persistent' && finding.severity !== 'info'));
  protected readonly notObservedFindings = computed(() => this.findings().filter((finding) => this.lifecycle(finding) === 'not_observed' && finding.severity !== 'info'));
  protected readonly resolvedFindings = computed(() => this.findings().filter((finding) => this.lifecycle(finding) === 'resolved' && finding.severity !== 'info'));
  protected readonly currentFindings = computed(() => [...this.newFindings(), ...this.persistentFindings()].filter((finding) => finding.status !== 'resolved').sort((a, b) => this.severityRank(b.severity) - this.severityRank(a.severity)));
  protected readonly urgentCount = computed(() => this.currentFindings().filter((finding) => finding.severity === 'critical' || finding.severity === 'high').length);
  protected readonly assetCount = computed(() => this.targets().reduce((sum, target) => sum + Math.max(1, target.assetCount), 0));
  protected readonly portfolioPosture = computed(() => Math.round(this.targets().reduce((sum, target) => sum + target.posture, 0) / Math.max(1, this.targets().length)));
  protected readonly latestAsOf = computed(() => [...this.targets()].sort((a, b) => Date.parse(b.lastScanAt || '0') - Date.parse(a.lastScanAt || '0'))[0]?.lastScanAt || '');
  protected readonly patterns = computed(() => buildKnowledgePatterns(this.findings(), this.scans()));
  protected readonly recurringPatterns = computed(() => this.patterns().filter((pattern) => pattern.occurrences > 1));

  ngOnInit(): void { void this.load(); }
  private async load(): Promise<void> {
    try {
      const [targets, findings, actions, scans] = await Promise.all([this.pocketbase.targets(), this.pocketbase.findings(), this.pocketbase.agentActions(), this.pocketbase.scans()]);
      this.targets.set(targets); this.findings.set(findings); this.actions.set(actions); this.scans.set(scans);
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not load workspace data.'); }
  }
  protected lifecycle(finding: Finding): FindingLifecycle { return findingLifecycle(finding, this.latestScans().get(finding.target)?.id); }
  protected lifecycleLabel(finding: Finding): string { return ({ new: 'New', persistent: 'Persistent', not_observed: 'Not observed now', resolved: 'Resolved' } as Record<FindingLifecycle, string>)[this.lifecycle(finding)]; }
  protected findingsFor(target: Target): Finding[] { return this.currentFindings().filter((finding) => finding.target === target.id); }
  protected newFor(target: Target): Finding[] { return this.newFindings().filter((finding) => finding.target === target.id); }
  protected persistentFor(target: Target): Finding[] { return this.persistentFindings().filter((finding) => finding.target === target.id); }
  protected targetHost(id: string): string { return this.targets().find((target) => target.id === id)?.hostname || 'Unknown target'; }
  protected provider(target: Target): string { return this.actions().some((action) => action.target === target.id && action.summary.toLowerCase().includes('cloudflare')) ? 'Cloudflare edge' : 'Direct public route'; }
  protected serviceCount(target: Target): number {
    const action = [...this.actions()].reverse().find((item) => item.target === target.id && item.tool === 'discover_service_hosts');
    try { const result = JSON.parse(action?.summary || '{}'); return (result['serviceHosts']?.length || 0) + (result['root'] ? 1 : 0); } catch { return Math.max(0, target.assetCount - 1); }
  }
  protected targetState(target: Target): string { const severities = this.findingsFor(target).map((finding) => finding.severity); return severities.some((item) => item === 'critical' || item === 'high') ? 'risk' : severities.some((item) => item === 'medium' || item === 'low') ? 'warning' : 'healthy'; }
  protected postureLabel(score: number): string { return score >= 90 ? 'Strong posture' : score >= 70 ? 'Review recommended' : 'Attention required'; }
  private severityRank(value: string): number { return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 } as Record<string, number>)[value] || 0; }
}
