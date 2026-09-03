import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Finding, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-dashboard',
  imports: [AppSidebarComponent, DatePipe, RouterLink],
  template: `
    <div class="app-layout">
      <wg-app-sidebar />
      <main class="app-main">
        <header class="app-header">
          <div><span class="app-breadcrumb">Workspace / Overview</span><h1>External posture</h1></div>
          <div class="header-actions"><span class="system-state"><i></i> Observer ready</span><button class="icon-button" aria-label="Notifications">●</button></div>
        </header>

        <section class="posture-overview">
          <div class="posture-score">
            <div class="score-ring" [style.--score]="targets()[0]?.posture || 0"><span>{{ targets()[0]?.posture || '—' }}</span><small>/ 100</small></div>
            <div><span class="section-index">Current posture</span><h2>One exposure deserves your attention.</h2><p>The public surface is stable. A management interface remains reachable from the internet.</p></div>
          </div>
          <div class="metric-column"><span>Open findings</span><strong>{{ findings().length }}</strong><small><i class="severity-dot high"></i> {{ highCount() }} high priority</small></div>
          <div class="metric-column"><span>Observed assets</span><strong>{{ targets()[0]?.assetCount || 0 }}</strong><small><i class="severity-dot healthy"></i> No new assets today</small></div>
        </section>

        <section class="dashboard-grid">
          <div class="panel target-panel">
            <div class="panel-heading"><div><span class="section-index">Authorized scope</span><h2>Targets</h2></div><button class="small-button" type="button">Add target <span>+</span></button></div>
            <div class="target-table-head"><span>Target</span><span>Posture</span><span>Surface</span><span>Last observed</span><span></span></div>
            @for (target of targets(); track target.id) {
              <a class="target-row" [routerLink]="['/app/targets', target.id]">
                <span class="target-identity"><i>{{ target.hostname.slice(0, 1).toUpperCase() }}</i><span><strong>{{ target.hostname }}</strong><small>{{ target.authorizationStatus === 'admin_override' ? 'Admin authorized' : 'Ownership verified' }}</small></span></span>
                <span><b class="posture-pill">{{ target.posture }}</b></span>
                <span><strong>{{ target.assetCount }} assets</strong><small>{{ target.findingCount }} findings</small></span>
                <span><strong>{{ target.lastScanAt | date:'MMM d, HH:mm' }}</strong><small>standard observation</small></span>
                <span class="row-arrow">→</span>
              </a>
            }
          </div>

          <div class="panel activity-panel">
            <div class="panel-heading"><div><span class="section-index">Investigator</span><h2>Recent activity</h2></div><span class="live-label">live</span></div>
            <div class="activity-stream">
              <article><i class="activity-symbol observe"></i><div><strong>Compared the public surface</strong><p>No ports changed since the previous observation.</p><time>37 seconds ago</time></div></article>
              <article><i class="activity-symbol tls">✓</i><div><strong>Validated TLS identity</strong><p>Certificate is trusted and covers the requested host.</p><time>42 seconds ago</time></div></article>
              <article><i class="activity-symbol reason">?</i><div><strong>Investigated service identity</strong><p>Correlated page metadata with public product documentation.</p><time>51 seconds ago</time></div></article>
            </div>
          </div>

          <div class="panel findings-panel">
            <div class="panel-heading"><div><span class="section-index">Evidence requiring review</span><h2>Open findings</h2></div><a href="#" class="text-link">View all <span>→</span></a></div>
            <div class="finding-list">
              @for (finding of findings(); track finding.id) {
                <article class="finding-row">
                  <span class="severity-label" [class]="finding.severity">{{ finding.severity }}</span>
                  <div><h3>{{ finding.title }}</h3><p>{{ finding.summary }}</p><span class="asset-label">{{ finding.asset }}</span></div>
                  <div class="confidence"><span>{{ finding.confidence }}%</span><small>confidence</small></div>
                </article>
              }
            </div>
          </div>
        </section>
      </main>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class DashboardComponent implements OnInit {
  private readonly pocketbase = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]);
  protected readonly findings = signal<Finding[]>([]);
  protected readonly highCount = () => this.findings().filter((finding) => finding.severity === 'critical' || finding.severity === 'high').length;

  ngOnInit(): void {
    void Promise.all([this.pocketbase.targets(), this.pocketbase.findings()]).then(([targets, findings]) => {
      this.targets.set(targets); this.findings.set(findings);
    });
  }
}
