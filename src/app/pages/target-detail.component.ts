import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Finding, Target, TlsObservation } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-target-detail',
  imports: [AppSidebarComponent, DatePipe, RouterLink],
  template: `
    <div class="app-layout">
      <wg-app-sidebar />
      <main class="app-main target-main">
        <header class="app-header target-header">
          <div><a class="app-breadcrumb" routerLink="/app">Workspace / Targets /</a><h1>{{ target()?.hostname || 'Loading target…' }}</h1><p>{{ target()?.name }}</p></div>
          <div class="header-actions"><span class="authorization-badge"><i></i> Admin authorized</span><button class="button button-primary scan-button" (click)="scan()" [disabled]="scanState() === 'requesting'">{{ scanLabel() }} <span>◎</span></button></div>
        </header>

        <nav class="target-tabs" aria-label="Target sections"><a class="active" href="#overview">Overview</a><a href="#findings">Findings <b>{{ findings().length }}</b></a><a href="#surface">Surface</a><a href="#history">History</a><a href="#authorization">Authorization</a></nav>

        <section class="target-status-strip">
          <div><span class="status-orb"></span><span><small>Observation status</small><strong>Continuous watch active</strong></span></div>
          <div><small>Last completed</small><strong>{{ target()?.lastScanAt | date:'MMM d, HH:mm:ss' }}</strong></div>
          <div><small>Policy</small><strong>Standard · recon only</strong></div>
          <div><small>Next observation</small><strong>in 5 hours</strong></div>
        </section>

        <section class="target-content" id="overview">
          <div class="target-primary">
            <article class="panel attention-panel">
              <div class="panel-heading"><div><span class="section-index">Posture summary</span><h2>What the observer sees</h2></div><span class="posture-pill large">{{ target()?.posture || 64 }}</span></div>
              <p class="attention-lede">The host presents a valid identity through Cloudflare, while its homepage reveals a public infrastructure management surface.</p>
              <div class="finding-list detailed" id="findings">
                @for (finding of findings(); track finding.id) {
                  <article class="finding-row">
                    <span class="severity-label" [class]="finding.severity">{{ finding.severity }}</span>
                    <div><h3>{{ finding.title }}</h3><p>{{ finding.summary }}</p><details><summary>View observed evidence</summary><ul>@for (item of finding.evidence; track item) { <li>{{ item }}</li> }</ul></details></div>
                    <div class="confidence"><span>{{ finding.confidence }}%</span><small>confidence</small></div>
                  </article>
                }
              </div>
            </article>

            <article class="panel surface-panel" id="surface">
              <div class="panel-heading"><div><span class="section-index">Reachable surface</span><h2>Observed services</h2></div><span class="panel-note">2 responding</span></div>
              <div class="service-map">
                <div class="service-row"><span class="port-number">443</span><span class="service-protocol">HTTPS</span><span><strong>Cloudflare edge</strong><small>HTTP/2 · application surface</small></span><span class="service-health review">review</span></div>
                <div class="service-row"><span class="port-number">80</span><span class="service-protocol">HTTP</span><span><strong>Redirect service</strong><small>Permanent move to HTTPS</small></span><span class="service-health healthy">expected</span></div>
              </div>
            </article>
          </div>

          <aside class="target-aside">
            <article class="panel tls-panel">
              <div class="tls-hero"><div class="certificate-seal">✓</div><span><small>TLS identity</small><strong>{{ tls()?.valid ? 'Valid & trusted' : 'Needs attention' }}</strong></span></div>
              <div class="tls-days"><strong>{{ tls()?.daysRemaining || '—' }}</strong><span>days<br>remaining</span></div>
              <dl>
                <div><dt>Issuer</dt><dd>{{ tls()?.issuer }}</dd></div>
                <div><dt>Valid until</dt><dd>{{ tls()?.validTo | date:'MMM d, y' }}</dd></div>
                <div><dt>Protocol</dt><dd>{{ tls()?.protocol }}</dd></div>
                <div><dt>Coverage</dt><dd>{{ tls()?.subjectAltNames?.length || 0 }} names</dd></div>
              </dl>
              <div class="tls-timeline"><span style="--progress: 62%"></span></div>
              <p>Renewal should be observed before <strong>{{ tls()?.validTo | date:'MMM d' }}</strong>.</p>
            </article>

            <article class="panel reasoning-panel">
              <div class="panel-heading"><div><span class="section-index">Latest trace</span><h2>Agent reasoning</h2></div><span class="live-label muted">complete</span></div>
              <ol>
                <li class="done"><span></span><p><strong>Resolved public edge</strong>Cloudflare addresses returned for the root host.</p></li>
                <li class="done"><span></span><p><strong>Inspected application identity</strong>HTML title and static assets identify Easypanel.</p></li>
                <li class="done"><span></span><p><strong>Validated certificate</strong>Chain and hostname checks succeeded.</p></li>
                <li class="finding"><span></span><p><strong>Recorded exposure</strong>Public control surface marked for owner review.</p></li>
              </ol>
            </article>
          </aside>
        </section>
      </main>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class TargetDetailComponent implements OnInit {
  private readonly pocketbase = inject(PocketBaseService);
  private readonly route = inject(ActivatedRoute);
  protected readonly target = signal<Target | null>(null);
  protected readonly findings = signal<Finding[]>([]);
  protected readonly tls = signal<TlsObservation | null>(null);
  protected readonly scanState = signal<'idle' | 'requesting' | 'queued'>('idle');
  protected readonly scanLabel = () => ({ idle: 'Observe now', requesting: 'Requesting…', queued: 'Observation queued' })[this.scanState()];

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id') ?? '';
    void Promise.all([this.pocketbase.targets(), this.pocketbase.findings(id), this.pocketbase.tls(id)]).then(([targets, findings, tls]) => {
      this.target.set(targets.find((item) => item.id === id) ?? targets[0] ?? null);
      this.findings.set(findings); this.tls.set(tls);
    });
  }

  protected async scan(): Promise<void> {
    const target = this.target();
    if (!target) return;
    this.scanState.set('requesting');
    try { await this.pocketbase.requestScan(target.id); this.scanState.set('queued'); }
    catch { this.scanState.set('idle'); }
  }
}
