import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({ selector: 'wg-targets', imports: [AppSidebarComponent, RouterLink, DatePipe], template: `
  <div class="app-layout"><wg-app-sidebar /><main class="app-main"><header class="app-header"><div><span class="app-breadcrumb">OBSERVE / TARGETS</span><h1>Authorized targets</h1><p>Every investigation is anchored to a verified or administrator-approved root.</p></div><div class="header-actions"><span class="scope-lock">⌾ Scope enforcement active</span><a class="button primary compact" routerLink="/app/admin">Add or scan target →</a></div></header>
  @if (error()) { <div class="error-banner"><strong>Targets unavailable</strong><span>{{ error() }}</span></div> }
  <section class="panel inventory-panel"><div class="panel-heading"><div><span class="section-index">INVENTORY</span><h2>{{ targets().length }} monitored root{{ targets().length === 1 ? '' : 's' }}</h2></div><span class="evidence-count">Administrator approved</span></div>
    <div class="data-table target-inventory"><div class="table-head"><span>Target</span><span>Authorization</span><span>Posture</span><span>Open findings</span><span>Last observed</span><span></span></div>
    @for (target of targets(); track target.id) { <a class="table-row" [routerLink]="['/app/targets', target.id]"><span class="target-cell"><i>{{ target.hostname[0].toUpperCase() }}</i><span><strong>{{ target.hostname }}</strong><small>{{ target.name }}</small></span></span><span><b class="state-pill" data-state="healthy">{{ authLabel(target) }}</b></span><span><b class="posture-number">{{ target.posture }}</b>/100</span><span><b>{{ target.findingCount }}</b></span><span><strong>{{ target.lastScanAt | date:'MMM d, y' }}</strong><small>{{ target.lastScanAt | date:'HH:mm:ss' }}</small></span><span>→</span></a> }
    @empty { <div class="empty-state"><strong>No authorized targets.</strong><span>Open Administration to approve a root and queue its first scan.</span><a class="button primary compact" routerLink="/app/admin">Add target →</a></div> }</div>
  </section>
  <section class="callout-panel"><div><span>BOUNDARY</span><h2>Authorization is checked before every network action.</h2></div><p>The observer resolves every requested host back to the approved root and blocks private or loopback destinations by default.</p></section>
  </main></div>`, changeDetection: ChangeDetectionStrategy.OnPush })
export class TargetsComponent implements OnInit {
  private readonly db = inject(PocketBaseService); protected readonly targets = signal<Target[]>([]); protected readonly error = signal('');
  ngOnInit(): void { void this.db.targets().then((v) => this.targets.set(v)).catch((e) => this.error.set(e instanceof Error ? e.message : 'Could not load targets.')); }
  protected authLabel(target: Target): string { return target.authorizationStatus === 'admin_override' ? 'Admin approved' : target.authorizationStatus === 'verified' ? 'Verified' : 'Pending'; }
}
