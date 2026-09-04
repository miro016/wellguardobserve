import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { InfrastructureGraphComponent } from '../components/infrastructure-graph.component';
import { AgentActionRecord, Finding, Target, TlsObservation } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({ selector: 'wg-surface', imports: [AppSidebarComponent, InfrastructureGraphComponent, FormsModule, RouterLink], template: `
  <div class="app-layout"><wg-app-sidebar /><main class="app-main surface-page"><header class="app-header"><div><span class="app-breadcrumb">OBSERVE / SURFACE MAP</span><h1>Infrastructure topology</h1><p>An evidence-bound model of how your authorized public edge appears from outside.</p></div>@if (targets().length > 1) { <label class="target-select"><span>Target</span><select [ngModel]="selectedId()" (ngModelChange)="selectTarget($event)">@for (target of targets(); track target.id) { <option [value]="target.id">{{ target.hostname }}</option> }</select></label> }</header>
  @if (error()) { <div class="error-banner"><strong>Surface unavailable</strong><span>{{ error() }}</span></div> }
  @if (target(); as item) { <section class="panel topology-panel expanded"><div class="panel-heading"><div><span class="section-index">INTERACTIVE ASSET MAP</span><h2>{{ item.hostname }}</h2></div><div class="panel-actions"><span class="evidence-count">Click a node for provenance</span><a [routerLink]="['/app/targets', item.id]">Target detail →</a></div></div><wg-infrastructure-graph [target]="item" [findings]="findings()" [tls]="tls()" [actions]="actions()" /></section><div class="map-notice"><span>ABOUT INFERENCE</span><p>Dashed or unknown details are deliberate. When a CDN conceals the origin, Wellguard will not present edge geolocation or open edge ports as facts about your server.</p></div> }
  </main></div>`, changeDetection: ChangeDetectionStrategy.OnPush })
export class SurfaceComponent implements OnInit {
  private readonly db = inject(PocketBaseService); protected readonly targets = signal<Target[]>([]); protected readonly selectedId = signal(''); protected readonly findings = signal<Finding[]>([]); protected readonly tls = signal<TlsObservation | null>(null); protected readonly actions = signal<AgentActionRecord[]>([]); protected readonly error = signal(''); protected readonly target = computed(() => this.targets().find((x) => x.id === this.selectedId()) || null);
  ngOnInit(): void { void this.db.targets().then((items) => { this.targets.set(items); this.selectedId.set(items[0]?.id || ''); return this.loadEvidence(); }).catch((e) => this.error.set(e instanceof Error ? e.message : 'Could not load surface.')); }
  protected selectTarget(id: string): void { this.selectedId.set(id); void this.loadEvidence(); }
  protected async loadEvidence(): Promise<void> { const id = this.selectedId(); if (!id) return; try { const [findings, tls, actions] = await Promise.all([this.db.findings(id), this.db.tls(id), this.db.agentActions({ targetId: id })]); this.findings.set(findings); this.tls.set(tls); this.actions.set(actions); } catch (e) { this.error.set(e instanceof Error ? e.message : 'Could not load evidence.'); } }
}
