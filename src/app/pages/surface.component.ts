import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { InfrastructureGraphComponent } from '../components/infrastructure-graph.component';
import { AgentActionRecord, CertificateTransparencyRecord, Finding, Target, TlsObservation } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({ selector: 'wg-surface', imports: [AppSidebarComponent, InfrastructureGraphComponent, FormsModule, RouterLink, DatePipe], template: `
  <div class="app-layout"><wg-app-sidebar /><main class="app-main surface-page"><header class="app-header"><div><span class="app-breadcrumb">OBSERVE / SURFACE MAP</span><h1>Infrastructure topology</h1><p>An evidence-bound model of how your authorized public edge appears from outside.</p></div><label class="target-select"><span>Target</span><select [ngModel]="selectedId()" (ngModelChange)="selectTarget($event)">@for (target of targets(); track target.id) { <option [value]="target.id">{{ target.hostname }}</option> }</select></label></header>
  @if (error()) { <div class="error-banner"><strong>Surface unavailable</strong><span>{{ error() }}</span></div> }
  @if (target(); as item) {
    <section class="panel topology-panel expanded"><div class="panel-heading"><div><span class="section-index">INTERACTIVE ASSET MAP</span><h2>{{ item.hostname }}</h2></div><div class="panel-actions"><span class="evidence-count">Drag to pan · wheel to zoom · click for provenance</span><a [routerLink]="['/app/targets', item.id]">Target detail →</a></div></div><wg-infrastructure-graph [target]="item" [findings]="findings()" [tls]="tls()" [actions]="actions()" /></section>
    @if (certificateInventory(); as inventory) {
      <section class="panel certificate-inventory"><div class="panel-heading"><div><span class="section-index">PUBLIC CERTIFICATE HISTORY</span><h2>{{ inventory.total }} certificate-transparency records</h2></div><span class="evidence-count">Source · {{ inventory.source }}</span></div>
        @if (inventory.certificates.length) { <div class="certificate-table"><div class="certificate-head"><span>Common name / names</span><span>Issuer</span><span>Validity</span><span>Record</span></div>@for (certificate of inventory.certificates; track $index) { <details class="certificate-row"><summary><span><strong>{{ certificate.commonName || certificate.names[0] || 'Unnamed certificate' }}</strong><small>{{ certificate.names.length }} DNS name{{ certificate.names.length === 1 ? '' : 's' }}</small></span><span>{{ issuer(certificate.issuerName) }}</span><span><strong>{{ certificate.notAfter | date:'mediumDate' }}</strong><small>{{ certificate.notBefore | date:'mediumDate' }} → {{ certificate.notAfter | date:'mediumDate' }}</small></span><b>Evidence ↓</b></summary><div><dl><div><dt>All certificate names</dt><dd>{{ certificate.names.join(', ') || 'Not retained' }}</dd></div><div><dt>Full issuer</dt><dd>{{ certificate.issuerName || 'Not retained' }}</dd></div><div><dt>Issuer CA identifier</dt><dd>{{ certificate.issuerCaId ?? 'Not returned' }}</dd></div><div><dt>Serial number</dt><dd>{{ certificate.serialNumber || 'Not retained' }}</dd></div><div><dt>Matching entries</dt><dd>{{ certificate.resultCount || 1 }}</dd></div></dl><p><span>EVIDENCE</span>Public certificate-transparency record {{ certificate.id }} returned by {{ inventory.source }}.</p></div></details> }</div> }
        @else { <div class="empty-state"><strong>This older scan retained the count, but not individual records.</strong><span>Run a new investigation to retain and display each certificate record and its names, issuer, validity, serial, and log timestamp.</span></div> }
      </section>
    }
    <div class="map-notice"><span>ABOUT INFERENCE</span><p>Dashed or unknown details are deliberate. When a CDN conceals the origin, Wellguard will not present edge geolocation or open edge ports as facts about your server.</p></div>
  }
  </main></div>`, changeDetection: ChangeDetectionStrategy.OnPush })
export class SurfaceComponent implements OnInit {
  private readonly db = inject(PocketBaseService); private readonly route = inject(ActivatedRoute); protected readonly targets = signal<Target[]>([]); protected readonly selectedId = signal(''); protected readonly findings = signal<Finding[]>([]); protected readonly tls = signal<TlsObservation | null>(null); protected readonly actions = signal<AgentActionRecord[]>([]); protected readonly error = signal(''); protected readonly target = computed(() => this.targets().find((x) => x.id === this.selectedId()) || null);
  protected readonly certificateInventory = computed(() => {
    const action = this.actions().filter((item) => item.tool === 'inspect_certificate_transparency').at(-1);
    if (!action) return null;
    try {
      const data = JSON.parse(action.summary) as { source?: string; certificateCount?: number; certificates?: CertificateTransparencyRecord[] };
      return { source: data.source || 'certificate transparency', total: Number(data.certificateCount || data.certificates?.length || 0), certificates: data.certificates || [] };
    } catch { return null; }
  });
  ngOnInit(): void { void this.db.targets().then((items) => { this.targets.set(items); const requested = this.route.snapshot.queryParamMap.get('target'); this.selectedId.set(items.some((item) => item.id === requested) ? requested! : items[0]?.id || ''); return this.loadEvidence(); }).catch((e) => this.error.set(e instanceof Error ? e.message : 'Could not load surface.')); }
  protected selectTarget(id: string): void { this.selectedId.set(id); void this.loadEvidence(); }
  protected async loadEvidence(): Promise<void> { const id = this.selectedId(); if (!id) return; try { const [findings, tls, actions] = await Promise.all([this.db.findings(id), this.db.tls(id), this.db.agentActions({ targetId: id })]); this.findings.set(findings); this.tls.set(tls); this.actions.set(actions); } catch (e) { this.error.set(e instanceof Error ? e.message : 'Could not load evidence.'); } }
  protected issuer(value: string): string { return value.match(/(?:^|,)\s*O=([^,]+)/)?.[1] || value.match(/(?:^|,)\s*CN=([^,]+)/)?.[1] || value || 'Unknown issuer'; }
}
