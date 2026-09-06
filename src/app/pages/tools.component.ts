import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { GeneratedProbeAssertion, GeneratedTool, GeneratedToolExecution, ScanMode } from '../models';
import { SCAN_PROFILES } from '../scan-profiles';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-tools',
  imports: [AppSidebarComponent, DatePipe, FormsModule, RouterLink],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main tools-page">
      <header class="app-header"><div><span class="app-breadcrumb">MANAGE / CAPABILITY REGISTRY</span><h1>Agent tools</h1><p>Review capabilities composed from scan evidence and decide where they may run automatically.</p></div><span class="scope-lock"><i></i>Compiled plans · no generated code</span></header>
      @if (error()) { <div class="error-banner"><strong>Tool registry unavailable</strong><span>{{ error() }}</span></div> }

      <section class="capability-promotion panel" aria-label="Generated tool promotion path">
        <div class="promotion-thesis"><span class="section-index">CAPABILITY PROMOTION</span><h2>The model may design the probe. Policy decides its reach.</h2><p>Every proposal is evidence-linked, schema-validated and checksum-bound. Unbounded can exercise a new plan; broader reuse begins only after review.</p></div>
        <div class="promotion-track">
          <div class="promotion-node"><i>AI</i><span><strong>Proposed</strong><small>{{ proposedCount() }} waiting</small></span></div><b></b>
          <div class="promotion-node hot"><i>U</i><span><strong>Unbounded lab</strong><small>{{ autoCount() }} auto-eligible</small></span></div><b></b>
          <div class="promotion-gate"><span></span><strong>ADMIN GATE</strong></div><b></b>
          <div class="promotion-node trusted"><i>✓</i><span><strong>Profile fleet</strong><small>{{ approvedCount() }} approved</small></span></div>
        </div>
      </section>

      <section class="tool-metrics">
        <article><span>Registry</span><strong>{{ tools().length }}</strong><small>Immutable capability receipts</small></article>
        <article><span>Awaiting review</span><strong>{{ proposedCount() }}</strong><small>Unbounded remains isolated</small></article>
        <article><span>Executed</span><strong>{{ executions().length }}</strong><small>{{ requestTotal() }} bounded requests retained</small></article>
        <article><span>Active profiles</span><strong>{{ profileSpread() }}</strong><small>Lowest approved contract</small></article>
      </section>

      <section class="tool-filter panel"><label><span>Search capabilities</span><input [ngModel]="query()" (ngModelChange)="query.set($event)" placeholder="Name, category, evidence…"></label><label><span>Status</span><select [ngModel]="statusFilter()" (ngModelChange)="statusFilter.set($event)"><option value="all">All states</option><option value="proposed">Proposed</option><option value="approved">Approved</option><option value="disabled">Disabled</option><option value="rejected">Rejected</option></select></label><span>{{ filtered().length }} shown</span></section>

      <section class="tool-console">
        <div class="panel tool-register">
          <div class="tool-register-head"><span>Capability</span><span>Contract</span><span>Use</span></div>
          @for (tool of filtered(); track tool.id) {
            <button type="button" class="tool-row" [class.selected]="selectedId() === tool.id || (!selectedId() && $first)" [attr.data-status]="tool.status" (click)="select(tool)">
              <span class="tool-risk" [attr.data-risk]="tool.riskLevel">{{ riskCode(tool) }}</span>
              <span><small>{{ tool.category }} · {{ tool.name }}</small><strong>{{ tool.title }}</strong><em>{{ tool.summary }}</em></span>
              <span><strong>{{ profileName(tool.minProfile) }}</strong><small>{{ tool.requestCeiling }} request ceiling</small></span>
              <span><strong>{{ executionCount(tool) }}</strong><small>runs</small></span>
            </button>
          } @empty { <div class="empty-state"><strong>No generated tools match this view.</strong><span>An Unbounded investigation can propose one when installed capabilities leave an evidence-backed question unanswered.</span></div> }
        </div>

        <aside class="panel tool-inspector">
          @if (active(); as tool) {
            <header><div><span class="tool-state" [attr.data-status]="tool.status">{{ tool.status }}</span><span class="tool-checksum">SHA-256 {{ tool.checksum.slice(0, 12) }}</span></div><h2>{{ tool.title }}</h2><p>{{ tool.rationale }}</p></header>
            <div class="tool-boundary"><strong>Capability boundary</strong><span>{{ tool.riskLevel }} · {{ tool.requestCeiling }} same-origin requests · {{ tool.schemaVersion }}</span><small>No source code, shell, arbitrary headers, ambient credentials or cross-origin access.</small></div>

            <h3>Why the agent proposed it</h3><ul class="evidence-list">@for (evidence of tool.evidence; track evidence) { <li>{{ evidence }}</li> }</ul>

            <h3>Compiled request plan</h3><div class="probe-plan">@for (step of tool.spec.steps; track step.id) { <article><div><span [attr.data-method]="step.method">{{ step.method }}</span><code>{{ step.path }}</code></div><p>{{ step.purpose }}</p><ul>@for (assertion of step.assertions; track $index) { <li>{{ assertionLabel(assertion) }}</li> }</ul></article> }</div>

            <h3>Deployment policy</h3><div class="tool-policy"><label><span>Automatic from profile</span><select [ngModel]="draftProfile()" (ngModelChange)="draftProfile.set($event)">@for (profile of profiles; track profile.id) { <option [value]="profile.id" [disabled]="!tool.compatibleProfiles.includes(profile.id)">{{ profile.name }}{{ !tool.compatibleProfiles.includes(profile.id) ? ' · incompatible' : '' }}</option> }</select></label><label class="policy-toggle"><input type="checkbox" [ngModel]="draftAutoUse()" (ngModelChange)="draftAutoUse.set($event)"><span><strong>Allow before review in Unbounded</strong><small>The schema-valid plan remains isolated to administrator-selected non-production runs.</small></span></label><label><span>Review note</span><textarea rows="3" maxlength="1200" [ngModel]="draftNote()" (ngModelChange)="draftNote.set($event)" placeholder="Reason for approval, rejection or profile choice"></textarea></label></div>
            <div class="tool-review-actions">@if (tool.status !== 'approved') { <button class="button primary" type="button" [disabled]="saving()" (click)="review('approved')">Approve &amp; assign</button> } @else { <button class="button primary" type="button" [disabled]="saving()" (click)="review('approved')">Save policy</button> } @if (tool.status !== 'rejected') { <button class="button ghost" type="button" [disabled]="saving()" (click)="review('rejected')">Reject</button> } @if (tool.status === 'approved') { <button class="button ghost risk-action" type="button" [disabled]="saving()" (click)="review('disabled')">Disable</button> }</div>

            <h3>Execution receipts</h3><div class="tool-executions">@for (execution of executionsFor(tool); track execution.id) { <article><span [attr.data-status]="execution.status"></span><div><strong>{{ execution.hostname }}</strong><small>{{ profileName(execution.profile) }} · {{ execution.occurredAt | date:'MMM d, HH:mm' }}</small></div><p>{{ execution.summary }}</p></article> } @empty { <div class="empty-state">This capability has not run yet.</div> }</div>
            @if (tool.sourceScan) { <a class="tool-trace-link" [routerLink]="['/app/traces']" [queryParams]="{ scan: tool.sourceScan }">Open proposal trace →</a> }
          } @else { <div class="empty-state"><strong>Select a generated capability.</strong><span>The complete request plan and its evidence will appear here.</span></div> }
        </aside>
      </section>
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class ToolsComponent implements OnInit {
  private readonly db = inject(PocketBaseService);
  protected readonly profiles = SCAN_PROFILES;
  protected readonly tools = signal<GeneratedTool[]>([]);
  protected readonly executions = signal<GeneratedToolExecution[]>([]);
  protected readonly selectedId = signal('');
  protected readonly query = signal('');
  protected readonly statusFilter = signal('all');
  protected readonly draftProfile = signal<ScanMode>('unbounded');
  protected readonly draftAutoUse = signal(true);
  protected readonly draftNote = signal('');
  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly filtered = computed(() => {
    const query = this.query().trim().toLowerCase();
    return this.tools().filter((tool) => (this.statusFilter() === 'all' || tool.status === this.statusFilter()) && (!query || [tool.name, tool.title, tool.summary, tool.category, ...tool.evidence].join(' ').toLowerCase().includes(query)));
  });
  protected readonly active = computed(() => this.filtered().find((tool) => tool.id === this.selectedId()) || this.filtered()[0] || null);
  protected readonly proposedCount = computed(() => this.tools().filter((tool) => tool.status === 'proposed').length);
  protected readonly approvedCount = computed(() => this.tools().filter((tool) => tool.status === 'approved').length);
  protected readonly autoCount = computed(() => this.tools().filter((tool) => tool.status === 'proposed' && tool.unboundedAutoUse).length);
  protected readonly requestTotal = computed(() => this.executions().reduce((sum, item) => sum + item.requestCount, 0));
  protected readonly profileSpread = computed(() => new Set(this.tools().filter((tool) => tool.status === 'approved').map((tool) => tool.minProfile)).size);

  ngOnInit(): void { void this.load(); }
  protected select(tool: GeneratedTool): void { this.selectedId.set(tool.id); this.draftProfile.set(tool.minProfile); this.draftAutoUse.set(tool.unboundedAutoUse); this.draftNote.set(tool.reviewNote); }
  protected profileName(id: ScanMode): string { return this.profiles.find((profile) => profile.id === id)?.name || id; }
  protected riskCode(tool: GeneratedTool): string { return tool.riskLevel === 'interactive' ? 'INT' : tool.riskLevel === 'low' ? 'LOW' : 'GET'; }
  protected executionCount(tool: GeneratedTool): number { return this.executions().filter((item) => item.tool === tool.id).length; }
  protected executionsFor(tool: GeneratedTool): GeneratedToolExecution[] { return this.executions().filter((item) => item.tool === tool.id).slice(0, 8); }
  protected assertionLabel(assertion: GeneratedProbeAssertion): string {
    if (assertion.type === 'status-in') return `Status is one of ${assertion.values?.join(', ')}`;
    if (assertion.type === 'header-present') return `Header ${assertion.name} is present`;
    if (assertion.type === 'header-contains') return `Header ${assertion.name} contains the proposed marker`;
    if (assertion.type === 'body-contains') return 'Body contains the proposed marker';
    return `JSON key ${assertion.path} exists`;
  }
  protected async review(status: GeneratedTool['status']): Promise<void> {
    const tool = this.active(); if (!tool) return;
    this.saving.set(true); this.error.set('');
    try {
      await this.db.reviewGeneratedTool(tool, { status, minProfile: this.draftProfile(), unboundedAutoUse: this.draftAutoUse(), reviewNote: this.draftNote() });
      this.tools.update((items) => items.map((item) => item.id === tool.id ? { ...item, status, minProfile: this.draftProfile(), unboundedAutoUse: this.draftAutoUse(), reviewNote: this.draftNote() } : item));
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not update the capability policy.'); }
    finally { this.saving.set(false); }
  }
  private async load(): Promise<void> {
    try {
      const [tools, executions] = await Promise.all([this.db.generatedTools(), this.db.generatedToolExecutions()]);
      this.tools.set(tools); this.executions.set(executions); if (tools[0]) this.select(tools[0]);
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not load generated tools.'); }
  }
}
