import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ActivatedRoute } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { AssetRecord, ChangeReview, ChangeReviewStatus, Finding, Scan, SurfaceChangeState, Target, TargetCriticality } from '../models';
import { findingLifecycle, latestCompletedScans } from '../services/posture-intelligence';
import { PocketBaseService } from '../services/pocketbase.service';
import { PriorityAssessment, SurfaceChange, assessFindingPriority, diffAssets } from '../services/surface-intelligence';

interface ReviewEvent extends SurfaceChange {
  target: Target; scan: Scan; previousScan: Scan; review?: ChangeReview; finding?: Finding; priority: PriorityAssessment | null; priorityScore: number;
}

@Component({ selector: 'wg-change-review', imports: [AppSidebarComponent, FormsModule, RouterLink, DatePipe], template: `
  <div class="app-layout"><wg-app-sidebar /><main class="app-main change-review-page">
    <header class="app-header"><div><span class="app-breadcrumb">ANALYZE / CHANGE REVIEW</span><h1>Change review</h1><p>Decide whether each observed surface change is expected, requires investigation, or confirms completed work.</p></div><div class="header-actions"><label class="target-select"><span>Target</span><select [ngModel]="targetId()" (ngModelChange)="selectTarget($event)"><option value="all">All targets</option>@for (target of targets(); track target.id) { <option [value]="target.id">{{ target.hostname }}</option> }</select></label></div></header>
    @if (error()) { <div class="error-banner"><strong>Change ledger unavailable</strong><span>{{ error() }}</span></div> }
    <section class="change-command panel">
      <div><span>UNREVIEWED</span><strong>{{ unreviewedCount() }}</strong><small>owner decisions pending</small></div>
      <div><span>INVESTIGATE</span><strong>{{ investigateCount() }}</strong><small>explicitly escalated</small></div>
      <div><span>NEWLY OBSERVED</span><strong>{{ addedCount() }}</strong><small>assets added across comparisons</small></div>
      <div><span>NOT OBSERVED</span><strong>{{ absentCount() }}</strong><small>confirmation still required</small></div>
      <p><b>Decision boundary</b> “Not observed” never means resolved. It can be caused by changed coverage, routing, or temporary reachability.</p>
    </section>
    @if (selectedTarget(); as target) {
      <section class="asset-context panel"><div><span class="section-index">ENVIRONMENTAL CONTEXT</span><strong>{{ target.hostname }}</strong><small>Used by Wellguard priority; does not modify CVSS.</small></div><label><span>Business criticality</span><select [ngModel]="criticality()" (ngModelChange)="criticality.set($event)"><option value="critical">Critical</option><option value="high">High</option><option value="standard">Standard</option><option value="low">Low</option></select></label><label><span>Tags</span><input [ngModel]="tags()" (ngModelChange)="tags.set($event)" placeholder="production, identity, customer-facing"></label>@if (db.isAdmin()) { <button type="button" class="button secondary compact" [disabled]="savingContext()" (click)="saveContext()">{{ savingContext() ? 'Saving…' : 'Save context' }}</button> }</section>
    }
    <section class="filter-bar change-filters"><label><span>Search</span><input [ngModel]="query()" (ngModelChange)="query.set($event)" placeholder="Asset, host, service…"></label><label><span>Decision</span><select [ngModel]="status()" (ngModelChange)="status.set($event)"><option value="all">All decisions</option><option value="unreviewed">Unreviewed</option><option value="investigate">Investigate</option><option value="expected">Expected</option><option value="resolved">Resolved</option></select></label><label><span>Change</span><select [ngModel]="changeState()" (ngModelChange)="changeState.set($event)"><option value="all">All changes</option><option value="added">Newly observed</option><option value="changed">Changed</option><option value="not_observed">Not observed</option></select></label><div class="filter-result">{{ filtered().length }} changes</div></section>
    <section class="change-layout"><div class="panel change-register">
      @for (event of filtered(); track event.scan.id + event.key) { <button type="button" class="change-row" [class.selected]="isSelected(event)" [attr.data-change]="event.state" (click)="selectEvent(event)"><span class="change-glyph">{{ event.state === 'added' ? '+' : event.state === 'changed' ? '∆' : '–' }}</span><span><small>{{ event.target.hostname }} · {{ event.kind }}</small><strong>{{ event.label }}</strong><em>{{ changeLabel(event.state) }} · {{ event.scan.completedAt || event.scan.created | date:'MMM d, y HH:mm' }}</em></span><span class="priority-orb" [attr.data-band]="event.priority?.band || 'watch'"><b>{{ event.priorityScore }}</b><small>priority</small></span><span class="review-state" [attr.data-status]="event.review?.status || 'unreviewed'">{{ reviewLabel(event.review?.status) }}</span></button> }
      @empty { <div class="empty-state"><strong>No changes match this view.</strong><span>At least two completed observations are needed for a deterministic comparison.</span></div> }
    </div><aside class="panel change-inspector">
      @if (active(); as event) { <div class="inspector-head"><span class="lifecycle-tag" [attr.data-state]="event.state">{{ changeLabel(event.state) }}</span><span class="priority-badge" [attr.data-band]="event.priority?.band || 'watch'">{{ event.priority?.label || 'Review' }} · {{ event.priorityScore }}</span></div><h2>{{ event.label }}</h2><p>{{ event.target.hostname }} · {{ event.kind }} · compared with {{ event.previousScan.completedAt || event.previousScan.created | date:'medium' }}</p>
        <div class="change-evidence"><div><span>PREVIOUS</span><strong>{{ event.before?.subtitle || 'Not present' }}</strong><small>{{ event.before ? stateLabel(event.before.state) : 'No matching asset key in the previous snapshot.' }}</small></div><i>→</i><div><span>OBSERVED</span><strong>{{ event.after?.subtitle || 'Not observed now' }}</strong><small>{{ event.after ? stateLabel(event.after.state) : 'The prior asset key is absent from this snapshot.' }}</small></div></div>
        @if (event.changedFields.length && event.state === 'changed') { <p class="changed-fields"><b>Changed evidence fields</b>{{ event.changedFields.join(' · ') }}</p> }
        <div class="snapshot-link"><span><small>SNAPSHOT</small><strong>{{ event.scan.completedAt || event.scan.created | date:'medium' }}</strong></span><a [routerLink]="['/app/surface']" [queryParams]="{target:event.target.id, scan:event.scan.id, compare:1}">Open visual diff →</a></div>
        @if (event.priority; as priority) { <h3>Priority rationale</h3><p class="score-boundary">Wellguard priority combines observed exposure with owner context and retained threat intelligence. It is not a CVSS score.</p><div class="priority-factors">@for (factor of priority.factors; track factor.label) { <div [class.unavailable]="!factor.available"><span><strong>{{ factor.label }}</strong><small>{{ factor.evidence }}</small></span><b>{{ factor.value }}</b><em>{{ factor.points === null ? '—' : (factor.points > 0 ? '+' : '') + factor.points }}</em></div> }</div> }
        @if (db.isAdmin()) { <div class="review-decision"><label><span>Owner note</span><textarea rows="3" [ngModel]="note()" (ngModelChange)="note.set($event)" placeholder="Why is this expected, or what should be investigated?"></textarea></label><div><button type="button" class="button ghost compact" [disabled]="savingReview()" (click)="review(event, 'expected')">Expected</button><button type="button" class="button danger compact" [disabled]="savingReview()" (click)="review(event, 'investigate')">Investigate</button><button type="button" class="button secondary compact" [disabled]="savingReview()" (click)="review(event, 'resolved')">Confirmed resolved</button></div></div> }
      } @else { <div class="empty-state">Select a surface change to inspect the evidence and record a decision.</div> }
    </aside></section>
  </main></div>`, changeDetection: ChangeDetectionStrategy.OnPush })
export class ChangeReviewComponent implements OnInit {
  protected readonly db = inject(PocketBaseService);
  private readonly route = inject(ActivatedRoute);
  protected readonly targets = signal<Target[]>([]); protected readonly scans = signal<Scan[]>([]); protected readonly assets = signal<AssetRecord[]>([]); protected readonly findings = signal<Finding[]>([]); protected readonly reviews = signal<ChangeReview[]>([]);
  protected readonly targetId = signal('all'); protected readonly query = signal(''); protected readonly status = signal<ChangeReviewStatus | 'all'>('unreviewed'); protected readonly changeState = signal<SurfaceChangeState | 'all'>('all'); protected readonly selectedKey = signal(''); protected readonly error = signal('');
  protected readonly criticality = signal<TargetCriticality>('standard'); protected readonly tags = signal(''); protected readonly savingContext = signal(false); protected readonly savingReview = signal(false); protected readonly note = signal('');
  private readonly latest = computed(() => latestCompletedScans(this.scans()));
  protected readonly selectedTarget = computed(() => this.targets().find((target) => target.id === this.targetId()) || null);
  protected readonly events = computed<ReviewEvent[]>(() => {
    const reviewMap = new Map(this.reviews().map((review) => [`${review.scan}:${review.changeKey}`, review]));
    const all: ReviewEvent[] = [];
    for (const target of this.targets()) {
      const scans = this.scans().filter((scan) => scan.target === target.id && scan.status === 'completed').sort((a, b) => Date.parse(a.completedAt || a.created) - Date.parse(b.completedAt || b.created));
      for (let index = 1; index < scans.length; index++) {
        const previousScan = scans[index - 1]!; const scan = scans[index]!;
        const current = this.assets().filter((asset) => asset.scan === scan.id); const previous = this.assets().filter((asset) => asset.scan === previousScan.id);
        for (const change of diffAssets(current, previous)) {
          const finding = this.findings().find((item) => (item.assetKey === change.assetKey || item.relatedAssetKeys.includes(change.assetKey)) && (item.scan === scan.id || item.observations.some((observation) => observation.scan === scan.id)));
          const priority = finding ? assessFindingPriority(finding, target.criticality, findingLifecycle(finding, this.latest().get(target.id)?.id)) : null;
          const fallback = change.state === 'added' ? (['port', 'service', 'server'].includes(change.kind) ? 54 : 42) : change.state === 'changed' ? 46 : 24;
          all.push({ ...change, target, scan, previousScan, review: reviewMap.get(`${scan.id}:${change.key}`), finding, priority, priorityScore: priority?.score ?? fallback });
        }
      }
    }
    return all.sort((a, b) => (a.review?.status === 'unreviewed' || !a.review ? -1 : 1) - (b.review?.status === 'unreviewed' || !b.review ? -1 : 1) || b.priorityScore - a.priorityScore || Date.parse(b.scan.completedAt || b.scan.created) - Date.parse(a.scan.completedAt || a.scan.created));
  });
  protected readonly filtered = computed(() => { const query = this.query().trim().toLowerCase(); return this.events().filter((event) => (this.targetId() === 'all' || event.target.id === this.targetId()) && (this.status() === 'all' || (event.review?.status || 'unreviewed') === this.status()) && (this.changeState() === 'all' || event.state === this.changeState()) && (!query || [event.label, event.assetKey, event.kind, event.target.hostname, event.after?.subtitle, event.before?.subtitle].join(' ').toLowerCase().includes(query))); });
  protected readonly active = computed(() => this.filtered().find((event) => `${event.scan.id}:${event.key}` === this.selectedKey()) || this.filtered()[0] || null);
  protected readonly unreviewedCount = computed(() => this.events().filter((event) => !event.review || event.review.status === 'unreviewed').length);
  protected readonly investigateCount = computed(() => this.events().filter((event) => event.review?.status === 'investigate').length);
  protected readonly addedCount = computed(() => this.events().filter((event) => event.state === 'added').length);
  protected readonly absentCount = computed(() => this.events().filter((event) => event.state === 'not_observed').length);
  ngOnInit(): void { void this.load(); }
  private async load(): Promise<void> { try { const [targets, scans, findings, reviews] = await Promise.all([this.db.targets(), this.db.scans(), this.db.findings(), this.db.changeReviews()]); const assets = (await Promise.all(targets.map((target) => this.db.assets(target.id)))).flat(); this.targets.set(targets); this.scans.set(scans); this.findings.set(findings); this.reviews.set(reviews); this.assets.set(assets); const requested = this.route.snapshot.queryParamMap.get('target'); if (targets.some((target) => target.id === requested)) this.selectTarget(requested!); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not build the change ledger.'); } }
  protected selectTarget(id: string): void { this.targetId.set(id); const target = this.targets().find((item) => item.id === id); this.criticality.set(target?.criticality || 'standard'); this.tags.set(target?.tags.join(', ') || ''); this.selectedKey.set(''); }
  protected async saveContext(): Promise<void> { const target = this.selectedTarget(); if (!target) return; this.savingContext.set(true); try { const tags = this.tags().split(',').map((tag) => tag.trim()).filter(Boolean); await this.db.updateTargetContext(target.id, this.criticality(), tags); this.targets.update((items) => items.map((item) => item.id === target.id ? { ...item, criticality: this.criticality(), tags } : item)); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not save context.'); } finally { this.savingContext.set(false); } }
  protected async review(event: ReviewEvent, status: ChangeReviewStatus): Promise<void> { this.savingReview.set(true); try { const review = await this.db.reviewChange(event.target.id, event.scan.id, event.key, status, this.note(), event.review?.id); this.reviews.update((items) => [...items.filter((item) => item.id !== review.id), review]); this.note.set(''); } catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not record the decision.'); } finally { this.savingReview.set(false); } }
  protected reviewLabel(status?: ChangeReviewStatus): string { return ({ unreviewed: 'Unreviewed', expected: 'Expected', investigate: 'Investigate', resolved: 'Resolved' } as Record<string, string>)[status || 'unreviewed']; }
  protected isSelected(event: ReviewEvent): boolean { const active = this.active(); return active?.scan.id === event.scan.id && active.key === event.key; }
  protected selectEvent(event: ReviewEvent): void { this.selectedKey.set(`${event.scan.id}:${event.key}`); this.note.set(event.review?.note || ''); }
  protected changeLabel(state: SurfaceChangeState): string { return ({ added: 'Newly observed', changed: 'Evidence changed', not_observed: 'Not observed now' } as const)[state]; }
  protected stateLabel(state: string): string { return ({ risk: 'Needs action', warning: 'Review', healthy: 'Healthy', observed: 'Observed', unknown: 'Unknown' } as Record<string, string>)[state] || state; }
}
