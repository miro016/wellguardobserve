import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Finding, FindingFeedback, ImprovementProposal, KnowledgeObservation, KnowledgePattern, Scan, ScanEvaluation, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';
import { buildKnowledgePatterns } from '../services/posture-intelligence';

@Component({
  selector: 'wg-knowledge',
  imports: [AppSidebarComponent, DatePipe, FormsModule, RouterLink],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main knowledge-page">
      <header class="app-header"><div><span class="app-breadcrumb">ANALYZE / KNOWLEDGE</span><h1>Exposure knowledge</h1><p>Recurring mistakes and technology patterns built from retained, owner-authorized observations.</p></div><span class="as-of-chip"><i></i>{{ observationCount() }} evidence observations</span></header>
      @if (error()) { <div class="error-banner"><strong>Knowledge unavailable</strong><span>{{ error() }}</span></div> }

      <section class="calibration-rail panel" aria-label="Governed learning cycle">
        <div class="calibration-intro"><span class="section-index">CONTROLLED IMPROVEMENT</span><h2>Evidence changes the system only after review</h2><p>Every completed scan is scored deterministically. Repeated signals become bounded proposals—not autonomous prompt or code changes.</p></div>
        <div class="calibration-stage complete"><i>01</i><span><strong>Evidence</strong><small>{{ evaluations().length }} evaluated runs</small></span></div><div class="calibration-link"></div>
        <div class="calibration-stage complete"><i>02</i><span><strong>Evaluate</strong><small>{{ averageQuality() }}% mean quality</small></span></div><div class="calibration-link"></div>
        <div class="calibration-stage" [class.attention]="proposed().length > 0"><i>03</i><span><strong>Human review</strong><small>{{ proposed().length }} awaiting decision</small></span></div><div class="calibration-link"></div>
        <div class="calibration-stage"><i>04</i><span><strong>Apply guard</strong><small>{{ approvedCount() }} approved · {{ applicationCount() }} uses</small></span></div>
      </section>

      <section class="knowledge-metrics">
        <article><span>Distinct patterns</span><strong>{{ patterns().length }}</strong><small>Deterministically grouped</small></article>
        <article><span>Recurring patterns</span><strong>{{ recurringCount() }}</strong><small>Observed more than once</small></article>
        <article><span>Affected targets</span><strong>{{ affectedTargetCount() }}</strong><small>Across authorized scope</small></article>
        <article class="knowledge-leading"><span>Leading category</span><strong>{{ leadingCategory() }}</strong><small>By retained occurrence count</small></article>
      </section>

      <section class="knowledge-intro panel">
        <div><span class="section-index">EVIDENCE MEMORY</span><h2>From individual findings to repeatable prevention</h2><p>Wellguard assigns a stable pattern key to each observation using the weakness, technology, and configuration category. This creates a queryable foundation for baselines, recurring-control recommendations, and anonymized benchmarks later.</p></div>
        <div class="knowledge-flow" aria-label="Knowledge pipeline"><span>Observation</span><i>→</i><span>Pattern</span><i>→</i><span>Prevention</span></div>
      </section>

      <section class="learning-console">
        <div class="panel proposal-queue">
          <div class="proposal-heading"><div><span class="section-index">APPROVAL QUEUE</span><h2>System improvement proposals</h2></div><span>{{ proposals().length }} total</span></div>
          @for (proposal of proposals(); track proposal.id) {
            <article class="proposal-card" [attr.data-status]="proposal.status">
              <div class="proposal-marker"><span>{{ proposal.kind.replace('_', ' ') }}</span><strong>{{ proposal.confidence }}%</strong></div>
              <div class="proposal-copy"><div><h3>{{ proposal.title }}</h3><span class="proposal-status">{{ proposal.status }}</span></div><p>{{ proposal.rationale }}</p><small>{{ proposal.occurrences }} supporting signals · {{ proposal.applicationCount }} subsequent uses</small></div>
              @if (proposal.status === 'proposed' && canReview()) { <div class="proposal-actions"><button type="button" class="button primary" [disabled]="reviewing() === proposal.id" (click)="reviewProposal(proposal, 'approved')">Approve guard</button><button type="button" class="button" [disabled]="reviewing() === proposal.id" (click)="reviewProposal(proposal, 'rejected')">Reject</button></div> }
            </article>
          } @empty { <div class="empty-state"><strong>No change is waiting for approval.</strong><span>The current evidence has not crossed a proposal threshold.</span></div> }
        </div>
        <aside class="panel evaluation-card"><span class="section-index">LATEST EVALUATION</span>
          @if (latestEvaluation(); as evaluation) {
            <div class="quality-dial"><strong>{{ evaluation.qualityScore }}</strong><span>/ 100</span></div>
            <dl><div><dt>Tool success</dt><dd>{{ percent(evaluation.toolSuccessRate) }}</dd></div><div><dt>Evidence coverage</dt><dd>{{ percent(evaluation.evidenceCoverage) }}</dd></div><div><dt>Asset linkage</dt><dd>{{ percent(evaluation.assetLinkage) }}</dd></div><div><dt>External cache</dt><dd>{{ evaluation.cacheHits }} hits / {{ evaluation.originRequests }} origin</dd></div></dl>
            <p>{{ evaluation.profile }} profile · {{ evaluation.model }} · {{ evaluation.reasoningEffort }} reasoning</p>
          } @else { <div class="empty-state">A quality receipt will appear after the next completed scan.</div> }
        </aside>
      </section>

      <section class="filter-bar knowledge-filters"><label><span>Search patterns</span><input [ngModel]="query()" (ngModelChange)="query.set($event)" placeholder="Technology, weakness, category…"></label><label><span>Category</span><select [ngModel]="category()" (ngModelChange)="category.set($event)"><option value="all">All categories</option>@for (item of categories(); track item) { <option [value]="item">{{ item }}</option> }</select></label><div class="filter-result">{{ filteredPatterns().length }} patterns</div></section>

      <section class="knowledge-layout">
        <div class="panel pattern-register">
          <div class="pattern-head"><span>Pattern</span><span>Footprint</span><span>Frequency</span></div>
          @for (pattern of filteredPatterns(); track pattern.key) {
            <button type="button" class="pattern-row" [class.selected]="isSelected(pattern)" (click)="selectedKey.set(pattern.key)">
              <span class="pattern-signal" [attr.data-severity]="pattern.severity"></span>
              <span><small>{{ pattern.category }}</small><strong>{{ pattern.title }}</strong><em>{{ pattern.technology }}</em></span>
              <span><strong>{{ pattern.affectedTargetIds.length }}</strong><small>target{{ pattern.affectedTargetIds.length === 1 ? '' : 's' }}</small></span>
              <span><strong>{{ pattern.occurrences }}</strong><small>{{ pattern.currentCount }} current</small></span>
            </button>
          } @empty { <div class="empty-state"><strong>No patterns match this view.</strong><span>Change the filters or retain more observations.</span></div> }
        </div>

        <aside class="panel pattern-inspector">
          @if (active(); as pattern) {
            <div class="inspector-head"><span class="severity-label" [attr.data-severity]="pattern.severity">{{ pattern.severity }}</span><span>{{ pattern.category }}</span></div>
            <h2>{{ pattern.title }}</h2><p>{{ pattern.technology }}</p>
            <div class="pattern-stats"><div><small>FIRST SEEN</small><strong>{{ pattern.firstSeenAt | date:'mediumDate' }}</strong></div><div><small>LAST SEEN</small><strong>{{ pattern.lastSeenAt | date:'mediumDate' }}</strong></div><div><small>OBSERVATIONS</small><strong>{{ pattern.occurrences }}</strong></div></div>
            @if (pattern.weaknessIds.length) { <h3>Weakness classification</h3><div class="identifier-strip large">@for (id of pattern.weaknessIds; track id) { <span data-kind="cwe">{{ id }}</span> }</div> }
            <h3>Where it appears</h3><div class="affected-targets">@for (id of pattern.affectedTargetIds; track id) { <a [routerLink]="['/app/targets', id]"><span>{{ targetName(id) }}</span><small>Open target →</small></a> }</div>
            <h3>Evidence examples</h3><ul class="evidence-list">@for (finding of examples(pattern); track finding.id) { <li><strong>{{ finding.asset }}</strong><span>{{ finding.summary }}</span>@if (canReview()) { <div class="evidence-verdict"><button type="button" [class.active]="feedbackFor(finding)?.verdict === 'confirmed'" (click)="reviewEvidence(finding, pattern.key, 'confirmed')">Confirmed</button><button type="button" [class.active]="feedbackFor(finding)?.verdict === 'false_positive'" (click)="reviewEvidence(finding, pattern.key, 'false_positive')">False positive</button><button type="button" [class.active]="feedbackFor(finding)?.verdict === 'unclear'" (click)="reviewEvidence(finding, pattern.key, 'unclear')">Unclear</button></div> }</li> }</ul>
            <div class="knowledge-boundary"><strong>Interpretation boundary</strong><p>Frequency shows what was repeatedly observed. It does not prove that one configuration caused another issue, and “not observed” is not proof of remediation.</p></div>
          } @else { <div class="empty-state">Select a pattern to inspect its footprint.</div> }
        </aside>
      </section>
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class KnowledgeComponent implements OnInit {
  private readonly db = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]);
  protected readonly findings = signal<Finding[]>([]);
  protected readonly scans = signal<Scan[]>([]);
  protected readonly observations = signal<KnowledgeObservation[]>([]);
  protected readonly evaluations = signal<ScanEvaluation[]>([]);
  protected readonly proposals = signal<ImprovementProposal[]>([]);
  protected readonly feedback = signal<FindingFeedback[]>([]);
  protected readonly reviewing = signal('');
  protected readonly query = signal('');
  protected readonly category = signal('all');
  protected readonly selectedKey = signal('');
  protected readonly error = signal('');
  protected readonly patterns = computed(() => buildKnowledgePatterns(this.findings(), this.scans()));
  protected readonly categories = computed(() => [...new Set(this.patterns().map((pattern) => pattern.category))].sort());
  protected readonly filteredPatterns = computed(() => {
    const query = this.query().trim().toLowerCase();
    return this.patterns().filter((pattern) => (this.category() === 'all' || pattern.category === this.category()) && (!query || [pattern.title, pattern.category, pattern.technology, ...pattern.weaknessIds].join(' ').toLowerCase().includes(query)));
  });
  protected readonly active = computed(() => this.filteredPatterns().find((pattern) => pattern.key === this.selectedKey()) || this.filteredPatterns()[0] || null);
  protected readonly observationCount = computed(() => this.observations().length || this.findings().reduce((sum, finding) => sum + Math.max(1, finding.runCount), 0));
  protected readonly recurringCount = computed(() => this.patterns().filter((pattern) => pattern.occurrences > 1).length);
  protected readonly affectedTargetCount = computed(() => new Set(this.patterns().flatMap((pattern) => pattern.affectedTargetIds)).size);
  protected readonly leadingCategory = computed(() => {
    const counts = new Map<string, number>();
    for (const pattern of this.patterns()) counts.set(pattern.category, (counts.get(pattern.category) || 0) + pattern.occurrences);
    return [...counts].sort((a, b) => b[1] - a[1])[0]?.[0] || 'No evidence yet';
  });
  protected readonly latestEvaluation = computed(() => this.evaluations()[0] || null);
  protected readonly averageQuality = computed(() => this.evaluations().length ? Math.round(this.evaluations().reduce((sum, item) => sum + item.qualityScore, 0) / this.evaluations().length) : 0);
  protected readonly proposed = computed(() => this.proposals().filter((proposal) => proposal.status === 'proposed'));
  protected readonly approvedCount = computed(() => this.proposals().filter((proposal) => proposal.status === 'approved').length);
  protected readonly applicationCount = computed(() => this.proposals().reduce((sum, proposal) => sum + proposal.applicationCount, 0));
  protected readonly canReview = computed(() => this.db.canManageWorkspace(this.db.activeWorkspaceId()));

  ngOnInit(): void {
    void Promise.all([this.db.targets(), this.db.findings(), this.db.scans(), this.db.knowledgeObservations(), this.db.scanEvaluations(), this.db.improvementProposals(), this.db.findingFeedback()])
      .then(([targets, findings, scans, observations, evaluations, proposals, feedback]) => { this.targets.set(targets); this.findings.set(findings); this.scans.set(scans); this.observations.set(observations); this.evaluations.set(evaluations); this.proposals.set(proposals); this.feedback.set(feedback); })
      .catch((error) => this.error.set(error instanceof Error ? error.message : 'Could not build the knowledge view.'));
  }
  protected targetName(id: string): string { return this.targets().find((target) => target.id === id)?.hostname || 'Unknown target'; }
  protected isSelected(pattern: KnowledgePattern): boolean { return this.active()?.key === pattern.key; }
  protected examples(pattern: KnowledgePattern): Finding[] { return this.findings().filter((finding) => pattern.findingIds.includes(finding.id)).slice(0, 4); }
  protected feedbackFor(finding: Finding): FindingFeedback | undefined { return this.feedback().find((item) => item.finding === finding.id && item.reviewedBy === this.db.user()?.id); }
  protected percent(value: number): string { return `${Math.round(value * 100)}%`; }
  protected async reviewEvidence(finding: Finding, patternKey: string, verdict: FindingFeedback['verdict']): Promise<void> {
    try { const saved = await this.db.recordFindingFeedback(finding, patternKey, verdict); this.feedback.update((items) => [saved, ...items.filter((item) => item.id !== saved.id)]); }
    catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not retain the evidence review.'); }
  }
  protected async reviewProposal(proposal: ImprovementProposal, status: 'approved' | 'rejected'): Promise<void> {
    this.reviewing.set(proposal.id);
    try { await this.db.reviewImprovementProposal(proposal, status); this.proposals.update((items) => items.map((item) => item.id === proposal.id ? { ...item, status } : item)); }
    catch (error) { this.error.set(error instanceof Error ? error.message : 'Could not review the proposal.'); }
    finally { this.reviewing.set(''); }
  }
}
