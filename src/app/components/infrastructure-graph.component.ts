import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { Finding, Target, TlsObservation, AgentActionRecord } from '../models';
import { TopologyService } from '../services/topology.service';

@Component({
  selector: 'wg-infrastructure-graph',
  template: `
    <div class="topology-shell">
      <div class="topology-canvas" role="group" aria-label="Observed infrastructure topology">
        <div class="topology-grid" aria-hidden="true"></div>
        <div class="topology-lanes" aria-hidden="true"><span>Identity</span><span>Edge</span><span>Origin</span><span>Ports</span><span>Services</span></div>
        <svg class="topology-links" viewBox="0 0 1000 480" preserveAspectRatio="none" aria-hidden="true">
          @for (edge of topology().edges; track edge.from + edge.to) {
            <path [attr.d]="path(edge.from, edge.to)" />
          }
        </svg>
        @for (node of topology().nodes; track node.id) {
          <button class="topology-node" type="button" [class.selected]="selected().id === node.id" [attr.data-state]="node.state" [attr.data-kind]="node.kind" [style.left.%]="node.x" [style.top.%]="node.y" (click)="select(node.id)">
            <i aria-hidden="true">{{ icon(node.kind) }}</i><span><strong>{{ node.label }}</strong><small>{{ node.subtitle }}</small></span>
            @if (node.findingIds.length) { <b>{{ node.findingIds.length }}</b> }
          </button>
        }
        <div class="topology-legend"><span><i class="observed"></i>Observed</span><span><i class="healthy"></i>Healthy</span><span><i class="unknown"></i>Unknown</span><span><i class="risk"></i>Needs action</span></div>
      </div>

      <aside class="evidence-inspector">
        @if (selected(); as node) {
          <div class="inspector-head"><span class="node-kind">{{ node.kind }}</span><span class="state-pill" [attr.data-state]="node.state">{{ stateLabel(node.state) }}</span></div>
          <h3>{{ node.label }}</h3><p>{{ node.subtitle }}</p>
          <dl class="evidence-facts">
            @for (detail of node.details; track detail.label) {
              <div><dt>{{ detail.label }}</dt><dd>{{ detail.value }}</dd><small><span>Evidence</span>{{ detail.evidence }}</small></div>
            }
          </dl>
          @for (finding of nodeFindings(); track finding.id) {
            <article class="node-finding" [attr.data-severity]="finding.severity"><span>{{ finding.severity }} · {{ finding.confidence }}%</span><strong>{{ finding.title }}</strong><p>{{ finding.summary }}</p><h4>Recommended action</h4><p>{{ finding.remediation || 'Review the observed exposure and reduce public reachability if it is not required.' }}</p></article>
          }
        }
      </aside>
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class InfrastructureGraphComponent {
  readonly target = input.required<Target>();
  readonly findings = input<Finding[]>([]);
  readonly tls = input<TlsObservation | null>(null);
  readonly actions = input<AgentActionRecord[]>([]);
  private readonly builder = inject(TopologyService);
  protected readonly selectedId = signal('domain');
  protected readonly topology = computed(() => this.builder.build(this.target(), this.findings(), this.tls(), this.actions()));
  protected readonly selected = computed(() => this.topology().nodes.find((node) => node.id === this.selectedId()) || this.topology().nodes[0]);
  protected readonly nodeFindings = computed(() => this.findings().filter((finding) => this.selected()?.findingIds.includes(finding.id)));

  constructor() { effect(() => { if (!this.topology().nodes.some((n) => n.id === this.selectedId())) this.selectedId.set('domain'); }); }
  protected select(id: string): void { this.selectedId.set(id); }
  protected icon(kind: string): string { return ({ domain: '◎', edge: '◇', server: '▣', port: ':', service: '◆' } as Record<string, string>)[kind] || '•'; }
  protected stateLabel(state: string): string { return ({ risk: 'Needs action', warning: 'Review', healthy: 'Healthy', observed: 'Observed', unknown: 'Unknown' } as Record<string, string>)[state] || state; }
  protected path(from: string, to: string): string {
    const a = this.topology().nodes.find((n) => n.id === from); const b = this.topology().nodes.find((n) => n.id === to);
    if (!a || !b) return '';
    const x1 = a.x * 10 + 40, y1 = a.y * 4.8, x2 = b.x * 10 - 45, y2 = b.y * 4.8;
    return `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`;
  }
}
