import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { Finding, Target, TlsObservation, AgentActionRecord } from '../models';
import { TopologyService } from '../services/topology.service';

@Component({
  selector: 'wg-infrastructure-graph',
  template: `
    <div class="topology-shell">
      <div class="topology-canvas" [class.dragging]="dragging()" role="application" aria-label="Observed infrastructure topology. Drag to pan and use the controls or mouse wheel to zoom." (wheel)="zoomWheel($event)" (pointerdown)="panStart($event)" (pointermove)="panMove($event)" (pointerup)="panEnd($event)" (pointercancel)="panEnd($event)">
        <div class="map-controls" aria-label="Map controls"><button type="button" title="Zoom in" aria-label="Zoom in" (click)="zoomBy(0.15)">+</button><span>{{ zoomPercent() }}%</span><button type="button" title="Zoom out" aria-label="Zoom out" (click)="zoomBy(-0.15)">−</button><button class="fit-control" type="button" title="Fit all nodes" (click)="resetView()">Fit</button></div>
        <div class="topology-stage" [style.height.px]="stageHeight()" [style.transform]="stageTransform()">
          <div class="topology-grid" aria-hidden="true"></div>
          <div class="topology-lanes" aria-hidden="true"><span>Identity</span><span>Edge</span><span>Origin</span><span>Ports</span><span>Services</span></div>
          <svg class="topology-links" [attr.viewBox]="viewBox()" preserveAspectRatio="none" aria-hidden="true">
            @for (edge of topology().edges; track edge.from + edge.to) {
              <path [attr.d]="path(edge.from, edge.to)" />
            }
          </svg>
          @for (node of topology().nodes; track node.id) {
            <button class="topology-node" type="button" [class.selected]="selected().id === node.id" [attr.data-state]="node.state" [attr.data-kind]="node.kind" [style.left.%]="node.x" [style.top.%]="node.y" [style.--node-left]="node.x + '%'" [style.--node-top]="node.y + '%'" (click)="select(node.id)">
              <i aria-hidden="true">{{ icon(node.kind) }}</i><span><strong>{{ node.label }}</strong><small>{{ node.subtitle }}</small></span>
              @if (node.findingIds.length) { <b>{{ node.findingIds.length }}</b> }
            </button>
          }
        </div>
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
  protected readonly zoom = signal(1);
  protected readonly panX = signal(0);
  protected readonly panY = signal(0);
  protected readonly dragging = signal(false);
  protected readonly stageHeight = computed(() => {
    const services = this.topology().nodes.filter((node) => node.kind === 'service').length;
    const ports = this.topology().nodes.filter((node) => node.kind === 'port').length;
    return Math.max(630, Math.max(services, ports) * 66 + 80);
  });
  protected readonly stageTransform = computed(() => `translate3d(${this.panX()}px, ${this.panY()}px, 0) scale(${this.zoom()})`);
  protected readonly zoomPercent = computed(() => Math.round(this.zoom() * 100));
  protected readonly viewBox = computed(() => `0 0 1000 ${this.stageHeight()}`);
  private dragOrigin = { pointerX: 0, pointerY: 0, panX: 0, panY: 0 };
  private previousNodeCount = 0;

  constructor() { effect(() => {
    const count = this.topology().nodes.length;
    if (!this.topology().nodes.some((n) => n.id === this.selectedId())) this.selectedId.set('domain');
    if (count !== this.previousNodeCount) { this.previousNodeCount = count; this.resetView(); }
  }); }
  protected select(id: string): void { this.selectedId.set(id); }
  protected icon(kind: string): string { return ({ domain: '◎', edge: '◇', server: '▣', port: ':', service: '◆' } as Record<string, string>)[kind] || '•'; }
  protected stateLabel(state: string): string { return ({ risk: 'Needs action', warning: 'Review', healthy: 'Healthy', observed: 'Observed', unknown: 'Unknown' } as Record<string, string>)[state] || state; }
  protected path(from: string, to: string): string {
    const a = this.topology().nodes.find((n) => n.id === from); const b = this.topology().nodes.find((n) => n.id === to);
    if (!a || !b) return '';
    const x1 = a.x * 10 + 40, y1 = a.y * this.stageHeight() / 100, x2 = b.x * 10 - 45, y2 = b.y * this.stageHeight() / 100;
    return `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`;
  }
  protected zoomBy(delta: number): void { this.zoom.set(this.clampZoom(this.zoom() + delta)); }
  protected resetView(): void { this.zoom.set(this.clampZoom(Math.min(1, 590 / this.stageHeight()))); this.panX.set(0); this.panY.set(0); }
  protected zoomWheel(event: WheelEvent): void {
    event.preventDefault();
    const canvas = event.currentTarget as HTMLElement;
    const rect = canvas.getBoundingClientRect();
    const pointX = event.clientX - rect.left; const pointY = event.clientY - rect.top;
    const oldZoom = this.zoom(); const nextZoom = this.clampZoom(oldZoom + (event.deltaY < 0 ? 0.1 : -0.1));
    const contentX = (pointX - this.panX()) / oldZoom; const contentY = (pointY - this.panY()) / oldZoom;
    this.panX.set(pointX - contentX * nextZoom); this.panY.set(pointY - contentY * nextZoom); this.zoom.set(nextZoom);
  }
  protected panStart(event: PointerEvent): void {
    const target = event.target as HTMLElement;
    if (target.closest('.topology-node, .map-controls')) return;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    this.dragOrigin = { pointerX: event.clientX, pointerY: event.clientY, panX: this.panX(), panY: this.panY() };
    this.dragging.set(true);
  }
  protected panMove(event: PointerEvent): void {
    if (!this.dragging()) return;
    this.panX.set(this.dragOrigin.panX + event.clientX - this.dragOrigin.pointerX);
    this.panY.set(this.dragOrigin.panY + event.clientY - this.dragOrigin.pointerY);
  }
  protected panEnd(event: PointerEvent): void {
    if (!this.dragging()) return;
    const canvas = event.currentTarget as HTMLElement;
    if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    this.dragging.set(false);
  }
  private clampZoom(value: number): number { return Math.max(0.45, Math.min(1.8, Math.round(value * 100) / 100)); }
}
