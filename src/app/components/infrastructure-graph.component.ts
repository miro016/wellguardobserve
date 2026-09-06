import { afterNextRender, ChangeDetectionStrategy, Component, computed, effect, ElementRef, HostListener, inject, input, signal, viewChild } from '@angular/core';
import { Finding, Target, TlsObservation, AgentActionRecord, AssetRecord, AssetRelationRecord, NodeKind, TopologyEdge, TopologyNode } from '../models';
import { Topology, TopologyService } from '../services/topology.service';
import { topologyEdgeId, traceTopologyPath } from '../services/topology-path';
import { FindingStoryComponent } from './finding-story.component';

type GraphView = 'architecture' | 'routing' | 'evidence';

@Component({
  selector: 'wg-infrastructure-graph',
  imports: [FindingStoryComponent],
  template: `
    <div class="topology-shell">
      <div class="topology-toolbar">
        <div class="topology-lens" role="group" aria-label="Topology detail"><span>MAP LENS</span><button type="button" [class.active]="viewMode() === 'architecture'" (click)="setView('architecture')">Architecture</button><button type="button" [class.active]="viewMode() === 'routing'" (click)="setView('routing')">Network routing</button><button type="button" [class.active]="viewMode() === 'evidence'" (click)="setView('evidence')">All evidence</button></div>
        <label class="topology-search"><span>FILTER ASSETS</span><input type="search" placeholder="Hostname, service, technology…" [value]="query()" (input)="changeQuery($event)"></label>
        <button class="risk-filter" type="button" [class.active]="riskOnly()" (click)="riskOnly.set(!riskOnly())"><i></i>Needs action</button>
        <p><strong>{{ topology().nodes.length }} shown</strong><span>{{ collapsedLabel() }}</span></p>
      </div>
      <div #canvas class="topology-canvas" [class.dragging]="dragging()" role="application" aria-label="Observed infrastructure topology. Hover a node to trace its complete upstream and downstream evidence path. Drag to pan and use the controls or mouse wheel to zoom." (wheel)="zoomWheel($event)" (pointerdown)="panStart($event)" (pointermove)="panMove($event)" (pointerup)="panEnd($event)" (pointercancel)="panEnd($event)">
        <div class="map-controls" aria-label="Map controls"><button type="button" title="Zoom in" aria-label="Zoom in" (click)="zoomBy(0.15)">+</button><span>{{ zoomPercent() }}%</span><button type="button" title="Zoom out" aria-label="Zoom out" (click)="zoomBy(-0.15)">−</button><button class="fit-control" type="button" title="Fit all nodes" (click)="resetView()">Fit</button></div>
        <div class="topology-stage" [attr.data-view]="viewMode()" [style.height.px]="stageHeight()" [style.transform]="stageTransform()">
          <div class="topology-grid" aria-hidden="true"></div>
          <div class="topology-lanes" aria-hidden="true" [style.grid-template-columns]="'repeat(' + laneLabels().length + ',1fr)'">@for (label of laneLabels(); track label) { <span>{{ label }}</span> }</div>
          <svg class="topology-links" [attr.viewBox]="viewBox()" preserveAspectRatio="none" aria-label="Observed asset relationships">
            @for (edge of topology().edges; track edge.id || edge.from + edge.to) {
              <g class="topology-link" [class.selected]="selectedEdge()?.id === edge.id" [class.connection-active]="isHoveredEdge(edge)" [class.connection-muted]="!!hoveredNodeId() && !isHoveredEdge(edge)" [attr.data-state]="edge.state || 'observed'" role="button" tabindex="0" (click)="selectEdge(edge.id || edge.from + edge.to)" (keydown.enter)="selectEdge(edge.id || edge.from + edge.to)">
                <path class="link-hit" [attr.d]="path(edge.from, edge.to)" /><path [attr.d]="path(edge.from, edge.to)" />
              </g>
            }
          </svg>
          @for (edge of topology().edges; track edge.id || edge.from + edge.to) {
            @if (edge.state === 'risk' || edge.state === 'warning') { <button type="button" class="topology-edge-badge" [class.selected]="selectedEdge()?.id === edge.id" [attr.data-state]="edge.state" [style.left.%]="midXPercent(edge.from, edge.to)" [style.top.px]="midY(edge.from, edge.to) - 28" (pointerdown)="$event.stopPropagation()" (click)="selectEdge(edge.id || edge.from + edge.to)">{{ edge.label }}</button> }
          }
          @for (node of topology().nodes; track node.id) {
            <button class="topology-node" type="button" [class.selected]="!selectedEdge() && selected().id === node.id" [class.connection-source]="hoveredNodeId() === node.id" [class.connection-active]="isConnectedNode(node.id)" [class.connection-muted]="!!hoveredNodeId() && !isConnectedNode(node.id)" [attr.data-state]="node.state" [attr.data-kind]="node.kind" [style.left.%]="node.x" [style.top.%]="node.y" [style.--node-left]="node.x + '%'" [style.--node-top]="node.y + '%'" (pointerenter)="hoveredNodeId.set(node.id)" (pointerleave)="hoveredNodeId.set('')" (focus)="hoveredNodeId.set(node.id)" (blur)="hoveredNodeId.set('')" (click)="select(node.id)">
              <i aria-hidden="true">{{ icon(node.kind) }}</i><span><strong>{{ node.label }}</strong><small>{{ nodeSubtitle(node) }}</small></span>
              @if (node.findingIds.length) { <b>{{ node.findingIds.length }}</b> }
            </button>
          }
        </div>
        <div class="topology-legend"><span><i class="observed"></i>Observed</span><span><i class="healthy"></i>Healthy</span><span><i class="unknown"></i>Unknown</span><span><i class="risk"></i>Needs action</span></div>
      </div>

      <aside class="evidence-inspector">
        @if (selectedEdge(); as edge) {
          <div class="inspector-head"><span class="node-kind">relationship · {{ edge.type || 'observed' }}</span><span class="state-pill" [attr.data-state]="edge.state || 'observed'">{{ stateLabel(edge.state || 'observed') }}</span></div>
          <h3>{{ edge.label || edge.type || 'Observed relationship' }}</h3><p>{{ nodeLabel(edge.from) }} → {{ nodeLabel(edge.to) }}</p>
          <dl class="evidence-facts"><div><dt>Confidence</dt><dd>{{ edge.confidence || 'Unscored' }}{{ edge.confidence ? '%' : '' }}</dd><small><span>Basis</span>{{ basisLabel(edge.basis) }}</small></div>@for (item of edge.evidence || []; track item) { <div><dt>Relationship evidence</dt><dd>{{ item }}</dd><small><span>Attribution</span>This evidence belongs to the connection between both assets.</small></div> }</dl>
          @for (finding of edgeFindings(); track finding.id) { <article class="node-finding" [attr.data-severity]="finding.severity"><span>{{ finding.severity }} · {{ finding.confidence }}%</span><strong>{{ finding.title }}</strong><p>{{ finding.summary }}</p><wg-finding-story [finding]="finding" [compact]="true" /><h4>Change on</h4><p>{{ finding.asset }}</p><h4>Recommended action</h4><p>{{ finding.remediation }}</p></article> }
        } @else if (selected(); as node) {
          <div class="inspector-head"><span class="node-kind">{{ node.kind }}</span><span class="state-pill" [attr.data-state]="node.state">{{ stateLabel(node.state) }}</span></div>
          <h3>{{ node.label }}</h3><p>{{ node.subtitle }}</p>
          <dl class="evidence-facts">
            @for (detail of node.details; track detail.label) {
              <div><dt>{{ detail.label }}</dt><dd>{{ detail.value }}</dd><small><span>{{ detail.basis ? basisLabel(detail.basis) : 'Evidence' }}{{ detail.confidence ? ' · ' + detail.confidence + '%' : '' }}</span>{{ detail.evidence }}</small></div>
            }
          </dl>
          @for (finding of nodeFindings(); track finding.id) {
            <article class="node-finding" [attr.data-severity]="finding.severity"><span>{{ finding.severity }} · {{ finding.confidence }}%</span><strong>{{ finding.title }}</strong><p>{{ finding.summary }}</p><wg-finding-story [finding]="finding" [compact]="true" /><h4>Recommended action</h4><p>{{ finding.remediation || 'Review the observed exposure and reduce public reachability if it is not required.' }}</p></article>
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
  readonly assets = input<AssetRecord[]>([]);
  readonly relations = input<AssetRelationRecord[]>([]);
  private readonly builder = inject(TopologyService);
  private readonly canvas = viewChild<ElementRef<HTMLElement>>('canvas');
  protected readonly selectedId = signal('');
  protected readonly selectedEdgeId = signal('');
  protected readonly hoveredNodeId = signal('');
  protected readonly viewMode = signal<GraphView>('architecture');
  protected readonly query = signal('');
  protected readonly riskOnly = signal(false);
  protected readonly fullTopology = computed(() => this.builder.build(this.target(), this.findings(), this.tls(), this.actions(), this.assets(), this.relations()));
  protected readonly topology = computed(() => this.layout(this.filter(this.project(this.fullTopology(), this.viewMode()))));
  protected readonly laneLabels = computed(() => {
    const labels: Record<GraphView, Array<[NodeKind, string]>> = {
      architecture: [['domain', 'Authorized root'], ['hostname', 'Host'], ['url', 'Public URL'], ['server', 'Observed machine'], ['port', 'Machine port'], ['service', 'Application']],
      routing: [['domain', 'Authorized root'], ['hostname', 'Host'], ['url', 'Public URL'], ['edge', 'Provider edge'], ['network', 'Network'], ['server', 'Observed machine']],
      evidence: [['domain', 'Root'], ['hostname', 'Host'], ['url', 'URL'], ['edge', 'Edge'], ['network', 'Network'], ['server', 'Machine'], ['port', 'Port'], ['service', 'Application']]
    };
    const kinds = new Set(this.topology().nodes.map((node) => node.kind));
    return labels[this.viewMode()].filter(([kind]) => kinds.has(kind)).map(([, label]) => label);
  });
  protected readonly collapsedLabel = computed(() => {
    const hidden = this.fullTopology().nodes.length - this.topology().nodes.length;
    if (this.query() || this.riskOnly()) return `${hidden} asset${hidden === 1 ? '' : 's'} outside the current filter`;
    if (this.viewMode() === 'architecture') return hidden ? `${hidden} routing record${hidden === 1 ? '' : 's'} available in other lenses` : 'Complete observed application path';
    return hidden ? `${hidden} detail record${hidden === 1 ? '' : 's'} available in other lenses` : 'Every retained asset is visible';
  });
  protected readonly selected = computed(() => this.topology().nodes.find((node) => node.id === this.selectedId()) || this.topology().nodes[0]);
  protected readonly selectedEdge = computed(() => this.topology().edges.find((edge) => (edge.id || edge.from + edge.to) === this.selectedEdgeId()) || null);
  protected readonly highlightedPath = computed(() => traceTopologyPath(this.topology().edges, this.hoveredNodeId()));
  protected readonly nodeFindings = computed(() => this.findings().filter((finding) => this.selected()?.findingIds.includes(finding.id)));
  protected readonly edgeFindings = computed(() => this.findings().filter((finding) => this.selectedEdge()?.findingIds?.includes(finding.id)));
  protected readonly zoom = signal(1);
  protected readonly panX = signal(0);
  protected readonly panY = signal(0);
  protected readonly dragging = signal(false);
  protected readonly stageHeight = computed(() => {
    const counts = new Map<string, number>();
    for (const node of this.topology().nodes) counts.set(node.kind, (counts.get(node.kind) || 0) + 1);
    return Math.max(630, Math.max(1, ...counts.values()) * 66 + 100);
  });
  protected readonly stageTransform = computed(() => `translate3d(${this.panX()}px, ${this.panY()}px, 0) scale(${this.zoom()})`);
  protected readonly zoomPercent = computed(() => Math.round(this.zoom() * 100));
  protected readonly viewBox = computed(() => `0 0 1000 ${this.stageHeight()}`);
  private dragOrigin = { pointerX: 0, pointerY: 0, panX: 0, panY: 0 };
  private previousNodeCount = 0;

  constructor() {
    effect(() => {
      const count = this.topology().nodes.length;
      if (!this.topology().nodes.some((n) => n.id === this.selectedId())) this.selectedId.set(this.topology().nodes[0]?.id || 'domain');
      if (this.selectedEdgeId() && !this.topology().edges.some((edge) => (edge.id || edge.from + edge.to) === this.selectedEdgeId())) this.selectedEdgeId.set('');
      if (count !== this.previousNodeCount) { this.previousNodeCount = count; queueMicrotask(() => this.resetView()); }
    });
    afterNextRender(() => this.resetView());
  }
  protected select(id: string): void {
    this.selectedId.set(id);
    this.selectedEdgeId.set('');
  }
  protected selectEdge(id: string): void { this.selectedEdgeId.set(id); }
  protected isConnectedNode(id: string): boolean { return this.highlightedPath().nodeIds.has(id); }
  protected isHoveredEdge(edge: TopologyEdge): boolean { return this.highlightedPath().edgeIds.has(topologyEdgeId(edge)); }
  protected setView(view: GraphView): void { this.viewMode.set(view); }
  protected changeQuery(event: Event): void { this.query.set((event.target as HTMLInputElement).value); }
  protected icon(kind: string): string { return ({ domain: 'H', hostname: 'H', url: '/', network: 'N', edge: 'E', server: 'M', port: 'P', service: 'A' } as Record<string, string>)[kind] || '•'; }
  protected nodeSubtitle(node: TopologyNode): string { return node.subtitle; }
  protected stateLabel(state: string): string { return ({ risk: 'Needs action', warning: 'Review', healthy: 'Healthy', observed: 'Observed', unknown: 'Unknown' } as Record<string, string>)[state] || state; }
  protected path(from: string, to: string): string {
    const a = this.topology().nodes.find((n) => n.id === from); const b = this.topology().nodes.find((n) => n.id === to);
    if (!a || !b) return '';
    const x1 = a.x * 10 + 40, y1 = a.y * this.stageHeight() / 100, x2 = b.x * 10 - 45, y2 = b.y * this.stageHeight() / 100;
    return `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`;
  }
  protected midXPercent(from: string, to: string): number { const a = this.topology().nodes.find((n) => n.id === from); const b = this.topology().nodes.find((n) => n.id === to); return a && b ? (a.x + b.x) / 2 : 0; }
  protected midY(from: string, to: string): number { const a = this.topology().nodes.find((n) => n.id === from); const b = this.topology().nodes.find((n) => n.id === to); return a && b ? (a.y + b.y) * this.stageHeight() / 200 : 0; }
  protected nodeLabel(id: string): string { return this.topology().nodes.find((node) => node.id === id)?.label || id; }
  protected basisLabel(value?: string): string { return ({ observed: 'Direct observation', registry: 'Registry metadata', inferred: 'Inference', owner_confirmed: 'Owner confirmed' } as Record<string, string>)[value || ''] || 'Evidence'; }
  protected zoomBy(delta: number): void { this.zoom.set(this.clampZoom(this.zoom() + delta)); }
  @HostListener('window:resize')
  protected resetView(): void {
    const canvas = this.canvas()?.nativeElement;
    const stage = canvas?.querySelector<HTMLElement>('.topology-stage');
    const availableWidth = Math.max(280, (canvas?.clientWidth || 1000) - 24);
    const availableHeight = Math.max(280, (canvas?.clientHeight || 630) - 24);
    const stageWidth = stage?.clientWidth || availableWidth;
    const nextZoom = this.clampZoom(Math.min(1, availableWidth / stageWidth, availableHeight / this.stageHeight()));
    this.zoom.set(nextZoom);
    this.panX.set(Math.max(0, (availableWidth - stageWidth * nextZoom) / 2) + 12);
    this.panY.set(12);
  }
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
    if (target.closest('.topology-node, .map-controls, .topology-edge-badge')) return;
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
  private clampZoom(value: number): number { return Math.max(0.3, Math.min(1.8, Math.round(value * 100) / 100)); }

  private project(topology: Topology, view: GraphView): Topology {
    if (view === 'evidence') return topology;
    const kinds: Record<Exclude<GraphView, 'evidence'>, NodeKind[]> = {
      architecture: ['domain', 'hostname', 'url', 'server', 'port', 'service'],
      routing: ['domain', 'hostname', 'url', 'edge', 'network', 'server']
    };
    const domainLabels = new Set(topology.nodes.filter((node) => node.kind === 'domain').map((node) => node.label.toLowerCase().replace(/\.$/, '')));
    const visibleNodes = topology.nodes.filter((node) => kinds[view].includes(node.kind) && !(node.kind === 'hostname' && domainLabels.has(node.label.toLowerCase().replace(/\.$/, ''))));
    const visible = new Set(visibleNodes.map((node) => node.id));
    const outgoing = new Map<string, TopologyEdge[]>();
    for (const edge of topology.edges) outgoing.set(edge.from, [...(outgoing.get(edge.from) || []), edge]);
    const projected = new Map<string, TopologyEdge>();
    const rank = { risk: 4, warning: 3, unknown: 2, healthy: 1, observed: 0 } as Record<string, number>;
    for (const source of visibleNodes) {
      const queue: Array<{ node: string; path: TopologyEdge[] }> = (outgoing.get(source.id) || []).map((edge) => ({ node: edge.to, path: [edge] }));
      const visited = new Set<string>();
      while (queue.length) {
        const current = queue.shift()!;
        if (current.node === source.id || visited.has(current.node) || current.path.length > 8) continue;
        visited.add(current.node);
        if (visible.has(current.node)) {
          const key = `${source.id}→${current.node}`;
          const states = current.path.map((edge) => edge.state || 'observed');
          const state = states.sort((a, b) => rank[b]! - rank[a]!)[0] as TopologyEdge['state'];
          const hiddenPort = current.path.flatMap((edge) => [edge.from, edge.to]).map((id) => topology.nodes.find((node) => node.id === id)).find((node) => node?.kind === 'port');
          const findingIds = [...new Set(current.path.flatMap((edge) => edge.findingIds || []))];
          const edge: TopologyEdge = current.path.length === 1 ? current.path[0]! : {
            id: `projected:${key}`, from: source.id, to: current.node, type: 'evidence_path', label: hiddenPort ? `via ${hiddenPort.label}` : 'observed path',
            state, confidence: Math.min(...current.path.map((item) => item.confidence || 100)), basis: current.path.some((item) => item.basis === 'inferred') ? 'inferred' : 'observed',
            evidence: [...new Set(current.path.flatMap((item) => item.evidence || []))].slice(0, 12), findingIds
          };
          const previous = projected.get(key);
          if (!previous || current.path.length === 1 || rank[edge.state || 'observed']! > rank[previous.state || 'observed']!) projected.set(key, edge);
          continue;
        }
        for (const edge of outgoing.get(current.node) || []) queue.push({ node: edge.to, path: [...current.path, edge] });
      }
    }
    let projectedEdges = [...projected.values()];
    if (view === 'architecture') {
      const urlDestinations = new Set(projectedEdges.filter((edge) => visibleNodes.find((node) => node.id === edge.from)?.kind === 'url').map((edge) => edge.to));
      projectedEdges = projectedEdges.filter((edge) => {
        const from = visibleNodes.find((node) => node.id === edge.from);
        const to = visibleNodes.find((node) => node.id === edge.to);
        return !(from && (from.kind === 'domain' || from.kind === 'hostname') && to?.kind === 'server' && urlDestinations.has(to.id));
      });
    }
    return { nodes: visibleNodes, edges: projectedEdges };
  }

  private filter(topology: Topology): Topology {
    const query = this.query().trim().toLowerCase();
    if (!query && !this.riskOnly()) return topology;
    const matched = topology.nodes.filter((node) => (!this.riskOnly() || node.state === 'risk' || node.state === 'warning') && (!query || [node.label, node.subtitle, ...node.details.flatMap((item) => [item.label, item.value])].join(' ').toLowerCase().includes(query)));
    const keep = new Set(matched.map((node) => node.id));
    const incoming = new Map<string, string[]>();
    for (const edge of topology.edges) incoming.set(edge.to, [...(incoming.get(edge.to) || []), edge.from]);
    const queue = [...keep];
    while (queue.length) for (const parent of incoming.get(queue.shift()!) || []) if (!keep.has(parent)) { keep.add(parent); queue.push(parent); }
    for (const node of matched.filter((item) => item.kind === 'domain' || item.kind === 'hostname')) {
      for (const edge of topology.edges.filter((item) => item.from === node.id)) keep.add(edge.to);
    }
    return { nodes: topology.nodes.filter((node) => keep.has(node.id)), edges: topology.edges.filter((edge) => keep.has(edge.from) && keep.has(edge.to)) };
  }

  private layout(topology: Topology): Topology {
    const kindOrder: Record<GraphView, NodeKind[]> = {
      architecture: ['domain', 'hostname', 'url', 'server', 'port', 'service'],
      routing: ['domain', 'hostname', 'url', 'edge', 'network', 'server'],
      evidence: ['domain', 'hostname', 'url', 'edge', 'network', 'server', 'port', 'service']
    };
    const rawOrder = kindOrder[this.viewMode()];
    const order = rawOrder.filter((kind) => topology.nodes.some((node) => node.kind === kind));
    const positions = new Map<string, { x: number; y: number }>();
    order.forEach((kind, column) => {
      const items = topology.nodes.filter((node) => node.kind === kind).sort((a, b) => a.y - b.y || a.label.localeCompare(b.label));
      const x = order.length === 1 ? 50 : 8 + column * (84 / (order.length - 1));
      items.forEach((node, index) => positions.set(node.id, { x, y: items.length === 1 ? 50 : 10 + index * (80 / Math.max(1, items.length - 1)) }));
    });
    return { nodes: topology.nodes.map((node) => ({ ...node, ...(positions.get(node.id) || { x: node.x, y: node.y }) })), edges: topology.edges };
  }
}
