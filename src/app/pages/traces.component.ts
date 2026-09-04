import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { AgentActionRecord, AgentMessageRecord, Scan, Target } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({ selector: 'wg-traces', imports: [AppSidebarComponent, FormsModule, DatePipe], template: `
  <div class="app-layout"><wg-app-sidebar /><main class="app-main"><header class="app-header"><div><span class="app-breadcrumb">TRANSPARENCY / AGENT TRACES</span><h1>Investigation transcript</h1><p>See what the model was told, what it said, and every bounded tool call made on its behalf.</p></div><label class="target-select"><span>Investigation</span><select [ngModel]="scanId()" (ngModelChange)="selectScan($event)">@for (scan of scans(); track scan.id) { <option [value]="scan.id">{{ targetName(scan.target) }} · {{ scan.created | date:'MMM d, HH:mm' }}</option> }</select></label></header>
  @if (error()) { <div class="error-banner"><strong>Trace unavailable</strong><span>{{ error() }}</span></div> }
  <section class="trace-layout"><article class="panel transcript-panel"><div class="panel-heading"><div><span class="section-index">MODEL TRANSCRIPT</span><h2>Messages</h2></div><span class="evidence-count">{{ messages().length }} messages</span></div><div class="transcript">@for (message of messages(); track message.id) { <article class="message" [attr.data-role]="message.role"><header><span>{{ message.role }}</span>@if (message.toolName) { <b>{{ message.toolName }}</b> }<time>{{ message.occurredAt | date:'HH:mm:ss' }}</time></header><pre>{{ message.content }}</pre></article> } @empty { <div class="empty-state"><strong>No model messages retained for this older scan.</strong><span>Full transcript capture is active for new investigations. Tool calls from this scan remain available alongside.</span></div> }</div></article>
  <aside class="panel tools-panel"><div class="panel-heading"><div><span class="section-index">BOUNDED EXECUTION</span><h2>Tool calls</h2></div><span class="evidence-count">{{ actions().length }} calls</span></div><div class="tool-calls">@for (action of actions(); track action.id; let index = $index) { <details [open]="index === 0"><summary><span>{{ index + 1 }}</span><strong>{{ action.tool }}</strong><time>{{ action.occurredAt | date:'HH:mm:ss' }}</time></summary><div><small>INPUT</small><pre>{{ json(action.input) }}</pre><small>RESULT</small><pre>{{ pretty(action.summary) }}</pre></div></details> } @empty { <div class="empty-state">No tool calls are linked to this scan.</div> }</div></aside></section>
  <div class="trace-notice"><span>TRANSPARENCY BOUNDARY</span><p>Host responses and public documents are treated as untrusted data. The trace is retained so users can audit the path from observation to finding.</p></div>
  </main></div>`, changeDetection: ChangeDetectionStrategy.OnPush })
export class TracesComponent implements OnInit {
  private readonly db = inject(PocketBaseService); private readonly route = inject(ActivatedRoute); protected readonly scans = signal<Scan[]>([]); protected readonly targets = signal<Target[]>([]); protected readonly scanId = signal(''); protected readonly messages = signal<AgentMessageRecord[]>([]); protected readonly actions = signal<AgentActionRecord[]>([]); protected readonly error = signal('');
  ngOnInit(): void { void Promise.all([this.db.scans(), this.db.targets()]).then(([scans, targets]) => { this.scans.set(scans); this.targets.set(targets); const targetId = this.route.snapshot.queryParamMap.get('target'); const id = scans.find((scan) => scan.target === targetId)?.id || scans[0]?.id || ''; this.scanId.set(id); return this.loadTrace(id); }).catch((e) => this.error.set(e instanceof Error ? e.message : 'Could not load traces.')); }
  protected selectScan(id: string): void { this.scanId.set(id); void this.loadTrace(id); }
  private async loadTrace(id: string): Promise<void> { if (!id) return; try { const [messages, actions] = await Promise.all([this.db.agentMessages({ scanId: id }), this.db.agentActions({ scanId: id })]); this.messages.set(messages); this.actions.set(actions); } catch (e) { this.error.set(e instanceof Error ? e.message : 'Could not load trace.'); } }
  protected targetName(id: string): string { return this.targets().find((t) => t.id === id)?.hostname || 'Unknown target'; }
  protected json(value: unknown): string { return JSON.stringify(value, null, 2); }
  protected pretty(value: string): string { try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; } }
}
