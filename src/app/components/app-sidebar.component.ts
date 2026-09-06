import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink, RouterLinkActive } from '@angular/router';
import { PocketBaseService } from '../services/pocketbase.service';
import { ThemeService } from '../services/theme.service';

@Component({
  selector: 'wg-app-sidebar',
  imports: [RouterLink, RouterLinkActive, FormsModule],
  template: `
    <aside class="app-sidebar">
      <a class="wordmark sidebar-wordmark" routerLink="/" aria-label="Wellguard Observe home"><span class="brand-mark"><i></i></span><span>Wellguard<em>Observe</em></span></a>
      <label class="workspace-chip workspace-switcher"><i></i><span><small>Active workspace</small>@if (pocketbase.workspaces().length) { <select aria-label="Active workspace" [ngModel]="pocketbase.activeWorkspaceId()" (ngModelChange)="switchWorkspace($event)">@for (workspace of pocketbase.workspaces(); track workspace.id) { <option [value]="workspace.id">{{ workspace.name }}</option> }</select> } @else { <strong>No workspace</strong> }</span></label>
      <nav class="app-navigation" aria-label="Workspace navigation">
        <span>Posture</span>
        <a routerLink="/app" routerLinkActive="active" [routerLinkActiveOptions]="{exact:true}"><i>P</i>Current posture</a>
        <a routerLink="/app/surface" routerLinkActive="active"><i>M</i>Surface map</a>
        <a routerLink="/app/targets" routerLinkActive="active"><i>T</i>Targets</a>
        <span>Analyze</span>
        <a routerLink="/app/findings" routerLinkActive="active"><i>I</i>Issue register</a>
        <a routerLink="/app/changes" routerLinkActive="active"><i>∆</i>Change review</a>
        <a routerLink="/app/reports" routerLinkActive="active"><i>H</i>Change history</a>
        <a routerLink="/app/knowledge" routerLinkActive="active"><i>K</i>Knowledge</a>
        <span>Operate</span>
        <a routerLink="/app/jobs" routerLinkActive="active"><i>O</i>Investigations @if (activeJobs()) { <b class="nav-job-count"><span></span>{{ activeJobs() }}</b> }</a>
        <a routerLink="/app/identities" routerLinkActive="active"><i>G</i>Identity governance</a>
        <a routerLink="/app/sources" routerLinkActive="active"><i>E</i>Evidence library</a>
        <span>Manage</span>
        @if (pocketbase.isAdmin()) { <a routerLink="/app/workspaces" routerLinkActive="active"><i>W</i>Workspaces</a><a routerLink="/app/tools" routerLinkActive="active"><i>C</i>Agent tools</a><a routerLink="/app/admin" routerLinkActive="active"><i>A</i>Target administration</a> }
        <a routerLink="/app/settings" routerLinkActive="active"><i>S</i>Settings</a>
      </nav>
      <div class="sidebar-status"><span><i></i>Evidence service online</span><small>Authorized scope · actions retained</small></div>
      <div class="sidebar-footer">
        <button class="theme-toggle" type="button" (click)="theme.toggle()" [attr.aria-label]="'Switch to ' + (theme.theme() === 'dark' ? 'light' : 'dark') + ' theme'"><span>{{ theme.theme() === 'dark' ? '☼' : '☾' }}</span>{{ theme.theme() === 'dark' ? 'Light theme' : 'Dark theme' }}</button>
        <div class="sidebar-user"><span class="user-avatar">{{ initials() }}</span><div><strong>{{ pocketbase.user()?.['name'] || pocketbase.user()?.['email'] || 'Workspace user' }}</strong><small>{{ roleLabel() }}</small></div><button type="button" aria-label="Sign out" (click)="signOut()">↗</button></div>
      </div>
    </aside>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppSidebarComponent implements OnInit, OnDestroy {
  protected readonly pocketbase = inject(PocketBaseService);
  protected readonly theme = inject(ThemeService);
  private readonly router = inject(Router);
  private timer?: ReturnType<typeof setTimeout>;
  protected readonly activeJobs = signal(0);
  ngOnInit(): void { void this.pocketbase.loadWorkspaceContext().finally(() => void this.refreshJobs()); }
  ngOnDestroy(): void { if (this.timer) clearTimeout(this.timer); }
  protected initials(): string {
    const label = String(this.pocketbase.user()?.['name'] || this.pocketbase.user()?.['email'] || 'AD');
    return label.split(/[\s@.]+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join('');
  }
  protected signOut(): void { this.pocketbase.signOut(); void this.router.navigateByUrl('/'); }
  protected switchWorkspace(workspaceId: string): void { this.pocketbase.activateWorkspace(workspaceId); window.location.assign('/app'); }
  protected roleLabel(): string {
    const role = this.pocketbase.activeWorkspaceRole();
    if (role === 'platform-admin') return 'Platform administrator';
    return role ? `${role[0]!.toUpperCase()}${role.slice(1)}` : 'Workspace member';
  }
  private async refreshJobs(): Promise<void> {
    try { const jobs = await this.pocketbase.scanRequests(); this.activeJobs.set(jobs.filter((job) => ['queued', 'processing', 'cancelling'].includes(job.status)).length); }
    catch { /* Page-level errors remain the primary error surface. */ }
    finally { this.timer = setTimeout(() => void this.refreshJobs(), 5_000); }
  }
}
