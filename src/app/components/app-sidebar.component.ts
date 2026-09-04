import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive } from '@angular/router';
import { PocketBaseService } from '../services/pocketbase.service';
import { ThemeService } from '../services/theme.service';

@Component({
  selector: 'wg-app-sidebar',
  imports: [RouterLink, RouterLinkActive],
  template: `
    <aside class="app-sidebar">
      <a class="wordmark sidebar-wordmark" routerLink="/" aria-label="Wellguard Observe home"><span class="brand-mark"><i></i></span><span>WELLGUARD<em>OBSERVE</em></span></a>
      <div class="workspace-chip"><i></i><span><small>Workspace</small><strong>Private preview</strong></span></div>
      <nav class="app-navigation" aria-label="Workspace navigation">
        <span>Observe</span>
        <a routerLink="/app" routerLinkActive="active" [routerLinkActiveOptions]="{exact:true}"><i>⌂</i>Overview</a>
        <a routerLink="/app/targets" routerLinkActive="active"><i>◎</i>Targets</a>
        <a routerLink="/app/surface" routerLinkActive="active"><i>⌘</i>Surface map</a>
        <a routerLink="/app/findings" routerLinkActive="active"><i>△</i>Findings</a>
        <a routerLink="/app/reports" routerLinkActive="active"><i>▤</i>Reports</a>
        <span>Transparency</span>
        <a routerLink="/app/traces" routerLinkActive="active"><i>›_</i>Agent traces</a>
        <a routerLink="/app/sources" routerLinkActive="active"><i>⊙</i>Evidence sources</a>
        <span>Workspace</span>
        @if (pocketbase.isAdmin()) { <a routerLink="/app/admin" routerLinkActive="active"><i>⌁</i>Administration</a> }
        <a routerLink="/app/settings" routerLinkActive="active"><i>⚙</i>Settings</a>
      </nav>
      <div class="sidebar-status"><span><i></i>Observer ready</span><small>Recon only · scope locked</small></div>
      <div class="sidebar-footer">
        <button class="theme-toggle" type="button" (click)="theme.toggle()" [attr.aria-label]="'Switch to ' + (theme.theme() === 'dark' ? 'light' : 'dark') + ' theme'"><span>{{ theme.theme() === 'dark' ? '☼' : '☾' }}</span>{{ theme.theme() === 'dark' ? 'Light theme' : 'Dark theme' }}</button>
        <div class="sidebar-user"><span class="user-avatar">{{ initials() }}</span><div><strong>{{ pocketbase.user()?.['name'] || pocketbase.user()?.['email'] || 'Administrator' }}</strong><small>Administrator</small></div><button type="button" aria-label="Sign out" (click)="signOut()">↗</button></div>
      </div>
    </aside>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppSidebarComponent {
  protected readonly pocketbase = inject(PocketBaseService);
  protected readonly theme = inject(ThemeService);
  private readonly router = inject(Router);
  protected initials(): string {
    const label = String(this.pocketbase.user()?.['name'] || this.pocketbase.user()?.['email'] || 'AD');
    return label.split(/[\s@.]+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join('');
  }
  protected signOut(): void { this.pocketbase.signOut(); void this.router.navigateByUrl('/'); }
}
