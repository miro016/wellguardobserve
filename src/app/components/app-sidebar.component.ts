import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { Router, RouterLink, RouterLinkActive } from '@angular/router';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-app-sidebar',
  imports: [RouterLink, RouterLinkActive],
  template: `
    <aside class="app-sidebar" [class.mobile-open]="open()">
      <div class="sidebar-top">
        <a class="wordmark sidebar-wordmark" routerLink="/"><span class="brand-mark"><i></i></span><span>wellguard<em>observe</em></span></a>
        <span class="preview-badge">private preview</span>
      </div>
      <nav class="app-navigation" aria-label="Workspace">
        <span>Workspace</span>
        <a routerLink="/app" routerLinkActive="active" [routerLinkActiveOptions]="{exact:true}"><i class="nav-icon overview-icon"></i>Overview</a>
        <a routerLink="/app"><i class="nav-icon target-icon"></i>Targets <b>1</b></a>
        <a href="#"><i class="nav-icon finding-icon"></i>Findings <b>2</b></a>
        <a href="#"><i class="nav-icon trace-icon"></i>Agent traces</a>
        <span class="navigation-section">Manage</span>
        <a href="#"><i class="nav-icon integration-icon"></i>Sources</a>
        <a href="#"><i class="nav-icon settings-icon"></i>Settings</a>
      </nav>
      <div class="sidebar-scope">
        <div><span class="pulse-dot"></span><strong>Scan policy active</strong></div>
        <p>Reconnaissance only<br>1 authorized root</p>
      </div>
      <div class="sidebar-user">
        <span class="user-avatar">MP</span>
        <div><strong>{{ pocketbase.user()?.['name'] || 'Miroslav Petro' }}</strong><small>Administrator</small></div>
        <button type="button" aria-label="Sign out" (click)="signOut()">↗</button>
      </div>
    </aside>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppSidebarComponent {
  readonly open = input(false);
  protected readonly pocketbase = inject(PocketBaseService);
  private readonly router = inject(Router);

  protected signOut(): void {
    this.pocketbase.signOut();
    void this.router.navigateByUrl('/');
  }
}
