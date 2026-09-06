import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AppSidebarComponent } from '../components/app-sidebar.component';
import { Target, WorkspaceMember, WorkspaceRole, WorkspaceUser } from '../models';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-workspaces',
  imports: [AppSidebarComponent, FormsModule],
  template: `
    <div class="app-layout"><wg-app-sidebar /><main class="app-main workspace-admin-page">
      <header class="app-header"><div><span class="app-breadcrumb">PLATFORM / ACCESS CONTROL</span><h1>Workspace governance</h1><p>Separate customer estates, assign people by responsibility, and keep every target inside an explicit security boundary.</p></div><span class="scope-lock">⌾ Platform administrator</span></header>
      @if (error()) { <div class="error-banner"><strong>Operation failed</strong><span>{{ error() }}</span></div> }
      @if (notice()) { <div class="success-banner"><strong>{{ notice() }}</strong><span>Workspace access rules are effective immediately.</span></div> }

      <section class="workspace-metrics">
        <article><small>WORKSPACES</small><strong>{{ db.workspaces().length }}</strong><span>{{ activeWorkspaceCount() }} active boundaries</span></article>
        <article><small>ASSIGNED SEATS</small><strong>{{ enabledMemberCount() }}</strong><span>{{ uniqueMemberCount() }} people</span></article>
        <article><small>AUTHORIZED TARGETS</small><strong>{{ targets().length }}</strong><span>Isolated by workspace</span></article>
        <article class="workspace-control-note"><i>ACL</i><div><strong>Least-privilege roles</strong><span>Viewer · Operator · Admin · Owner</span></div></article>
      </section>

      <section class="workspace-console">
        <aside class="panel workspace-ledger">
          <div class="panel-heading"><div><span class="section-index">BOUNDARY LEDGER</span><h2>Workspaces</h2></div><span class="evidence-count">{{ db.workspaces().length }} records</span></div>
          <div class="workspace-ledger-list">@for (workspace of db.workspaces(); track workspace.id) {
            <button type="button" [class.selected]="selectedWorkspaceId() === workspace.id" (click)="selectedWorkspaceId.set(workspace.id)">
              <span class="workspace-monogram">{{ workspace.name.slice(0, 2).toUpperCase() }}</span>
              <span><strong>{{ workspace.name }}</strong><small>{{ workspace.slug }} · {{ workspaceTargetCount(workspace.id) }} targets</small></span>
              <i [attr.data-status]="workspace.status"></i>
            </button>
          } @empty { <div class="empty-state"><strong>No workspace yet.</strong><span>Create the first customer boundary.</span></div> }</div>
          <form class="workspace-create" (ngSubmit)="createWorkspace()">
            <span class="section-index">NEW BOUNDARY</span>
            <label><span>Name</span><input name="workspaceName" [(ngModel)]="workspaceName" maxlength="160" placeholder="Acme production" required></label>
            <label><span>Slug</span><input name="workspaceSlug" [(ngModel)]="workspaceSlug" maxlength="80" placeholder="acme-production" required></label>
            <label><span>Purpose</span><textarea name="workspaceDescription" [(ngModel)]="workspaceDescription" maxlength="600" rows="3" placeholder="Customer production perimeter"></textarea></label>
            <button class="button primary compact" type="submit" [disabled]="busy()">Create workspace <span>+</span></button>
          </form>
        </aside>

        @if (selectedWorkspace(); as workspace) {
          <div class="workspace-detail">
            <section class="panel workspace-identity">
              <div><span class="workspace-monogram large">{{ workspace.name.slice(0, 2).toUpperCase() }}</span><div><span class="section-index">{{ workspace.slug }}</span><h2>{{ workspace.name }}</h2><p>{{ workspace.description || 'No internal workspace description has been recorded.' }}</p></div></div>
              <div class="workspace-status-control"><span class="state-pill" [attr.data-state]="workspace.status === 'active' ? 'healthy' : 'warning'">{{ workspace.status }}</span><button class="button secondary compact" type="button" (click)="toggleWorkspaceStatus(workspace.id, workspace.status)" [disabled]="busy()">{{ workspace.status === 'active' ? 'Archive' : 'Restore' }}</button></div>
            </section>

            <section class="panel access-matrix">
              <div class="panel-heading"><div><span class="section-index">ACCESS MATRIX</span><h2>{{ workspaceMembers().length }} assigned people</h2></div><span class="evidence-count">Role-based control</span></div>
              <div class="access-head"><span>Identity</span><span>Role</span><span>Observe</span><span>Operate</span><span>Govern</span><span>Status</span></div>
              @for (member of workspaceMembers(); track member.id) {
                <div class="access-row" [class.disabled]="!member.enabled">
                  <span class="member-identity"><i>{{ memberInitials(member) }}</i><span><strong>{{ member.userName || memberEmail(member) || member.user }}</strong><small>{{ memberEmail(member) || 'Email hidden on legacy account' }}</small></span></span>
                  <select [ngModel]="member.role" (ngModelChange)="changeMemberRole(member, $event)" [ngModelOptions]="{standalone:true}" [disabled]="busy()"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option><option value="owner">Owner</option></select>
                  <span class="permission granted">✓</span><span class="permission" [class.granted]="canOperate(member.role)">{{ canOperate(member.role) ? '✓' : '—' }}</span><span class="permission" [class.granted]="canGovern(member.role)">{{ canGovern(member.role) ? '✓' : '—' }}</span>
                  <button class="member-state" type="button" (click)="toggleMember(member)" [disabled]="busy()"><i [class.on]="member.enabled"></i>{{ member.enabled ? 'Active' : 'Suspended' }}</button>
                </div>
              } @empty { <div class="empty-state"><strong>No people assigned.</strong><span>Assign an existing account below.</span></div> }
              <form class="assignment-bar" (ngSubmit)="assignMember()"><label><span>Account</span><select name="assignUser" [(ngModel)]="assignUserId" required><option value="" disabled>Select an account</option>@for (user of assignableUsers(); track user.id) { <option [value]="user.id">{{ user.name || user.email }} · {{ user.email }}</option> }</select></label><label><span>Workspace role</span><select name="assignRole" [(ngModel)]="assignRole"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option><option value="owner">Owner</option></select></label><button class="button secondary compact" type="submit" [disabled]="busy() || !assignUserId">Assign account</button></form>
            </section>

            <section class="workspace-bottom-grid">
              <section class="panel workspace-targets"><div class="panel-heading"><div><span class="section-index">TARGET OWNERSHIP</span><h2>{{ workspaceTargets().length }} targets</h2></div><span class="evidence-count">Movable boundary</span></div>
                @for (target of workspaceTargets(); track target.id) { <div class="workspace-target-row"><span class="target-monogram">{{ target.hostname[0].toUpperCase() }}</span><span><strong>{{ target.hostname }}</strong><small>{{ target.name }} · {{ target.findingCount }} issues</small></span><label><span>Workspace</span><select [ngModel]="target.workspace" (ngModelChange)="moveTarget(target, $event)" [ngModelOptions]="{standalone:true}" [disabled]="busy()">@for (option of db.workspaces(); track option.id) { <option [value]="option.id">{{ option.name }}</option> }</select></label></div> }
                @empty { <div class="empty-state"><strong>No targets assigned.</strong><span>Add one from Target administration or move an existing target here.</span></div> }
              </section>

              <form class="panel invite-account" (ngSubmit)="createUser()"><div class="panel-heading"><div><span class="section-index">ACCOUNT PROVISIONING</span><h2>Create invited user</h2></div><span class="evidence-count">No public signup</span></div><div class="form-body"><label><span>Full name</span><input name="userName" [(ngModel)]="userName" maxlength="160" required></label><label><span>Email</span><input name="userEmail" [(ngModel)]="userEmail" type="email" autocomplete="off" required></label><label><span>Temporary password</span><input name="userPassword" [(ngModel)]="userPassword" type="password" minlength="10" autocomplete="new-password" required><small>Share through a separate secure channel. Wellguard does not retain this value in the UI.</small></label><button class="button primary compact" type="submit" [disabled]="busy()">Create account</button></div></form>
            </section>
          </div>
        } @else {
          <section class="panel workspace-zero"><span>00</span><h2>Create a workspace to establish the first customer boundary.</h2><p>Users and targets are never placed into an implicit shared estate.</p></section>
        }
      </section>
    </main></div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class WorkspacesComponent implements OnInit {
  protected readonly db = inject(PocketBaseService);
  protected readonly targets = signal<Target[]>([]);
  protected readonly users = signal<WorkspaceUser[]>([]);
  protected readonly selectedWorkspaceId = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly notice = signal('');
  protected readonly selectedWorkspace = computed(() => this.db.workspaces().find((workspace) => workspace.id === this.selectedWorkspaceId()) || null);
  protected readonly workspaceMembers = computed(() => this.db.memberships().filter((member) => member.workspace === this.selectedWorkspaceId()));
  protected readonly workspaceTargets = computed(() => this.targets().filter((target) => target.workspace === this.selectedWorkspaceId()));
  protected readonly assignableUsers = computed(() => {
    const assigned = new Set(this.workspaceMembers().map((member) => member.user));
    return this.users().filter((user) => !assigned.has(user.id));
  });
  protected readonly activeWorkspaceCount = computed(() => this.db.workspaces().filter((workspace) => workspace.status === 'active').length);
  protected readonly enabledMemberCount = computed(() => this.db.memberships().filter((member) => member.enabled).length);
  protected readonly uniqueMemberCount = computed(() => new Set(this.db.memberships().filter((member) => member.enabled).map((member) => member.user)).size);

  protected workspaceName = ''; protected workspaceSlug = ''; protected workspaceDescription = '';
  protected userName = ''; protected userEmail = ''; protected userPassword = '';
  protected assignUserId = ''; protected assignRole: WorkspaceRole = 'viewer';

  ngOnInit(): void { void this.refresh(); }
  protected workspaceTargetCount(id: string): number { return this.targets().filter((target) => target.workspace === id).length; }
  protected canOperate(role: WorkspaceRole): boolean { return role !== 'viewer'; }
  protected canGovern(role: WorkspaceRole): boolean { return role === 'owner' || role === 'admin'; }
  protected memberInitials(member: WorkspaceMember): string { return (member.userName || member.userEmail || 'U').split(/[\s@.]+/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join(''); }
  protected memberEmail(member: WorkspaceMember): string { return member.userEmail || this.users().find((user) => user.id === member.user)?.email || ''; }

  private async refresh(preferredWorkspace = ''): Promise<void> {
    this.error.set('');
    try {
      await this.db.loadWorkspaceContext(true);
      const [targets, users] = await Promise.all([this.db.targets('all'), this.db.workspaceUsers()]);
      this.targets.set(targets); this.users.set(users);
      const current = preferredWorkspace || this.selectedWorkspaceId() || this.db.activeWorkspaceId();
      this.selectedWorkspaceId.set(this.db.workspaces().some((workspace) => workspace.id === current) ? current : this.db.workspaces()[0]?.id || '');
      if (!this.assignableUsers().some((user) => user.id === this.assignUserId)) this.assignUserId = this.assignableUsers()[0]?.id || '';
    } catch (error) { this.error.set(error instanceof Error ? error.message : 'Workspace records could not be loaded.'); }
  }

  protected async createWorkspace(): Promise<void> {
    this.resetMessages();
    const slug = this.workspaceSlug.trim().toLowerCase();
    if (!this.workspaceName.trim() || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) { this.error.set('Enter a workspace name and a lowercase URL-safe slug.'); return; }
    await this.perform(async () => {
      const workspace = await this.db.createWorkspace({ name: this.workspaceName, slug, description: this.workspaceDescription });
      this.workspaceName = ''; this.workspaceSlug = ''; this.workspaceDescription = '';
      this.notice.set(`${workspace.name} was created.`); await this.refresh(workspace.id);
    });
  }

  protected async createUser(): Promise<void> {
    this.resetMessages();
    if (!this.userName.trim() || !this.userEmail.trim() || this.userPassword.length < 10) { this.error.set('Enter a name, valid email, and a temporary password of at least 10 characters.'); return; }
    await this.perform(async () => {
      const user = await this.db.createWorkspaceUser({ name: this.userName, email: this.userEmail, password: this.userPassword });
      this.userName = ''; this.userEmail = ''; this.userPassword = '';
      this.notice.set(`${user.email} was provisioned and can now be assigned.`); await this.refresh(this.selectedWorkspaceId());
    });
  }

  protected async assignMember(): Promise<void> {
    this.resetMessages(); const workspace = this.selectedWorkspaceId(); if (!workspace || !this.assignUserId) return;
    await this.perform(async () => { await this.db.addWorkspaceMember(workspace, this.assignUserId, this.assignRole); this.notice.set('Workspace access was assigned.'); await this.refresh(workspace); });
  }

  protected async changeMemberRole(member: WorkspaceMember, role: WorkspaceRole): Promise<void> {
    this.resetMessages(); await this.perform(async () => { await this.db.updateWorkspaceMember(member.id, role, member.enabled); this.notice.set('Member role was updated.'); });
  }

  protected async toggleMember(member: WorkspaceMember): Promise<void> {
    this.resetMessages(); await this.perform(async () => { await this.db.updateWorkspaceMember(member.id, member.role, !member.enabled); this.notice.set(member.enabled ? 'Workspace access was suspended.' : 'Workspace access was restored.'); });
  }

  protected async toggleWorkspaceStatus(id: string, status: 'active' | 'archived'): Promise<void> {
    this.resetMessages(); await this.perform(async () => { await this.db.updateWorkspaceStatus(id, status === 'active' ? 'archived' : 'active'); this.notice.set(status === 'active' ? 'Workspace was archived.' : 'Workspace was restored.'); await this.refresh(id); });
  }

  protected async moveTarget(target: Target, workspace: string): Promise<void> {
    if (target.workspace === workspace) return;
    this.resetMessages(); await this.perform(async () => { await this.db.moveTargetToWorkspace(target.id, workspace); this.notice.set(`${target.hostname} was moved to a new workspace.`); await this.refresh(this.selectedWorkspaceId()); });
  }

  private resetMessages(): void { this.error.set(''); this.notice.set(''); }
  private async perform(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    try { await action(); } catch (error) { this.error.set(error instanceof Error ? error.message : 'The workspace operation failed.'); }
    finally { this.busy.set(false); }
  }
}
