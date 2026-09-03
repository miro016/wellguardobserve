import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { PocketBaseService } from '../services/pocketbase.service';

@Component({
  selector: 'wg-login',
  imports: [FormsModule, RouterLink],
  template: `
    <main class="login-shell">
      <a class="wordmark login-wordmark" routerLink="/"><span class="brand-mark"><i></i></span><span>wellguard<em>observe</em></span></a>
      <section class="login-panel">
        <div class="login-context">
          <span class="section-index">Private preview</span>
          <h1>Return to your<br><em>public edge.</em></h1>
          <p>Accounts are issued by an administrator during the private preview.</p>
          <div class="login-radar"><i></i><i></i><i></i><span>scope locked</span></div>
        </div>
        <form class="login-form" (ngSubmit)="submit()">
          <div><span class="eyebrow"><span class="pulse-dot"></span> Investigator access</span><h2>Sign in</h2><p>Use the account created for you.</p></div>
          <label>Email address<input class="input" type="email" name="email" autocomplete="email" [(ngModel)]="email" required placeholder="you@company.com"></label>
          <label>Password<input class="input" type="password" name="password" autocomplete="current-password" [(ngModel)]="password" required placeholder="••••••••••••"></label>
          @if (error()) { <div class="form-error">{{ error() }}</div> }
          <button class="button button-primary login-submit" type="submit" [disabled]="busy()">{{ busy() ? 'Checking access…' : 'Enter workspace' }} <span>→</span></button>
          <p class="login-note">No account? Ask the preview administrator for access.</p>
        </form>
      </section>
    </main>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LoginComponent {
  private readonly pocketbase = inject(PocketBaseService);
  private readonly router = inject(Router);
  protected email = '';
  protected password = '';
  protected readonly busy = signal(false);
  protected readonly error = signal('');

  protected async submit(): Promise<void> {
    this.busy.set(true); this.error.set('');
    try {
      await this.pocketbase.signIn(this.email, this.password);
      await this.router.navigateByUrl('/app');
    } catch {
      this.error.set('Those credentials did not match an issued account.');
    } finally {
      this.busy.set(false);
    }
  }
}
