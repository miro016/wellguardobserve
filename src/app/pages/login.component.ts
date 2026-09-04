import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { PocketBaseService } from '../services/pocketbase.service';
import { ThemeService } from '../services/theme.service';

@Component({
  selector: 'wg-login',
  imports: [FormsModule, RouterLink],
  template: `
    <main class="login-shell">
      <header class="login-nav"><a class="wordmark login-wordmark" routerLink="/"><span class="brand-mark"><i></i></span><span>WELLGUARD<em>OBSERVE</em></span></a><button class="icon-button theme-icon" type="button" (click)="theme.toggle()">{{ theme.theme() === 'dark' ? '☼' : '☾' }}</button></header>
      <section class="login-panel">
        <div class="login-context">
          <span class="section-index">SECURE WORKSPACE</span>
          <h1>Return to your<br><span>outside view.</span></h1>
          <p>Review the current surface model, evidence-backed findings, and complete investigator trace.</p>
          <div class="login-signal"><div><i></i><span><small>OBSERVER</small><strong>Ready</strong></span></div><div><i></i><span><small>SCOPE</small><strong>Locked</strong></span></div><div><i></i><span><small>MODE</small><strong>Recon only</strong></span></div></div>
        </div>
        <form class="login-form" (ngSubmit)="submit()">
          <div><span class="eyebrow"><span class="pulse-dot"></span>Administrator-issued access</span><h2>Sign in</h2><p>Enter the account created for this private workspace.</p></div>
          <label>Email address<input class="input" type="email" name="email" autocomplete="email" [(ngModel)]="email" required placeholder="you@company.com"></label>
          <label>Password<input class="input" type="password" name="password" autocomplete="current-password" [(ngModel)]="password" required placeholder="••••••••••••"></label>
          @if (error()) { <div class="form-error">{{ error() }}</div> }
          <button class="button primary login-submit" type="submit" [disabled]="busy()">{{ busy() ? 'Checking access…' : 'Enter workspace' }} <span>→</span></button>
          <p class="login-note">No account? Ask the preview administrator for access.</p>
        </form>
      </section>
    </main>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LoginComponent {
  private readonly pocketbase = inject(PocketBaseService);
  protected readonly theme = inject(ThemeService);
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
