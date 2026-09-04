import { Injectable, signal } from '@angular/core';
export type Theme = 'light' | 'dark';

@Injectable({ providedIn: 'root' })
export class ThemeService {
  readonly theme = signal<Theme>('dark');
  constructor() {
    const stored = localStorage.getItem('wellguard-theme') as Theme | null;
    const preferred: Theme = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    this.set(stored === 'light' || stored === 'dark' ? stored : preferred);
  }
  toggle(): void { this.set(this.theme() === 'dark' ? 'light' : 'dark'); }
  set(theme: Theme): void {
    this.theme.set(theme);
    document.documentElement.dataset['theme'] = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem('wellguard-theme', theme);
  }
}
