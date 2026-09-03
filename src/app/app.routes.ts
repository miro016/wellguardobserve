import { Routes } from '@angular/router';
import { authGuard } from './auth.guard';

export const routes: Routes = [
  {
    path: '',
    loadComponent: () => import('./pages/landing.component').then((m) => m.LandingComponent),
    title: 'Wellguard Observe — Know what the internet can see'
  },
  {
    path: 'login',
    loadComponent: () => import('./pages/login.component').then((m) => m.LoginComponent),
    title: 'Sign in — Wellguard Observe'
  },
  {
    path: 'app',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/dashboard.component').then((m) => m.DashboardComponent),
    title: 'Overview — Wellguard Observe'
  },
  {
    path: 'app/targets/:id',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/target-detail.component').then((m) => m.TargetDetailComponent),
    title: 'Target — Wellguard Observe'
  },
  { path: '**', redirectTo: '' }
];
