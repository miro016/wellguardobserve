import { Type } from '@angular/core';
import { Route, Routes } from '@angular/router';
import { adminGuard, authGuard } from './auth.guard';

const guarded = (path: string, loader: () => Promise<Type<unknown>>, title: string): Route => ({ path, canActivate: [authGuard], loadComponent: loader, title });

export const routes: Routes = [
  { path: '', loadComponent: () => import('./pages/landing.component').then((m) => m.LandingComponent), title: 'Wellguard Observe — External exposure intelligence' },
  { path: 'login', loadComponent: () => import('./pages/login.component').then((m) => m.LoginComponent), title: 'Sign in — Wellguard Observe' },
  guarded('app', () => import('./pages/dashboard.component').then((m) => m.DashboardComponent), 'Overview — Wellguard Observe'),
  guarded('app/targets', () => import('./pages/targets.component').then((m) => m.TargetsComponent), 'Targets — Wellguard Observe'),
  guarded('app/targets/:id', () => import('./pages/target-detail.component').then((m) => m.TargetDetailComponent), 'Target — Wellguard Observe'),
  guarded('app/investigations/:requestId', () => import('./pages/live-investigation.component').then((m) => m.LiveInvestigationComponent), 'Live investigation — Wellguard Observe'),
  guarded('app/surface', () => import('./pages/surface.component').then((m) => m.SurfaceComponent), 'Surface map — Wellguard Observe'),
  guarded('app/findings', () => import('./pages/findings.component').then((m) => m.FindingsComponent), 'Findings — Wellguard Observe'),
  guarded('app/identities', () => import('./pages/identities.component').then((m) => m.IdentitiesComponent), 'Identity exposure — Wellguard Observe'),
  guarded('app/reports', () => import('./pages/reports.component').then((m) => m.ReportsComponent), 'Reports — Wellguard Observe'),
  guarded('app/traces', () => import('./pages/traces.component').then((m) => m.TracesComponent), 'Agent traces — Wellguard Observe'),
  guarded('app/sources', () => import('./pages/sources.component').then((m) => m.SourcesComponent), 'Evidence sources — Wellguard Observe'),
  { path: 'app/admin', canActivate: [adminGuard], loadComponent: () => import('./pages/admin.component').then((m) => m.AdminComponent), title: 'Administration — Wellguard Observe' },
  guarded('app/settings', () => import('./pages/settings.component').then((m) => m.SettingsComponent), 'Settings — Wellguard Observe'),
  { path: '**', redirectTo: '' }
];
