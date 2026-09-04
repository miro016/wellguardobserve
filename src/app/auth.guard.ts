import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { PocketBaseService } from './services/pocketbase.service';

export const authGuard: CanActivateFn = () => {
  const pocketbase = inject(PocketBaseService);
  return pocketbase.client.authStore.isValid ? true : inject(Router).parseUrl('/login');
};

export const adminGuard: CanActivateFn = () => {
  const pocketbase = inject(PocketBaseService);
  const router = inject(Router);
  if (!pocketbase.client.authStore.isValid) return router.parseUrl('/login');
  return pocketbase.isAdmin() ? true : router.parseUrl('/app');
};
