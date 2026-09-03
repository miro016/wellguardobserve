import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { PocketBaseService } from './services/pocketbase.service';

export const authGuard: CanActivateFn = () => {
  const pocketbase = inject(PocketBaseService);
  return pocketbase.client.authStore.isValid ? true : inject(Router).parseUrl('/login');
};
