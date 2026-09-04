import type { ScopeGuard } from '../security/scope-guard';
import { keycloakAdapter } from './keycloak';
import type { AdapterInput, ServiceAdapter } from './types';

const adapters: ServiceAdapter[] = [keycloakAdapter];

export function adapterCatalog() {
  return adapters.map((adapter) => adapter.manifest);
}

export async function inspectWithAdapter(scope: ScopeGuard, adapterId: string, input: AdapterInput) {
  const adapter = adapters.find((candidate) => candidate.manifest.id === adapterId);
  if (!adapter) throw new Error(`Unknown service adapter ${adapterId}. Available adapters: ${adapters.map((item) => item.manifest.id).join(', ')}.`);
  return await adapter.inspect(scope, input);
}
