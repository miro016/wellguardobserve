export type WorkerObservationCadence = 'daily' | 'weekly' | 'monthly';

export function nextScheduledAt(cadence: WorkerObservationCadence, from = new Date()): string {
  const next = new Date(from);
  if (cadence === 'daily') next.setUTCDate(next.getUTCDate() + 1);
  if (cadence === 'weekly') next.setUTCDate(next.getUTCDate() + 7);
  if (cadence === 'monthly') {
    const day = next.getUTCDate();
    next.setUTCDate(1);
    next.setUTCMonth(next.getUTCMonth() + 1);
    const lastDay = new Date(Date.UTC(next.getUTCFullYear(), next.getUTCMonth() + 1, 0)).getUTCDate();
    next.setUTCDate(Math.min(day, lastDay));
  }
  return next.toISOString();
}
