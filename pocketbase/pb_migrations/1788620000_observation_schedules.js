/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const targets = app.findCollectionByNameOrId('targets');
  const requests = app.findCollectionByNameOrId('scanRequests');
  const worker = "@request.auth.collectionName = 'workers' && @request.auth.active = true";
  const owner = "@request.auth.collectionName = 'users' && @request.auth.id != '' && target.owner = @request.auth.id";
  const adminOwner = `${owner} && @request.auth.role = 'admin'`;

  const schedules = new Collection({
    type: 'base', name: 'observationSchedules',
    listRule: `(${owner}) || (${worker})`, viewRule: `(${owner}) || (${worker})`,
    createRule: `${adminOwner} && (@request.body.mode = 'light' || @request.body.mode = 'standard')`,
    updateRule: `(${adminOwner} && @request.body.target:changed = false) || ((${worker}) && @request.body.target:changed = false && (@request.body.enabled:changed = false || @request.body.enabled = false) && @request.body.cadence:changed = false && @request.body.mode:changed = false)`,
    deleteRule: adminOwner,
    fields: [
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'bool', name: 'enabled' },
      { type: 'select', name: 'cadence', required: true, maxSelect: 1, values: ['daily', 'weekly', 'monthly'] },
      { type: 'select', name: 'mode', required: true, maxSelect: 1, values: ['light', 'standard'] },
      { type: 'date', name: 'nextRunAt' },
      { type: 'date', name: 'lastQueuedAt' },
      { type: 'relation', name: 'lastRequest', maxSelect: 1, collectionId: requests.id, cascadeDelete: false },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_observation_schedule_target ON observationSchedules (target)',
      'CREATE INDEX idx_observation_schedule_due ON observationSchedules (enabled, nextRunAt)'
    ]
  });
  app.save(schedules);

  const ownerCreate = "@request.auth.collectionName = 'users' && @request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced' && @request.body.mode != 'unbounded') || @request.body.extendedConsent = true)";
  const scheduledCreate = `${worker} && @request.body.status = 'queued' && (@request.body.mode = 'light' || @request.body.mode = 'standard') && @request.body.extendedConsent = false`;
  requests.createRule = `(${ownerCreate}) || (${scheduledCreate})`;
  app.save(requests);
}, (app) => {
  try { app.delete(app.findCollectionByNameOrId('observationSchedules')); } catch (_) {}
  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced' && @request.body.mode != 'unbounded') || @request.body.extendedConsent = true)";
  app.save(requests);
});
