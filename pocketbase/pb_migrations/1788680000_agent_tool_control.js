/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const users = app.findCollectionByNameOrId('users');
  const targets = app.findCollectionByNameOrId('targets');
  const scans = app.findCollectionByNameOrId('scans');
  const actions = app.findCollectionByNameOrId('agentActions');
  const generated = app.findCollectionByNameOrId('generatedTools');
  const worker = `@request.auth.collectionName = 'workers' && @request.auth.active = true`;
  const admin = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @request.auth.role = 'admin'`;

  const agentTools = new Collection({
    type: 'base', name: 'agentTools',
    listRule: `(${admin}) || (${worker})`, viewRule: `(${admin}) || (${worker})`,
    createRule: worker,
    updateRule: `(${worker}) || ((${admin}) && @request.body.name:changed = false && @request.body.title:changed = false && @request.body.summary:changed = false && @request.body.category:changed = false && @request.body.source:changed = false && @request.body.version:changed = false && @request.body.riskLevel:changed = false && @request.body.supportedProfiles:changed = false && @request.body.essential:changed = false)`,
    deleteRule: null,
    fields: [
      { type: 'text', name: 'name', required: true, min: 3, max: 80, pattern: '^[a-z][a-z0-9_]+$' },
      { type: 'text', name: 'title', required: true, max: 160 },
      { type: 'text', name: 'summary', required: true, max: 1000 },
      { type: 'text', name: 'category', required: true, max: 80 },
      { type: 'select', name: 'source', required: true, maxSelect: 1, values: ['wellguard', 'vanguard'] },
      { type: 'text', name: 'version', required: true, max: 100 },
      { type: 'select', name: 'riskLevel', required: true, maxSelect: 1, values: ['passive', 'low', 'interactive'] },
      { type: 'bool', name: 'enabled' },
      { type: 'json', name: 'profiles', required: true, maxSize: 2000 },
      { type: 'json', name: 'supportedProfiles', required: true, maxSize: 2000 },
      { type: 'bool', name: 'essential' },
      { type: 'relation', name: 'updatedBy', maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: ['CREATE UNIQUE INDEX idx_agent_tools_name ON agentTools (name)', 'CREATE INDEX idx_agent_tools_enabled ON agentTools (enabled, name)']
  });
  app.save(agentTools);

  const outputs = new Collection({
    type: 'base', name: 'toolOutputs',
    listRule: `(${admin}) || (${worker})`, viewRule: `(${admin}) || (${worker})`, createRule: worker, updateRule: null, deleteRule: null,
    fields: [
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'relation', name: 'scan', required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: 'relation', name: 'action', maxSelect: 1, collectionId: actions.id, cascadeDelete: true },
      { type: 'text', name: 'tool', required: true, max: 100 },
      { type: 'json', name: 'input', required: true, maxSize: 100000 },
      { type: 'json', name: 'output', required: true, maxSize: 1000000 },
      { type: 'text', name: 'outputSha256', required: true, min: 64, max: 64, pattern: '^[a-f0-9]{64}$' },
      { type: 'bool', name: 'failed' },
      { type: 'date', name: 'occurredAt', required: true },
      { type: 'autodate', name: 'created', onCreate: true }
    ],
    indexes: ['CREATE INDEX idx_tool_outputs_scan ON toolOutputs (scan, occurredAt)', 'CREATE INDEX idx_tool_outputs_tool ON toolOutputs (tool, occurredAt)']
  });
  app.save(outputs);

  actions.fields.getByName('summary').max = 28000;
  app.save(actions);

  generated.createRule = `((${worker}) && @request.body.status = 'proposed' && @request.body.minProfile = 'unbounded') || (${admin})`;
  generated.deleteRule = admin;
  app.save(generated);
}, (app) => {
  const generated = app.findCollectionByNameOrId('generatedTools');
  const worker = `@request.auth.collectionName = 'workers' && @request.auth.active = true`;
  generated.createRule = `(${worker}) && @request.body.status = 'proposed' && @request.body.minProfile = 'unbounded'`;
  generated.deleteRule = null;
  app.save(generated);
  const actions = app.findCollectionByNameOrId('agentActions');
  actions.fields.getByName('summary').max = 5000;
  app.save(actions);
  for (const name of ['toolOutputs', 'agentTools']) {
    try { app.delete(app.findCollectionByNameOrId(name)); } catch (_) {}
  }
});
