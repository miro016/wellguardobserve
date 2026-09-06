/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const users = app.findCollectionByNameOrId('users');
  const workers = app.findCollectionByNameOrId('workers');
  const workspaces = app.findCollectionByNameOrId('workspaces');
  const targets = app.findCollectionByNameOrId('targets');
  const scans = app.findCollectionByNameOrId('scans');
  const worker = `@request.auth.collectionName = 'workers' && @request.auth.active = true`;
  const globalAdmin = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @request.auth.role = 'admin'`;

  const generatedTools = new Collection({
    type: 'base', name: 'generatedTools',
    listRule: `(${globalAdmin}) || (${worker})`, viewRule: `(${globalAdmin}) || (${worker})`,
    createRule: `(${worker}) && @request.body.status = 'proposed' && @request.body.minProfile = 'unbounded'`,
    updateRule: `(${globalAdmin}) && (@request.body.status = 'proposed' || @request.body.status = 'approved' || @request.body.status = 'rejected' || @request.body.status = 'disabled') && @request.body.workspace:changed = false && @request.body.name:changed = false && @request.body.title:changed = false && @request.body.summary:changed = false && @request.body.rationale:changed = false && @request.body.category:changed = false && @request.body.evidence:changed = false && @request.body.spec:changed = false && @request.body.schemaVersion:changed = false && @request.body.checksum:changed = false && @request.body.compatibleProfiles:changed = false && @request.body.requestCeiling:changed = false && @request.body.riskLevel:changed = false && @request.body.generatedByModel:changed = false && @request.body.sourceScan:changed = false && @request.body.sourceTarget:changed = false && @request.body.reviewedBy = @request.auth.id`,
    deleteRule: null,
    fields: [
      { type: 'relation', name: 'workspace', required: true, maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true },
      { type: 'text', name: 'name', required: true, min: 3, max: 64, pattern: '^[a-z][a-z0-9-]+$' },
      { type: 'text', name: 'title', required: true, max: 160 },
      { type: 'text', name: 'summary', required: true, max: 500 },
      { type: 'text', name: 'rationale', required: true, max: 1000 },
      { type: 'select', name: 'category', required: true, maxSelect: 1, values: ['discovery', 'configuration', 'authentication', 'authorization', 'session', 'input-validation', 'client-side', 'api'] },
      { type: 'json', name: 'evidence', required: true, maxSize: 12000 },
      { type: 'json', name: 'spec', required: true, maxSize: 30000 },
      { type: 'text', name: 'schemaVersion', required: true, max: 40 },
      { type: 'text', name: 'checksum', required: true, min: 64, max: 64, pattern: '^[a-f0-9]{64}$' },
      { type: 'json', name: 'compatibleProfiles', required: true, maxSize: 2000 },
      { type: 'number', name: 'requestCeiling', required: true, min: 1, max: 12, onlyInt: true },
      { type: 'select', name: 'riskLevel', required: true, maxSelect: 1, values: ['passive', 'low', 'interactive'] },
      { type: 'select', name: 'status', required: true, maxSelect: 1, values: ['proposed', 'approved', 'rejected', 'disabled'] },
      { type: 'select', name: 'minProfile', required: true, maxSelect: 1, values: ['light', 'standard', 'extended', 'advanced', 'unbounded'] },
      { type: 'bool', name: 'unboundedAutoUse' },
      { type: 'text', name: 'generatedByModel', required: true, max: 160 },
      { type: 'relation', name: 'sourceScan', maxSelect: 1, collectionId: scans.id, cascadeDelete: false },
      { type: 'relation', name: 'sourceTarget', maxSelect: 1, collectionId: targets.id, cascadeDelete: false },
      { type: 'relation', name: 'reviewedBy', maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: 'date', name: 'reviewedAt' },
      { type: 'text', name: 'reviewNote', max: 1200 },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_generated_tool_checksum ON generatedTools (workspace, checksum)',
      'CREATE UNIQUE INDEX idx_generated_tool_name ON generatedTools (workspace, name)',
      'CREATE INDEX idx_generated_tool_status ON generatedTools (workspace, status, updated)'
    ]
  });
  app.save(generatedTools);

  const executions = new Collection({
    type: 'base', name: 'generatedToolExecutions',
    listRule: `(${globalAdmin}) || (${worker})`, viewRule: `(${globalAdmin}) || (${worker})`, createRule: worker, updateRule: null, deleteRule: null,
    fields: [
      { type: 'relation', name: 'workspace', required: true, maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true },
      { type: 'relation', name: 'tool', required: true, maxSelect: 1, collectionId: generatedTools.id, cascadeDelete: true },
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'relation', name: 'scan', required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: 'select', name: 'profile', required: true, maxSelect: 1, values: ['light', 'standard', 'extended', 'advanced', 'unbounded'] },
      { type: 'text', name: 'hostname', required: true, max: 255 },
      { type: 'select', name: 'status', required: true, maxSelect: 1, values: ['completed', 'blocked', 'failed'] },
      { type: 'number', name: 'requestCount', min: 0, max: 12, onlyInt: true },
      { type: 'number', name: 'matchedAssertions', min: 0, onlyInt: true },
      { type: 'text', name: 'summary', required: true, max: 3000 },
      { type: 'date', name: 'occurredAt', required: true },
      { type: 'autodate', name: 'created', onCreate: true }
    ],
    indexes: [
      'CREATE INDEX idx_generated_execution_workspace ON generatedToolExecutions (workspace, occurredAt)',
      'CREATE INDEX idx_generated_execution_tool ON generatedToolExecutions (tool, occurredAt)'
    ]
  });
  app.save(executions);
}, (app) => {
  for (const name of ['generatedToolExecutions', 'generatedTools']) {
    try { app.delete(app.findCollectionByNameOrId(name)); } catch (_) {}
  }
});
