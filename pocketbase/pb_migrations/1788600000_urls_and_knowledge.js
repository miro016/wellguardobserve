/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const assets = app.findCollectionByNameOrId('assets');
  const kind = assets.fields.getByName('kind');
  if (!kind.values.includes('url')) kind.values = [...kind.values, 'url'];
  app.save(assets);

  const targets = app.findCollectionByNameOrId('targets');
  const scans = app.findCollectionByNameOrId('scans');
  const worker = "@request.auth.active = true";
  const owner = "@request.auth.id != '' && target.owner = @request.auth.id";
  const findings = app.findCollectionByNameOrId('findings');
  const immutableFindingFields = ['target', 'scan', 'title', 'summary', 'severity', 'confidence', 'asset', 'evidence', 'remediation', 'sourceUrls', 'cveIds', 'weaknessIds', 'frameworkRefs', 'customerNarrative', 'assetKey', 'relatedAssetKeys', 'relationKey', 'observations', 'runCount'];
  findings.updateRule = `(${worker}) || (@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id && (@request.body.status = 'open' || @request.body.status = 'accepted' || @request.body.status = 'resolved') && ${immutableFindingFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  app.save(findings);
  const knowledgeObservations = new Collection({
    type: 'base', name: 'knowledgeObservations', listRule: `(${owner}) || (${worker})`, viewRule: `(${owner}) || (${worker})`,
    createRule: worker, updateRule: null, deleteRule: null,
    fields: [
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'relation', name: 'scan', required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: 'text', name: 'patternKey', required: true, max: 500 },
      { type: 'text', name: 'category', required: true, max: 120 },
      { type: 'text', name: 'technology', required: true, max: 160 },
      { type: 'text', name: 'findingTitle', required: true, max: 300 },
      { type: 'select', name: 'severity', required: true, maxSelect: 1, values: ['critical', 'high', 'medium', 'low', 'info'] },
      { type: 'text', name: 'assetKey', max: 500 },
      { type: 'text', name: 'assetKind', max: 80 },
      { type: 'json', name: 'weaknessIds', maxSize: 6000 },
      { type: 'json', name: 'frameworkControls', maxSize: 8000 },
      { type: 'json', name: 'configurationSignals', maxSize: 12000 },
      { type: 'date', name: 'observedAt', required: true },
      { type: 'autodate', name: 'created', onCreate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_knowledge_observation ON knowledgeObservations (scan, patternKey, assetKey, findingTitle)',
      'CREATE INDEX idx_knowledge_pattern ON knowledgeObservations (patternKey, observedAt)',
      'CREATE INDEX idx_knowledge_target ON knowledgeObservations (target, observedAt)'
    ]
  });
  app.save(knowledgeObservations);
}, (app) => {
  try { app.delete(app.findCollectionByNameOrId('knowledgeObservations')); } catch (_) {}
  const findings = app.findCollectionByNameOrId('findings');
  findings.updateRule = '@request.auth.active = true';
  app.save(findings);
  const assets = app.findCollectionByNameOrId('assets');
  const kind = assets.fields.getByName('kind');
  kind.values = kind.values.filter((value) => value !== 'url');
  app.save(assets);
});
