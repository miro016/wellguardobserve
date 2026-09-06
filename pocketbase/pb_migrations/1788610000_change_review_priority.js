/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const users = app.findCollectionByNameOrId('users');
  const targets = app.findCollectionByNameOrId('targets');
  const scans = app.findCollectionByNameOrId('scans');
  const worker = "@request.auth.active = true";
  const owner = "@request.auth.id != '' && target.owner = @request.auth.id";
  const adminOwner = "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id";

  targets.fields.add(new SelectField({ name: 'criticality', maxSelect: 1, values: ['critical', 'high', 'standard', 'low'] }));
  targets.fields.add(new JSONField({ name: 'tags', maxSize: 6000 }));
  targets.updateRule = `((${worker}) && @request.body.owner:changed = false && @request.body.hostname:changed = false && @request.body.hostHints:changed = false && @request.body.authorizationStatus:changed = false && @request.body.authorizationReason:changed = false && @request.body.authorizedAt:changed = false && @request.body.authorizationExpiresAt:changed = false && @request.body.allowPrivateAddresses:changed = false) || (@request.auth.id != '' && @request.auth.role = 'admin' && owner = @request.auth.id && @request.body.owner:changed = false && @request.body.hostname:changed = false && @request.body.hostHints:changed = false && @request.body.authorizationStatus:changed = false && @request.body.authorizationReason:changed = false && @request.body.authorizedAt:changed = false && @request.body.authorizationExpiresAt:changed = false && @request.body.allowPrivateAddresses:changed = false && @request.body.status:changed = false && @request.body.lastScanAt:changed = false && @request.body.assetCount:changed = false && @request.body.findingCount:changed = false && @request.body.posture:changed = false)`;
  app.save(targets);

  const findings = app.findCollectionByNameOrId('findings');
  findings.fields.add(new JSONField({ name: 'threatContext', maxSize: 10000 }));
  const immutableFindingFields = ['target', 'scan', 'title', 'summary', 'severity', 'confidence', 'asset', 'evidence', 'remediation', 'sourceUrls', 'cveIds', 'weaknessIds', 'frameworkRefs', 'customerNarrative', 'assetKey', 'relatedAssetKeys', 'relationKey', 'observations', 'runCount', 'threatContext'];
  findings.updateRule = `(${worker}) || (@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id && (@request.body.status = 'open' || @request.body.status = 'accepted' || @request.body.status = 'resolved') && ${immutableFindingFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  app.save(findings);

  const reviews = new Collection({
    type: 'base', name: 'changeReviews', listRule: `(${owner}) || (${worker})`, viewRule: `(${owner}) || (${worker})`,
    createRule: adminOwner,
    updateRule: `${adminOwner} && @request.body.target:changed = false && @request.body.scan:changed = false && @request.body.changeKey:changed = false`,
    deleteRule: adminOwner,
    fields: [
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'relation', name: 'scan', required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: 'text', name: 'changeKey', required: true, max: 620 },
      { type: 'select', name: 'status', required: true, maxSelect: 1, values: ['unreviewed', 'expected', 'investigate', 'resolved'] },
      { type: 'text', name: 'note', max: 1200 },
      { type: 'relation', name: 'reviewedBy', maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: 'date', name: 'reviewedAt' },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_change_review_key ON changeReviews (target, scan, changeKey)',
      'CREATE INDEX idx_change_review_status ON changeReviews (target, status, created)'
    ]
  });
  app.save(reviews);
}, (app) => {
  try { app.delete(app.findCollectionByNameOrId('changeReviews')); } catch (_) {}
  const findings = app.findCollectionByNameOrId('findings');
  try { findings.fields.removeByName('threatContext'); } catch (_) {}
  const worker = "@request.auth.active = true";
  const immutableFindingFields = ['target', 'scan', 'title', 'summary', 'severity', 'confidence', 'asset', 'evidence', 'remediation', 'sourceUrls', 'cveIds', 'weaknessIds', 'frameworkRefs', 'customerNarrative', 'assetKey', 'relatedAssetKeys', 'relationKey', 'observations', 'runCount'];
  findings.updateRule = `(${worker}) || (@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id && (@request.body.status = 'open' || @request.body.status = 'accepted' || @request.body.status = 'resolved') && ${immutableFindingFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  app.save(findings);
  const targets = app.findCollectionByNameOrId('targets');
  try { targets.fields.removeByName('criticality'); } catch (_) {}
  try { targets.fields.removeByName('tags'); } catch (_) {}
  targets.updateRule = "@request.auth.active = true && @request.body.owner:changed = false && @request.body.hostname:changed = false && @request.body.hostHints:changed = false && @request.body.authorizationStatus:changed = false && @request.body.authorizationReason:changed = false && @request.body.authorizedAt:changed = false && @request.body.authorizationExpiresAt:changed = false && @request.body.allowPrivateAddresses:changed = false";
  app.save(targets);
});
