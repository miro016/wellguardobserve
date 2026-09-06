/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const users = app.findCollectionByNameOrId('users');
  const workers = app.findCollectionByNameOrId('workers');
  const workspaces = app.findCollectionByNameOrId('workspaces');
  const targets = app.findCollectionByNameOrId('targets');
  const scans = app.findCollectionByNameOrId('scans');
  const findings = app.findCollectionByNameOrId('findings');
  const worker = `@request.auth.collectionName = 'workers' && @request.auth.active = true`;
  const globalAdmin = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @request.auth.role = 'admin'`;
  const member = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @collection.workspaceMembers:membership.workspace ?= workspace && @collection.workspaceMembers:membership.user ?= @request.auth.id && @collection.workspaceMembers:membership.enabled ?= true`;
  const manager = `${member} && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin')`;

  const cache = new Collection({
    type: 'base', name: 'externalSourceCache',
    listRule: `(${globalAdmin}) || (${worker})`, viewRule: `(${globalAdmin}) || (${worker})`, createRule: worker, updateRule: worker, deleteRule: globalAdmin,
    fields: [
      { type: 'text', name: 'cacheKey', required: true, max: 80 },
      { type: 'text', name: 'source', required: true, max: 160 },
      { type: 'select', name: 'method', required: true, maxSelect: 1, values: ['GET', 'POST'] },
      { type: 'url', name: 'url', required: true, exceptDomains: [] },
      { type: 'number', name: 'statusCode', required: true, min: 100, max: 599, onlyInt: true },
      { type: 'text', name: 'contentType', max: 250 },
      { type: 'text', name: 'body', required: true, max: 7000000 },
      { type: 'text', name: 'etag', max: 500 },
      { type: 'text', name: 'lastModified', max: 500 },
      { type: 'text', name: 'cacheControl', max: 500 },
      { type: 'date', name: 'expiresAt', required: true },
      { type: 'date', name: 'fetchedAt', required: true },
      { type: 'date', name: 'lastAccessedAt', required: true },
      { type: 'number', name: 'hitCount', min: 0, onlyInt: true },
      { type: 'number', name: 'revalidationCount', min: 0, onlyInt: true },
      { type: 'number', name: 'staleUseCount', min: 0, onlyInt: true },
      { type: 'number', name: 'originRequestCount', min: 0, onlyInt: true },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_external_cache_key ON externalSourceCache (cacheKey)',
      'CREATE INDEX idx_external_cache_expiry ON externalSourceCache (expiresAt)',
      'CREATE INDEX idx_external_cache_source ON externalSourceCache (source, lastAccessedAt)'
    ]
  });
  app.save(cache);

  const evaluations = new Collection({
    type: 'base', name: 'scanEvaluations',
    listRule: `(${globalAdmin}) || (${worker}) || (${member})`, viewRule: `(${globalAdmin}) || (${worker}) || (${member})`,
    createRule: worker, updateRule: null, deleteRule: null,
    fields: [
      { type: 'relation', name: 'workspace', required: true, maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true },
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'relation', name: 'scan', required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: 'text', name: 'model', max: 160 },
      { type: 'text', name: 'reasoningEffort', max: 30 },
      { type: 'text', name: 'profile', max: 60 },
      { type: 'number', name: 'qualityScore', min: 0, max: 100 },
      { type: 'number', name: 'toolSuccessRate', min: 0, max: 1 },
      { type: 'number', name: 'evidenceCoverage', min: 0, max: 1 },
      { type: 'number', name: 'sourceCoverage', min: 0, max: 1 },
      { type: 'number', name: 'assetLinkage', min: 0, max: 1 },
      { type: 'number', name: 'toolErrors', min: 0, onlyInt: true },
      { type: 'number', name: 'duplicateCalls', min: 0, onlyInt: true },
      { type: 'number', name: 'unknownServices', min: 0, onlyInt: true },
      { type: 'number', name: 'cacheHits', min: 0, onlyInt: true },
      { type: 'number', name: 'cacheMisses', min: 0, onlyInt: true },
      { type: 'number', name: 'originRequests', min: 0, onlyInt: true },
      { type: 'json', name: 'signals', maxSize: 30000 },
      { type: 'autodate', name: 'created', onCreate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_scan_evaluation_scan ON scanEvaluations (scan)',
      'CREATE INDEX idx_scan_evaluation_workspace ON scanEvaluations (workspace, created)'
    ]
  });
  app.save(evaluations);

  const feedback = new Collection({
    type: 'base', name: 'findingFeedback',
    listRule: `(${globalAdmin}) || (${worker}) || (${member})`, viewRule: `(${globalAdmin}) || (${worker}) || (${member})`,
    createRule: `((${globalAdmin}) || (${manager})) && target.workspace = workspace && finding.target = target && @request.body.reviewedBy = @request.auth.id`,
    updateRule: `((${globalAdmin}) || (${manager})) && target.workspace = workspace && finding.target = target && @request.body.workspace:changed = false && @request.body.target:changed = false && @request.body.finding:changed = false && @request.body.patternKey:changed = false && @request.body.reviewedBy = @request.auth.id`,
    deleteRule: `(${globalAdmin}) || (${manager})`,
    fields: [
      { type: 'relation', name: 'workspace', required: true, maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true },
      { type: 'relation', name: 'target', required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: 'relation', name: 'finding', required: true, maxSelect: 1, collectionId: findings.id, cascadeDelete: true },
      { type: 'text', name: 'patternKey', required: true, max: 500 },
      { type: 'select', name: 'verdict', required: true, maxSelect: 1, values: ['confirmed', 'false_positive', 'unclear'] },
      { type: 'text', name: 'note', max: 1200 },
      { type: 'relation', name: 'reviewedBy', required: true, maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_finding_feedback_reviewer ON findingFeedback (finding, reviewedBy)',
      'CREATE INDEX idx_finding_feedback_pattern ON findingFeedback (workspace, patternKey, verdict)'
    ]
  });
  app.save(feedback);

  const proposals = new Collection({
    type: 'base', name: 'improvementProposals',
    listRule: `(${globalAdmin}) || (${worker}) || (${member})`, viewRule: `(${globalAdmin}) || (${worker}) || (${member})`,
    createRule: worker,
    updateRule: `((${worker})) || (((${globalAdmin}) || (${manager})) && (@request.body.status = 'approved' || @request.body.status = 'rejected') && @request.body.workspace:changed = false && @request.body.proposalKey:changed = false && @request.body.kind:changed = false && @request.body.scopeKey:changed = false && @request.body.title:changed = false && @request.body.rationale:changed = false && @request.body.evidence:changed = false && @request.body.recommendedAction:changed = false && @request.body.parameter:changed = false && @request.body.confidence:changed = false && @request.body.occurrences:changed = false && @request.body.applicationCount:changed = false && @request.body.lastAppliedAt:changed = false && @request.body.reviewedBy = @request.auth.id)`,
    deleteRule: null,
    fields: [
      { type: 'relation', name: 'workspace', required: true, maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true },
      { type: 'text', name: 'proposalKey', required: true, max: 600 },
      { type: 'select', name: 'kind', required: true, maxSelect: 1, values: ['confidence_guard', 'coverage_priority', 'tool_reliability'] },
      { type: 'text', name: 'scopeKey', required: true, max: 500 },
      { type: 'text', name: 'title', required: true, max: 240 },
      { type: 'text', name: 'rationale', required: true, max: 1600 },
      { type: 'json', name: 'evidence', maxSize: 30000 },
      { type: 'select', name: 'recommendedAction', required: true, maxSelect: 1, values: ['cap-confidence', 'prioritize-unknown-service', 'review-tool'] },
      { type: 'json', name: 'parameter', maxSize: 10000 },
      { type: 'number', name: 'confidence', min: 0, max: 100 },
      { type: 'number', name: 'occurrences', min: 0, onlyInt: true },
      { type: 'select', name: 'status', required: true, maxSelect: 1, values: ['proposed', 'approved', 'rejected'] },
      { type: 'relation', name: 'reviewedBy', maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: 'date', name: 'reviewedAt' },
      { type: 'text', name: 'reviewNote', max: 1200 },
      { type: 'number', name: 'applicationCount', min: 0, onlyInt: true },
      { type: 'date', name: 'lastAppliedAt' },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_improvement_proposal ON improvementProposals (workspace, proposalKey)',
      'CREATE INDEX idx_improvement_status ON improvementProposals (workspace, status, updated)'
    ]
  });
  app.save(proposals);
}, (app) => {
  for (const name of ['improvementProposals', 'findingFeedback', 'scanEvaluations', 'externalSourceCache']) {
    try { app.delete(app.findCollectionByNameOrId(name)); } catch (_) {}
  }
});
