/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const users = app.findCollectionByNameOrId('users');
  const targets = app.findCollectionByNameOrId('targets');
  const globalAdmin = "@request.auth.collectionName = 'users' && @request.auth.id != '' && @request.auth.role = 'admin'";
  const worker = "@request.auth.collectionName = 'workers' && @request.auth.active = true";

  const workspaces = new Collection({
    type: 'base', name: 'workspaces',
    listRule: globalAdmin,
    viewRule: globalAdmin,
    createRule: globalAdmin,
    updateRule: `${globalAdmin} && @request.body.createdBy:changed = false`,
    deleteRule: globalAdmin,
    fields: [
      { type: 'text', name: 'name', required: true, max: 160 },
      { type: 'text', name: 'slug', required: true, max: 80, pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
      { type: 'text', name: 'description', max: 600 },
      { type: 'select', name: 'status', required: true, maxSelect: 1, values: ['active', 'archived'] },
      { type: 'relation', name: 'createdBy', required: true, maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_workspaces_slug ON workspaces (slug)',
      'CREATE INDEX idx_workspaces_status ON workspaces (status, created)'
    ]
  });
  app.save(workspaces);

  const workspaceMembers = new Collection({
    type: 'base', name: 'workspaceMembers',
    listRule: `(${globalAdmin}) || (@request.auth.collectionName = 'users' && @request.auth.id != '' && user = @request.auth.id)`,
    viewRule: `(${globalAdmin}) || (@request.auth.collectionName = 'users' && @request.auth.id != '' && user = @request.auth.id)`,
    createRule: globalAdmin,
    updateRule: `${globalAdmin} && @request.body.workspace:changed = false && @request.body.user:changed = false`,
    deleteRule: globalAdmin,
    fields: [
      { type: 'relation', name: 'workspace', required: true, maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true },
      { type: 'relation', name: 'user', required: true, maxSelect: 1, collectionId: users.id, cascadeDelete: true },
      { type: 'select', name: 'role', required: true, maxSelect: 1, values: ['owner', 'admin', 'operator', 'viewer'] },
      { type: 'bool', name: 'enabled' },
      { type: 'autodate', name: 'created', onCreate: true },
      { type: 'autodate', name: 'updated', onCreate: true, onUpdate: true }
    ],
    indexes: [
      'CREATE UNIQUE INDEX idx_workspace_members_unique ON workspaceMembers (workspace, user)',
      'CREATE INDEX idx_workspace_members_user ON workspaceMembers (user, enabled)'
    ]
  });
  app.save(workspaceMembers);

  const memberForWorkspace = "@request.auth.collectionName = 'users' && @request.auth.id != '' && @collection.workspaceMembers:membership.workspace ?= id && @collection.workspaceMembers:membership.user ?= @request.auth.id && @collection.workspaceMembers:membership.enabled ?= true";
  workspaces.listRule = `(${globalAdmin}) || (${memberForWorkspace})`;
  workspaces.viewRule = workspaces.listRule;
  app.save(workspaces);

  targets.fields.add(new RelationField({ name: 'workspace', maxSelect: 1, collectionId: workspaces.id, cascadeDelete: true }));
  targets.indexes = targets.indexes.filter((index) => !index.includes('idx_targets_hostname_owner'));
  app.save(targets);

  const personalWorkspaceByOwner = {};
  for (const target of app.findAllRecords('targets')) {
    const ownerId = String(target.get('owner') || '');
    let workspaceId = personalWorkspaceByOwner[ownerId];
    if (!workspaceId) {
      let ownerLabel = 'Existing workspace';
      try {
        const ownerRecord = app.findRecordById('users', ownerId);
        ownerLabel = String(ownerRecord.get('name') || ownerRecord.get('email') || ownerLabel);
      } catch (_) {}
      const workspace = new Record(workspaces);
      workspace.set('name', `${ownerLabel} workspace`);
      workspace.set('slug', `personal-${ownerId.toLowerCase()}`);
      workspace.set('description', 'Workspace created automatically for existing authorized targets.');
      workspace.set('status', 'active');
      workspace.set('createdBy', ownerId);
      app.save(workspace);
      workspaceId = workspace.id;
      personalWorkspaceByOwner[ownerId] = workspaceId;

      const membership = new Record(workspaceMembers);
      membership.set('workspace', workspaceId);
      membership.set('user', ownerId);
      membership.set('role', 'owner');
      membership.set('enabled', true);
      app.save(membership);
    }
    target.set('workspace', workspaceId);
    app.save(target);
  }

  targets.fields.getByName('workspace').required = true;
  targets.indexes = [
    ...targets.indexes,
    'CREATE UNIQUE INDEX idx_targets_hostname_workspace ON targets (hostname, workspace)',
    'CREATE INDEX idx_targets_workspace ON targets (workspace, created)'
  ];

  const memberForTarget = "@request.auth.collectionName = 'users' && @request.auth.id != '' && @collection.workspaceMembers:membership.workspace ?= workspace && @collection.workspaceMembers:membership.user ?= @request.auth.id && @collection.workspaceMembers:membership.enabled ?= true";
  const managerForTarget = `${memberForTarget} && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin')`;
  const operatorForTarget = `${memberForTarget} && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin' || @collection.workspaceMembers:membership.role ?= 'operator')`;
  const memberForChild = "@request.auth.collectionName = 'users' && @request.auth.id != '' && @collection.workspaceMembers:membership.workspace ?= target.workspace && @collection.workspaceMembers:membership.user ?= @request.auth.id && @collection.workspaceMembers:membership.enabled ?= true";
  const managerForChild = `${memberForChild} && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin')`;
  const operatorForChild = `${memberForChild} && target.workspace.status = 'active' && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin' || @collection.workspaceMembers:membership.role ?= 'operator')`;

  targets.listRule = `(${globalAdmin}) || (${worker}) || (${memberForTarget})`;
  targets.viewRule = targets.listRule;
  targets.createRule = `${globalAdmin} && @request.body.owner = @request.auth.id && @request.body.workspace != '' && @request.body.authorizationStatus = 'admin_override' && @request.body.allowPrivateAddresses = false`;
  const workerTargetImmutable = ['owner', 'workspace', 'name', 'hostname', 'hostHints', 'authorizationStatus', 'authorizationReason', 'authorizedAt', 'authorizationExpiresAt', 'allowPrivateAddresses', 'criticality', 'tags'];
  const managerTargetImmutable = ['owner', 'workspace', 'hostname', 'hostHints', 'authorizationStatus', 'authorizationReason', 'authorizedAt', 'authorizationExpiresAt', 'allowPrivateAddresses', 'status', 'lastScanAt', 'assetCount', 'findingCount', 'posture'];
  const globalTargetImmutable = ['owner', 'hostname', 'hostHints', 'authorizationStatus', 'authorizationReason', 'authorizedAt', 'authorizationExpiresAt', 'allowPrivateAddresses', 'status', 'lastScanAt', 'assetCount', 'findingCount', 'posture'];
  targets.updateRule = `((${worker}) && ${workerTargetImmutable.map((field) => `@request.body.${field}:changed = false`).join(' && ')}) || ((${managerForTarget}) && ${managerTargetImmutable.map((field) => `@request.body.${field}:changed = false`).join(' && ')}) || ((${globalAdmin}) && ${globalTargetImmutable.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  targets.deleteRule = null;
  app.save(targets);

  users.listRule = `(id = @request.auth.id) || (${globalAdmin})`;
  users.viewRule = users.listRule;
  users.createRule = `${globalAdmin} && @request.body.role = 'member'`;
  users.updateRule = `(id = @request.auth.id && @request.body.role:changed = false) || ((${globalAdmin}) && @request.body.role:changed = false)`;
  users.deleteRule = null;
  app.save(users);

  const childNames = ['scanRequests', 'scans', 'findings', 'tlsObservations', 'agentActions', 'agentMessages', 'targetScopes', 'assets', 'assetRelations', 'publicIdentities', 'knowledgeObservations', 'changeReviews', 'observationSchedules'];
  for (const name of childNames) {
    const collection = app.findCollectionByNameOrId(name);
    collection.listRule = `(${globalAdmin}) || (${worker}) || (${memberForChild})`;
    collection.viewRule = collection.listRule;
    app.save(collection);
  }

  const requests = app.findCollectionByNameOrId('scanRequests');
  const ownerCreate = `${operatorForChild} && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced' && @request.body.mode != 'unbounded') || @request.body.extendedConsent = true)`;
  const scheduledCreate = `${worker} && target.workspace.status = 'active' && @request.body.status = 'queued' && (@request.body.mode = 'light' || @request.body.mode = 'standard') && @request.body.extendedConsent = false`;
  requests.createRule = `((${globalAdmin}) && target.workspace.status = 'active' && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced' && @request.body.mode != 'unbounded') || @request.body.extendedConsent = true)) || (${ownerCreate}) || (${scheduledCreate})`;
  requests.updateRule = `((${worker}) && @request.body.target:changed = false && @request.body.mode:changed = false) || (((${globalAdmin}) || (${operatorForChild})) && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled') && @request.body.target:changed = false && @request.body.mode:changed = false)`;
  app.save(requests);

  for (const name of ['scans', 'tlsObservations', 'agentActions', 'agentMessages', 'assets', 'assetRelations', 'knowledgeObservations']) {
    const collection = app.findCollectionByNameOrId(name);
    collection.createRule = worker;
    collection.updateRule = worker;
    collection.deleteRule = null;
    app.save(collection);
  }

  const findings = app.findCollectionByNameOrId('findings');
  const immutableFindingFields = ['target', 'scan', 'title', 'summary', 'severity', 'confidence', 'asset', 'evidence', 'remediation', 'sourceUrls', 'cveIds', 'weaknessIds', 'frameworkRefs', 'customerNarrative', 'assetKey', 'relatedAssetKeys', 'relationKey', 'observations', 'runCount', 'threatContext'];
  findings.updateRule = `(${worker}) || (((${globalAdmin}) || (${managerForChild})) && (@request.body.status = 'open' || @request.body.status = 'accepted' || @request.body.status = 'resolved') && ${immutableFindingFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  app.save(findings);

  const scopes = app.findCollectionByNameOrId('targetScopes');
  scopes.createRule = `((${globalAdmin}) || (${managerForChild})) && @request.body.kind = 'exact_host'`;
  scopes.updateRule = `((${globalAdmin}) || (${managerForChild})) && @request.body.target:changed = false && @request.body.hostname:changed = false && @request.body.kind:changed = false`;
  scopes.deleteRule = `(${globalAdmin}) || (${managerForChild})`;
  app.save(scopes);

  const identities = app.findCollectionByNameOrId('publicIdentities');
  const immutableIdentityFields = ['target', 'scan', 'key', 'kind', 'displayName', 'email', 'publicLinks', 'sourceUrls', 'evidence', 'sourceAssetKey', 'confidence'];
  identities.updateRule = `(${worker}) || (((${globalAdmin}) || (${managerForChild})) && ${immutableIdentityFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  identities.deleteRule = `(${globalAdmin}) || (${managerForChild})`;
  app.save(identities);

  const reviews = app.findCollectionByNameOrId('changeReviews');
  reviews.createRule = `(${globalAdmin}) || (${managerForChild})`;
  reviews.updateRule = `((${globalAdmin}) || (${managerForChild})) && @request.body.target:changed = false && @request.body.scan:changed = false && @request.body.changeKey:changed = false`;
  reviews.deleteRule = `(${globalAdmin}) || (${managerForChild})`;
  app.save(reviews);

  const schedules = app.findCollectionByNameOrId('observationSchedules');
  schedules.createRule = `((${globalAdmin}) || (${managerForChild})) && (@request.body.mode = 'light' || @request.body.mode = 'standard')`;
  schedules.updateRule = `(((${globalAdmin}) || (${managerForChild})) && @request.body.target:changed = false) || ((${worker}) && @request.body.target:changed = false && (@request.body.enabled:changed = false || @request.body.enabled = false) && @request.body.cadence:changed = false && @request.body.mode:changed = false)`;
  schedules.deleteRule = `(${globalAdmin}) || (${managerForChild})`;
  app.save(schedules);
}, (app) => {
  const legacyWorker = "@request.auth.active = true";
  const legacyOwner = "@request.auth.id != '' && target.owner = @request.auth.id";
  const legacyAdminOwner = "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id";
  const legacyChildRead = `(${legacyOwner}) || (${legacyWorker})`;

  const childNames = ['scanRequests', 'scans', 'findings', 'tlsObservations', 'agentActions', 'agentMessages', 'targetScopes', 'assets', 'assetRelations', 'publicIdentities', 'knowledgeObservations', 'changeReviews'];
  for (const name of childNames) {
    const collection = app.findCollectionByNameOrId(name);
    collection.listRule = legacyChildRead;
    collection.viewRule = legacyChildRead;
    app.save(collection);
  }

  const requests = app.findCollectionByNameOrId('scanRequests');
  const legacyUserRequest = "@request.auth.collectionName = 'users' && @request.auth.id != '' && target.owner = @request.auth.id";
  const legacyWorkerRequest = "@request.auth.collectionName = 'workers' && @request.auth.active = true";
  requests.createRule = `((${legacyUserRequest}) && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced' && @request.body.mode != 'unbounded') || @request.body.extendedConsent = true)) || ((${legacyWorkerRequest}) && @request.body.status = 'queued' && (@request.body.mode = 'light' || @request.body.mode = 'standard') && @request.body.extendedConsent = false)`;
  requests.updateRule = `((${legacyWorkerRequest}) && @request.body.target:changed = false && @request.body.mode:changed = false && @request.body.extendedConsent:changed = false) || ((${legacyUserRequest}) && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled') && @request.body.target:changed = false && @request.body.mode:changed = false && @request.body.extendedConsent:changed = false)`;
  app.save(requests);

  for (const name of ['scans', 'tlsObservations', 'agentActions', 'agentMessages', 'assets', 'assetRelations']) {
    const collection = app.findCollectionByNameOrId(name);
    collection.createRule = legacyWorker;
    collection.updateRule = legacyWorker;
    collection.deleteRule = null;
    app.save(collection);
  }
  const knowledge = app.findCollectionByNameOrId('knowledgeObservations');
  knowledge.createRule = legacyWorker;
  knowledge.updateRule = null;
  knowledge.deleteRule = null;
  app.save(knowledge);

  const findings = app.findCollectionByNameOrId('findings');
  const immutableFindingFields = ['target', 'scan', 'title', 'summary', 'severity', 'confidence', 'asset', 'evidence', 'remediation', 'sourceUrls', 'cveIds', 'weaknessIds', 'frameworkRefs', 'customerNarrative', 'assetKey', 'relatedAssetKeys', 'relationKey', 'observations', 'runCount', 'threatContext'];
  findings.updateRule = `(${legacyWorker}) || (${legacyAdminOwner} && (@request.body.status = 'open' || @request.body.status = 'accepted' || @request.body.status = 'resolved') && ${immutableFindingFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')})`;
  app.save(findings);

  const scopes = app.findCollectionByNameOrId('targetScopes');
  scopes.createRule = `${legacyAdminOwner} && @request.body.kind = 'exact_host'`;
  scopes.updateRule = `${legacyAdminOwner} && @request.body.target:changed = false && @request.body.hostname:changed = false && @request.body.kind:changed = false`;
  scopes.deleteRule = legacyAdminOwner;
  app.save(scopes);

  const identities = app.findCollectionByNameOrId('publicIdentities');
  const immutableIdentityFields = ['target', 'scan', 'key', 'kind', 'displayName', 'email', 'publicLinks', 'sourceUrls', 'evidence', 'sourceAssetKey', 'confidence'];
  identities.updateRule = `${legacyAdminOwner} && ${immutableIdentityFields.map((field) => `@request.body.${field}:changed = false`).join(' && ')}`;
  identities.deleteRule = legacyAdminOwner;
  app.save(identities);

  const reviews = app.findCollectionByNameOrId('changeReviews');
  reviews.createRule = legacyAdminOwner;
  reviews.updateRule = `${legacyAdminOwner} && @request.body.target:changed = false && @request.body.scan:changed = false && @request.body.changeKey:changed = false`;
  reviews.deleteRule = legacyAdminOwner;
  app.save(reviews);

  const scheduleUser = "@request.auth.collectionName = 'users' && @request.auth.id != '' && target.owner = @request.auth.id";
  const scheduleWorker = "@request.auth.collectionName = 'workers' && @request.auth.active = true";
  const schedules = app.findCollectionByNameOrId('observationSchedules');
  schedules.listRule = `(${scheduleUser}) || (${scheduleWorker})`;
  schedules.viewRule = schedules.listRule;
  schedules.createRule = `${scheduleUser} && @request.auth.role = 'admin' && (@request.body.mode = 'light' || @request.body.mode = 'standard')`;
  schedules.updateRule = `(${scheduleUser} && @request.auth.role = 'admin' && @request.body.target:changed = false) || ((${scheduleWorker}) && @request.body.target:changed = false && (@request.body.enabled:changed = false || @request.body.enabled = false) && @request.body.cadence:changed = false && @request.body.mode:changed = false)`;
  schedules.deleteRule = `${scheduleUser} && @request.auth.role = 'admin'`;
  app.save(schedules);

  const users = app.findCollectionByNameOrId('users');
  users.listRule = 'id = @request.auth.id';
  users.viewRule = users.listRule;
  users.createRule = null;
  users.updateRule = 'id = @request.auth.id && @request.body.role:changed = false';
  users.deleteRule = null;
  app.save(users);

  const targets = app.findCollectionByNameOrId('targets');
  targets.listRule = "(@request.auth.id != '' && owner = @request.auth.id) || (@request.auth.active = true)";
  targets.viewRule = targets.listRule;
  targets.createRule = "@request.auth.id != '' && @request.auth.role = 'admin' && @request.body.owner = @request.auth.id && @request.body.authorizationStatus = 'admin_override' && @request.body.allowPrivateAddresses = false";
  targets.updateRule = "((@request.auth.active = true) && @request.body.owner:changed = false && @request.body.hostname:changed = false && @request.body.hostHints:changed = false && @request.body.authorizationStatus:changed = false && @request.body.authorizationReason:changed = false && @request.body.authorizedAt:changed = false && @request.body.authorizationExpiresAt:changed = false && @request.body.allowPrivateAddresses:changed = false) || (@request.auth.id != '' && @request.auth.role = 'admin' && owner = @request.auth.id && @request.body.owner:changed = false && @request.body.hostname:changed = false && @request.body.hostHints:changed = false && @request.body.authorizationStatus:changed = false && @request.body.authorizationReason:changed = false && @request.body.authorizedAt:changed = false && @request.body.authorizationExpiresAt:changed = false && @request.body.allowPrivateAddresses:changed = false && @request.body.status:changed = false && @request.body.lastScanAt:changed = false && @request.body.assetCount:changed = false && @request.body.findingCount:changed = false && @request.body.posture:changed = false)";
  targets.deleteRule = null;
  targets.indexes = targets.indexes.filter((index) => !index.includes('idx_targets_hostname_workspace') && !index.includes('idx_targets_workspace'));
  try { targets.fields.removeByName('workspace'); } catch (_) {}
  targets.indexes = [...targets.indexes, 'CREATE UNIQUE INDEX idx_targets_hostname_owner ON targets (hostname, owner)'];
  app.save(targets);
  try { app.delete(app.findCollectionByNameOrId('workspaceMembers')); } catch (_) {}
  try { app.delete(app.findCollectionByNameOrId('workspaces')); } catch (_) {}
});
