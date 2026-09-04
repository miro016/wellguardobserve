migrate((app) => {
  const users = app.findCollectionByNameOrId("users");
  users.updateRule = "id = @request.auth.id && @request.body.role:changed = false";
  app.save(users);

  const workers = new Collection({
    type: "auth",
    name: "workers",
    listRule: null,
    viewRule: null,
    createRule: null,
    updateRule: null,
    deleteRule: null,
    authRule: "active = true",
    passwordAuth: { enabled: true, identityFields: ["email"] },
    fields: [
      { type: "bool", name: "active", required: true },
      { type: "text", name: "purpose", required: true, max: 160 }
    ]
  });
  app.save(workers);

  const worker = "@request.auth.active = true";
  const owner = "@request.auth.id != '' && target.owner = @request.auth.id";
  const ownerOrWorker = `(${owner}) || (${worker})`;
  const targets = app.findCollectionByNameOrId("targets");
  targets.listRule = "(@request.auth.id != '' && owner = @request.auth.id) || (@request.auth.active = true)";
  targets.viewRule = targets.listRule;
  targets.updateRule = `${worker} && @request.body.owner:changed = false && @request.body.hostname:changed = false && @request.body.hostHints:changed = false && @request.body.authorizationStatus:changed = false && @request.body.authorizationReason:changed = false && @request.body.authorizedAt:changed = false && @request.body.authorizationExpiresAt:changed = false && @request.body.allowPrivateAddresses:changed = false`;
  app.save(targets);

  const targetScopes = new Collection({
    type: "base",
    name: "targetScopes",
    listRule: ownerOrWorker,
    viewRule: ownerOrWorker,
    createRule: "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id && @request.body.kind = 'exact_host'",
    updateRule: "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id && @request.body.target:changed = false && @request.body.hostname:changed = false && @request.body.kind:changed = false",
    deleteRule: "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id",
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "text", name: "hostname", required: true, max: 253, pattern: "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$" },
      { type: "select", name: "kind", required: true, maxSelect: 1, values: ["exact_host"] },
      { type: "text", name: "reason", required: true, max: 500 },
      { type: "bool", name: "enabled", required: true },
      { type: "date", name: "authorizedAt", required: true },
      { type: "autodate", name: "created", onCreate: true },
      { type: "autodate", name: "updated", onCreate: true, onUpdate: true }
    ],
    indexes: ["CREATE UNIQUE INDEX idx_target_scopes_host ON targetScopes (target, hostname)"]
  });
  app.save(targetScopes);

  const scanRequests = app.findCollectionByNameOrId("scanRequests");
  scanRequests.listRule = ownerOrWorker;
  scanRequests.viewRule = ownerOrWorker;
  scanRequests.updateRule = `((${worker}) && @request.body.target:changed = false && @request.body.mode:changed = false) || (${owner} && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled') && @request.body.target:changed = false && @request.body.mode:changed = false)`;
  app.save(scanRequests);

  for (const name of ["scans", "findings", "tlsObservations", "agentActions", "agentMessages"]) {
    const collection = app.findCollectionByNameOrId(name);
    collection.listRule = ownerOrWorker;
    collection.viewRule = ownerOrWorker;
    collection.createRule = worker;
    collection.updateRule = worker;
    collection.deleteRule = null;
    app.save(collection);
  }

  const findings = app.findCollectionByNameOrId("findings");
  findings.fields.add(new TextField({ name: "assetKey", max: 500 }));
  findings.fields.add(new JSONField({ name: "relatedAssetKeys", maxSize: 12000 }));
  findings.fields.add(new TextField({ name: "relationKey", max: 500 }));
  app.save(findings);

  const scans = app.findCollectionByNameOrId("scans");
  const assetFields = [
    { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
    { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
    { type: "text", name: "key", required: true, max: 500 },
    { type: "select", name: "kind", required: true, maxSelect: 1, values: ["domain", "hostname", "edge", "network", "server", "port", "service"] },
    { type: "text", name: "label", required: true, max: 240 },
    { type: "text", name: "subtitle", max: 500 },
    { type: "select", name: "state", required: true, maxSelect: 1, values: ["risk", "warning", "healthy", "observed", "unknown"] },
    { type: "number", name: "confidence", required: true, min: 1, max: 100 },
    { type: "select", name: "basis", required: true, maxSelect: 1, values: ["observed", "registry", "inferred", "owner_confirmed"] },
    { type: "json", name: "details", maxSize: 30000 },
    { type: "autodate", name: "created", onCreate: true }
  ];
  const assets = new Collection({
    type: "base", name: "assets", listRule: ownerOrWorker, viewRule: ownerOrWorker,
    createRule: worker, updateRule: worker, deleteRule: null, fields: assetFields,
    indexes: ["CREATE UNIQUE INDEX idx_assets_scan_key ON assets (scan, key)", "CREATE INDEX idx_assets_target_kind ON assets (target, kind)"]
  });
  app.save(assets);

  const assetRelations = new Collection({
    type: "base", name: "assetRelations", listRule: ownerOrWorker, viewRule: ownerOrWorker,
    createRule: worker, updateRule: worker, deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: "text", name: "key", required: true, max: 500 },
      { type: "text", name: "fromKey", required: true, max: 500 },
      { type: "text", name: "toKey", required: true, max: 500 },
      { type: "text", name: "type", required: true, max: 80 },
      { type: "text", name: "label", required: true, max: 160 },
      { type: "select", name: "state", required: true, maxSelect: 1, values: ["risk", "warning", "healthy", "observed", "unknown"] },
      { type: "number", name: "confidence", required: true, min: 1, max: 100 },
      { type: "select", name: "basis", required: true, maxSelect: 1, values: ["observed", "registry", "inferred", "owner_confirmed"] },
      { type: "json", name: "evidence", maxSize: 24000 },
      { type: "json", name: "findingTitles", maxSize: 12000 },
      { type: "autodate", name: "created", onCreate: true }
    ],
    indexes: ["CREATE UNIQUE INDEX idx_asset_relations_scan_key ON assetRelations (scan, key)", "CREATE INDEX idx_asset_relations_target ON assetRelations (target)"]
  });
  app.save(assetRelations);

  const publicIdentities = new Collection({
    type: "base", name: "publicIdentities", listRule: ownerOrWorker, viewRule: ownerOrWorker,
    createRule: worker,
    updateRule: "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id && @request.body.target:changed = false && @request.body.scan:changed = false && @request.body.key:changed = false && @request.body.kind:changed = false && @request.body.displayName:changed = false && @request.body.email:changed = false && @request.body.publicLinks:changed = false && @request.body.sourceUrls:changed = false && @request.body.evidence:changed = false && @request.body.sourceAssetKey:changed = false && @request.body.confidence:changed = false",
    deleteRule: "@request.auth.id != '' && @request.auth.role = 'admin' && target.owner = @request.auth.id",
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: "text", name: "key", required: true, max: 500 },
      { type: "select", name: "kind", required: true, maxSelect: 1, values: ["person", "mailbox", "organization"] },
      { type: "text", name: "displayName", max: 240 },
      { type: "email", name: "email" },
      { type: "json", name: "publicLinks", maxSize: 12000 },
      { type: "json", name: "sourceUrls", maxSize: 12000 },
      { type: "json", name: "evidence", maxSize: 24000 },
      { type: "text", name: "sourceAssetKey", required: true, max: 500 },
      { type: "number", name: "confidence", required: true, min: 1, max: 100 },
      { type: "select", name: "employmentStatus", required: true, maxSelect: 1, values: ["unknown", "current", "former", "not_applicable"] },
      { type: "text", name: "reviewNote", max: 800 },
      { type: "relation", name: "confirmedBy", maxSelect: 1, collectionId: users.id, cascadeDelete: false },
      { type: "date", name: "confirmedAt" },
      { type: "autodate", name: "created", onCreate: true },
      { type: "autodate", name: "updated", onCreate: true, onUpdate: true }
    ],
    indexes: ["CREATE UNIQUE INDEX idx_public_identities_scan_key ON publicIdentities (scan, key)", "CREATE INDEX idx_public_identities_target ON publicIdentities (target)"]
  });
  app.save(publicIdentities);
}, (app) => {
  for (const name of ["publicIdentities", "assetRelations", "assets", "targetScopes", "workers"]) {
    try { app.delete(app.findCollectionByNameOrId(name)); } catch (_) {}
  }
  const findings = app.findCollectionByNameOrId("findings");
  for (const field of ["assetKey", "relatedAssetKeys", "relationKey"]) {
    try { findings.fields.removeByName(field); } catch (_) {}
  }
  app.save(findings);
  const users = app.findCollectionByNameOrId("users");
  users.updateRule = "id = @request.auth.id";
  app.save(users);

  const owner = "@request.auth.id != '' && target.owner = @request.auth.id";
  const targets = app.findCollectionByNameOrId("targets");
  targets.listRule = "@request.auth.id != '' && owner = @request.auth.id";
  targets.viewRule = targets.listRule;
  targets.updateRule = null;
  app.save(targets);

  const scanRequests = app.findCollectionByNameOrId("scanRequests");
  scanRequests.listRule = owner;
  scanRequests.viewRule = owner;
  scanRequests.updateRule = `${owner} && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled')`;
  app.save(scanRequests);

  for (const name of ["scans", "findings", "tlsObservations", "agentActions", "agentMessages"]) {
    const collection = app.findCollectionByNameOrId(name);
    collection.listRule = owner;
    collection.viewRule = owner;
    collection.createRule = null;
    collection.updateRule = null;
    app.save(collection);
  }
});
