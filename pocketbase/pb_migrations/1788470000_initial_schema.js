migrate((app) => {
  const timestamps = () => [
    { type: "autodate", name: "created", onCreate: true },
    { type: "autodate", name: "updated", onCreate: true, onUpdate: true }
  ];
  const users = app.findCollectionByNameOrId("users");
  users.listRule = "id = @request.auth.id";
  users.viewRule = "id = @request.auth.id";
  users.createRule = null;
  users.updateRule = "id = @request.auth.id";
  users.deleteRule = null;
  users.fields.add(new SelectField({ name: "role", required: true, maxSelect: 1, values: ["member", "admin"] }));
  users.indexes = [...users.indexes, "CREATE INDEX idx_users_role ON users (role)"];
  app.save(users);

  const targets = new Collection({
    type: "base",
    name: "targets",
    listRule: "@request.auth.id != '' && owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && owner = @request.auth.id",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "owner", required: true, maxSelect: 1, collectionId: users.id, cascadeDelete: true },
      { type: "text", name: "name", required: true, max: 160 },
      { type: "text", name: "hostname", required: true, max: 253, pattern: "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}$" },
      { type: "select", name: "authorizationStatus", required: true, maxSelect: 1, values: ["pending", "verified", "admin_override"] },
      { type: "text", name: "authorizationReason", max: 500 },
      { type: "date", name: "authorizedAt" },
      { type: "date", name: "authorizationExpiresAt" },
      { type: "bool", name: "allowPrivateAddresses" },
      { type: "select", name: "status", required: true, maxSelect: 1, values: ["observed", "scanning", "paused"] },
      { type: "date", name: "lastScanAt" },
      { type: "number", name: "assetCount", min: 0 },
      { type: "number", name: "findingCount", min: 0 },
      { type: "number", name: "posture", min: 0, max: 100 },
      ...timestamps()
    ],
    indexes: [
      "CREATE UNIQUE INDEX idx_targets_hostname_owner ON targets (hostname, owner)",
      "CREATE INDEX idx_targets_owner ON targets (owner)"
    ]
  });
  app.save(targets);

  const scanRequests = new Collection({
    type: "base",
    name: "scanRequests",
    listRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    createRule: "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued'",
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "select", name: "mode", required: true, maxSelect: 1, values: ["light", "standard"] },
      { type: "select", name: "status", required: true, maxSelect: 1, values: ["queued", "processing", "completed", "failed"] },
      { type: "date", name: "startedAt" },
      { type: "date", name: "completedAt" },
      { type: "text", name: "error", max: 500 },
      ...timestamps()
    ],
    indexes: ["CREATE INDEX idx_scan_requests_queue ON scanRequests (status, created)"]
  });
  app.save(scanRequests);

  const scans = new Collection({
    type: "base",
    name: "scans",
    listRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "request", maxSelect: 1, collectionId: scanRequests.id, cascadeDelete: false },
      { type: "select", name: "status", required: true, maxSelect: 1, values: ["running", "completed", "failed"] },
      { type: "date", name: "startedAt" },
      { type: "date", name: "completedAt" },
      { type: "text", name: "summary", max: 4000 },
      { type: "text", name: "error", max: 500 },
      ...timestamps()
    ],
    indexes: ["CREATE INDEX idx_scans_target_created ON scans (target, created)"]
  });
  app.save(scans);

  const findings = new Collection({
    type: "base",
    name: "findings",
    listRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: "text", name: "title", required: true, max: 160 },
      { type: "text", name: "summary", required: true, max: 1200 },
      { type: "select", name: "severity", required: true, maxSelect: 1, values: ["critical", "high", "medium", "low", "info"] },
      { type: "number", name: "confidence", required: true, min: 1, max: 100 },
      { type: "text", name: "asset", required: true, max: 255 },
      { type: "json", name: "evidence", maxSize: 24000 },
      { type: "text", name: "remediation", max: 1200 },
      { type: "json", name: "sourceUrls", maxSize: 12000 },
      { type: "select", name: "status", required: true, maxSelect: 1, values: ["open", "accepted", "resolved"] },
      ...timestamps()
    ],
    indexes: ["CREATE INDEX idx_findings_target_status ON findings (target, status)"]
  });
  app.save(findings);

  const tlsObservations = new Collection({
    type: "base",
    name: "tlsObservations",
    listRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: "text", name: "hostname", required: true, max: 253 },
      { type: "bool", name: "valid" },
      { type: "date", name: "expiresAt" },
      { type: "json", name: "details", required: true, maxSize: 24000 },
      ...timestamps()
    ],
    indexes: ["CREATE INDEX idx_tls_target_created ON tlsObservations (target, created)"]
  });
  app.save(tlsObservations);

  const agentActions = new Collection({
    type: "base",
    name: "agentActions",
    listRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: "text", name: "tool", required: true, max: 120 },
      { type: "json", name: "input", maxSize: 12000 },
      { type: "text", name: "summary", max: 5000 },
      { type: "date", name: "occurredAt", required: true },
      ...timestamps()
    ],
    indexes: ["CREATE INDEX idx_agent_actions_scan_created ON agentActions (scan, created)"]
  });
  app.save(agentActions);

  const settings = app.settings();
  settings.meta.appName = "Wellguard Observe";
  settings.logs.maxDays = 30;
  settings.logs.logIP = false;
  app.save(settings);
}, (app) => {
  for (const name of ["agentActions", "tlsObservations", "findings", "scans", "scanRequests", "targets"]) {
    try { app.delete(app.findCollectionByNameOrId(name)); } catch (_) {}
  }
  try {
    const users = app.findCollectionByNameOrId("users");
    users.fields.removeByName("role");
    users.indexes = users.indexes.filter((index) => !index.includes("idx_users_role"));
    app.save(users);
  } catch (_) {}
});
