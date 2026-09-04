migrate((app) => {
  const targets = app.findCollectionByNameOrId("targets");
  const scans = app.findCollectionByNameOrId("scans");
  const agentMessages = new Collection({
    type: "base",
    name: "agentMessages",
    listRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    viewRule: "@request.auth.id != '' && target.owner = @request.auth.id",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [
      { type: "relation", name: "target", required: true, maxSelect: 1, collectionId: targets.id, cascadeDelete: true },
      { type: "relation", name: "scan", required: true, maxSelect: 1, collectionId: scans.id, cascadeDelete: true },
      { type: "select", name: "role", required: true, maxSelect: 1, values: ["system", "user", "assistant", "tool"] },
      { type: "text", name: "content", max: 12000 },
      { type: "text", name: "toolName", max: 120 },
      { type: "number", name: "sequence", min: 0 },
      { type: "date", name: "occurredAt", required: true },
      { type: "autodate", name: "created", onCreate: true },
      { type: "autodate", name: "updated", onCreate: true, onUpdate: true }
    ],
    indexes: ["CREATE INDEX idx_agent_messages_scan_sequence ON agentMessages (scan, sequence)"]
  });
  app.save(agentMessages);
}, (app) => {
  try { app.delete(app.findCollectionByNameOrId("agentMessages")); } catch (_) {}
});
