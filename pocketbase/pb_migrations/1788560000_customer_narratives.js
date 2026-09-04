migrate((app) => {
  const findings = app.findCollectionByNameOrId('findings');
  findings.fields.add(new JSONField({ name: 'customerNarrative', maxSize: 12000 }));
  app.save(findings);
}, (app) => {
  const findings = app.findCollectionByNameOrId('findings');
  try { findings.fields.removeByName('customerNarrative'); } catch (_) {}
  app.save(findings);
});
