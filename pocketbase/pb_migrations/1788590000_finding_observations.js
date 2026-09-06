/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const findings = app.findCollectionByNameOrId('findings');
  findings.fields.add(new JSONField({ name: 'observations', maxSize: 6000 }));
  findings.fields.add(new NumberField({ name: 'runCount', min: 0 }));
  app.save(findings);
}, (app) => {
  const findings = app.findCollectionByNameOrId('findings');
  for (const field of ['observations', 'runCount']) { try { findings.fields.removeByName(field); } catch (_) {} }
  app.save(findings);
});
