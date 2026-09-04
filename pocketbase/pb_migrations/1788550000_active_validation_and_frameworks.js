migrate((app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued'";
  app.save(requests);

  const findings = app.findCollectionByNameOrId('findings');
  findings.fields.add(new JSONField({ name: 'frameworkRefs', maxSize: 30000 }));
  app.save(findings);
}, (app) => {
  const findings = app.findCollectionByNameOrId('findings');
  try { findings.fields.removeByName('frameworkRefs'); } catch (_) {}
  app.save(findings);

  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued' && (@request.body.mode != 'extended' || @request.body.extendedConsent = true)";
  app.save(requests);
});
