migrate((app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.fields.add(new DateField({ name: 'heartbeatAt' }));
  requests.fields.add(new TextField({ name: 'phase', max: 200 }));
  requests.fields.add(new NumberField({ name: 'actionCount', min: 0 }));
  requests.fields.add(new NumberField({ name: 'messageCount', min: 0 }));
  app.save(requests);
}, (app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  for (const field of ['heartbeatAt', 'phase', 'actionCount', 'messageCount']) {
    try { requests.fields.removeByName(field); } catch (_) {}
  }
  app.save(requests);
});
