migrate((app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.fields.getByName('mode').values = ['light', 'standard', 'extended'];
  requests.fields.add(new BoolField({ name: 'extendedConsent' }));
  requests.fields.add(new JSONField({ name: 'profileSnapshot', maxSize: 12000 }));
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued' && (@request.body.mode != 'extended' || @request.body.extendedConsent = true)";
  const worker = "@request.auth.collectionName = 'workers' && @request.auth.active = true";
  const owner = "@request.auth.collectionName = 'users' && @request.auth.id != '' && target.owner = @request.auth.id";
  requests.updateRule = `((${worker}) && @request.body.target:changed = false && @request.body.mode:changed = false && @request.body.extendedConsent:changed = false) || (${owner} && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled') && @request.body.target:changed = false && @request.body.mode:changed = false && @request.body.extendedConsent:changed = false)`;
  app.save(requests);
}, (app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  for (const field of ['extendedConsent', 'profileSnapshot']) { try { requests.fields.removeByName(field); } catch (_) {} }
  requests.fields.getByName('mode').values = ['light', 'standard'];
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued'";
  const worker = "@request.auth.collectionName = 'workers' && @request.auth.active = true";
  const owner = "@request.auth.collectionName = 'users' && @request.auth.id != '' && target.owner = @request.auth.id";
  requests.updateRule = `((${worker}) && @request.body.target:changed = false && @request.body.mode:changed = false) || (${owner} && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled') && @request.body.target:changed = false && @request.body.mode:changed = false)`;
  app.save(requests);
});
