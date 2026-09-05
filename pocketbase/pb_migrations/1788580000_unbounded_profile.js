/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.fields.getByName('mode').values = ['light', 'standard', 'extended', 'advanced', 'unbounded'];
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced' && @request.body.mode != 'unbounded') || @request.body.extendedConsent = true)";
  app.save(requests);
}, (app) => {
  const requests = app.findCollectionByNameOrId('scanRequests');
  requests.fields.getByName('mode').values = ['light', 'standard', 'extended', 'advanced'];
  requests.createRule = "@request.auth.id != '' && target.owner = @request.auth.id && @request.body.status = 'queued' && ((@request.body.mode != 'extended' && @request.body.mode != 'advanced') || @request.body.extendedConsent = true)";
  app.save(requests);
});
