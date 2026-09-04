migrate((app) => {
  const targets = app.findCollectionByNameOrId("targets");
  targets.fields.add(new JSONField({ name: "hostHints", maxSize: 12000 }));
  targets.createRule = "@request.auth.id != '' && @request.auth.role = 'admin' && @request.body.owner = @request.auth.id && @request.body.authorizationStatus = 'admin_override' && @request.body.allowPrivateAddresses = false";
  app.save(targets);
}, (app) => {
  const targets = app.findCollectionByNameOrId("targets");
  targets.createRule = null;
  targets.fields.removeByName("hostHints");
  app.save(targets);
});
