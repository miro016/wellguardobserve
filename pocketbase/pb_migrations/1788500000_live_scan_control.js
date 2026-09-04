migrate((app) => {
  const scanRequests = app.findCollectionByNameOrId("scanRequests");
  const requestStatus = scanRequests.fields.getByName("status");
  requestStatus.values = ["queued", "processing", "cancelling", "cancelled", "completed", "failed"];
  scanRequests.updateRule = "@request.auth.id != '' && target.owner = @request.auth.id && (@request.body.status = 'cancelling' || @request.body.status = 'cancelled')";
  app.save(scanRequests);

  const scans = app.findCollectionByNameOrId("scans");
  const scanStatus = scans.fields.getByName("status");
  scanStatus.values = ["running", "cancelled", "completed", "failed"];
  app.save(scans);

  const actions = app.findCollectionByNameOrId("agentActions");
  actions.fields.getByName("summary").max = 30000;
  app.save(actions);
}, (app) => {
  const scanRequests = app.findCollectionByNameOrId("scanRequests");
  scanRequests.fields.getByName("status").values = ["queued", "processing", "completed", "failed"];
  scanRequests.updateRule = null;
  app.save(scanRequests);

  const scans = app.findCollectionByNameOrId("scans");
  scans.fields.getByName("status").values = ["running", "completed", "failed"];
  app.save(scans);

  const actions = app.findCollectionByNameOrId("agentActions");
  actions.fields.getByName("summary").max = 5000;
  app.save(actions);
});
