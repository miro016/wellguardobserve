migrate((app) => {
  const findings = app.findCollectionByNameOrId("findings");
  findings.fields.add(new JSONField({ name: "cveIds", maxSize: 12000 }));
  findings.fields.add(new JSONField({ name: "weaknessIds", maxSize: 12000 }));
  app.save(findings);
}, (app) => {
  const findings = app.findCollectionByNameOrId("findings");
  findings.fields.removeByName("cveIds");
  findings.fields.removeByName("weaknessIds");
  app.save(findings);
});
