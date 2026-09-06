/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const messages = app.findCollectionByNameOrId('agentMessages');
  messages.fields.add(new TextField({ name: 'reasoning', max: 20000 }));
  app.save(messages);
}, (app) => {
  const messages = app.findCollectionByNameOrId('agentMessages');
  try { messages.fields.removeByName('reasoning'); } catch (_) {}
  app.save(messages);
});
