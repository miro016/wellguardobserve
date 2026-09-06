/// <reference path="../pb_data/types.d.ts" />
migrate((app) => {
  const proposals = app.findCollectionByNameOrId('improvementProposals');
  const globalAdmin = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @request.auth.role = 'admin'`;
  const member = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @collection.workspaceMembers:membership.workspace ?= workspace && @collection.workspaceMembers:membership.user ?= @request.auth.id && @collection.workspaceMembers:membership.enabled ?= true`;
  const manager = `${member} && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin')`;
  const worker = `@request.auth.collectionName = 'workers' && @request.auth.active = true`;
  const immutable = [
    'workspace', 'proposalKey', 'kind', 'scopeKey', 'title', 'rationale',
    'evidence', 'recommendedAction', 'parameter', 'confidence', 'occurrences',
    'applicationCount', 'lastAppliedAt'
  ].map((field) => `@request.body.${field}:changed = false`).join(' && ');

  proposals.updateRule = `((${worker})) || (((${globalAdmin}) || (${manager})) && (@request.body.status = 'approved' || @request.body.status = 'rejected') && ${immutable} && @request.body.reviewedBy = @request.auth.id)`;
  app.save(proposals);
}, (app) => {
  const proposals = app.findCollectionByNameOrId('improvementProposals');
  const globalAdmin = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @request.auth.role = 'admin'`;
  const member = `@request.auth.collectionName = 'users' && @request.auth.id != '' && @collection.workspaceMembers:membership.workspace ?= workspace && @collection.workspaceMembers:membership.user ?= @request.auth.id && @collection.workspaceMembers:membership.enabled ?= true`;
  const manager = `${member} && (@collection.workspaceMembers:membership.role ?= 'owner' || @collection.workspaceMembers:membership.role ?= 'admin')`;
  const worker = `@request.auth.collectionName = 'workers' && @request.auth.active = true`;
  const immutable = [
    'workspace', 'proposalKey', 'kind', 'scopeKey', 'title', 'rationale',
    'evidence', 'recommendedAction', 'parameter', 'confidence', 'occurrences',
    'applicationCount', 'lastAppliedAt'
  ].map((field) => `@request.body.${field}:changed = false`).join(' && ');

  proposals.updateRule = `((${worker})) || (((${globalAdmin}) || (${manager})) && ${immutable} && @request.body.reviewedBy = @request.auth.id)`;
  app.save(proposals);
});
