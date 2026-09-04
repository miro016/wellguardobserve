import PocketBase from 'pocketbase';

const baseUrl = process.env['POCKETBASE_URL'] || 'http://127.0.0.1:8090';
const superuserEmail = process.env['POCKETBASE_SUPERUSER_EMAIL'];
const superuserPassword = process.env['POCKETBASE_SUPERUSER_PASSWORD'];
const userEmail = process.env['WELLGUARD_ADMIN_EMAIL'] || 'demo@wellguard.local';
const userPassword = process.env['WELLGUARD_ADMIN_PASSWORD'];

if (!superuserEmail || !superuserPassword || !userPassword) {
  throw new Error('Set POCKETBASE_SUPERUSER_EMAIL, POCKETBASE_SUPERUSER_PASSWORD and WELLGUARD_ADMIN_PASSWORD before seeding.');
}

const pb = new PocketBase(baseUrl);
pb.autoCancellation(false);
await pb.collection('_superusers').authWithPassword(superuserEmail, superuserPassword);

let user;
try { user = await pb.collection('users').getFirstListItem(pb.filter('email = {:email}', { email: userEmail })); }
catch {
  user = await pb.collection('users').create({ email: userEmail, password: userPassword, passwordConfirm: userPassword, name: 'Miroslav Petro', role: 'admin', verified: true });
}

let target;
try { target = await pb.collection('targets').getFirstListItem('hostname = "miroslav-petro.com"'); }
catch {
  target = await pb.collection('targets').create({
    owner: user.id, name: 'Personal infrastructure', hostname: 'miroslav-petro.com',
    hostHints: ['keycloak1.miroslav-petro.com'],
    authorizationStatus: 'admin_override', authorizationReason: 'Infrastructure owner supplied this target for MVP testing.',
    authorizedAt: new Date().toISOString(), status: 'observed', posture: 100, assetCount: 1, findingCount: 0
  });
}

const relatedHostname = 'electric-keycloak.qtgksk.easypanel.host';
try {
  await pb.collection('targetScopes').getFirstListItem(pb.filter('target = {:target} && hostname = {:hostname}', { target: target.id, hostname: relatedHostname }));
} catch {
  await pb.collection('targetScopes').create({
    target: target.id, hostname: relatedHostname, kind: 'exact_host', enabled: true,
    reason: 'Infrastructure owner explicitly supplied this Keycloak service hostname for authorized reconnaissance.',
    authorizedAt: new Date().toISOString()
  });
}

console.log(JSON.stringify({ user: user.email, target: target.hostname, targetId: target.id }, null, 2));
