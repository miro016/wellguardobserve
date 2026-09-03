import PocketBase from 'pocketbase';

const [email, password, name = email] = Bun.argv.slice(2);
if (!email || !password) {
  console.error('Usage: bun run scripts/create-user.ts <email> <password> [name]');
  process.exit(2);
}

const superuserEmail = process.env['POCKETBASE_SUPERUSER_EMAIL'];
const superuserPassword = process.env['POCKETBASE_SUPERUSER_PASSWORD'];
if (!superuserEmail || !superuserPassword) throw new Error('PocketBase superuser credentials are required in the environment.');

const pb = new PocketBase(process.env['POCKETBASE_URL'] || 'http://127.0.0.1:8090');
await pb.collection('_superusers').authWithPassword(superuserEmail, superuserPassword);
const user = await pb.collection('users').create({ email, password, passwordConfirm: password, name, role: 'member', verified: true });
console.log(`Created invited user ${user['email']} (${user.id}).`);
